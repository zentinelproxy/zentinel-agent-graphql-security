//! Persisted query analyzer.
//!
//! Enforces query allowlists and resolves hash-only (APQ) requests.
//!
//! The hash a client sends in `extensions.persistedQuery.sha256Hash` is never
//! trusted on its own: whenever query text is present, the agent hashes that
//! text itself, and a client-supplied hash that disagrees is rejected. A
//! hash-only request is resolved to query text from a server-side store (the
//! allowlist file in `allowlist` mode, queries seen earlier in `cache` mode),
//! and the resolved text is what every analyzer then checks.

use super::{AnalysisContext, AnalysisResult, Analyzer};
use crate::config::{PersistedQueriesConfig, PersistedQueryMode};
use crate::error::{GraphQLError, Violation};
use crate::parser::{calculate_query_hash, get_apq_hash, ParsedDocument};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;
use tracing::{debug, warn};

/// Upper bound on queries remembered in `cache` mode.
const MAX_CACHED_QUERIES: usize = 10_000;

/// Analyzer that enforces persisted queries / allowlists.
pub struct PersistedQueryAnalyzer {
    config: PersistedQueriesConfig,
    /// Allowed query hashes (lowercase hex), with the query text when the
    /// allowlist file provides it.
    allowlist: RwLock<HashMap<String, Option<String>>>,
    /// `cache` mode: hash -> query text for queries whose hash was verified.
    cache: RwLock<HashMap<String, String>>,
}

/// Format for allowlist JSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AllowlistFile {
    /// Version for future compatibility
    #[serde(default)]
    version: u32,
    /// List of allowed queries
    queries: Vec<AllowlistEntry>,
}

/// Entry in the allowlist. At least one of `hash` and `query` is required.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AllowlistEntry {
    /// SHA-256 hash of the query text (hex)
    #[serde(default)]
    hash: Option<String>,
    /// The query text. Needed to serve hash-only requests for this entry.
    #[serde(default)]
    query: Option<String>,
    /// Optional name/description for the query
    #[serde(default)]
    name: Option<String>,
}

impl PersistedQueryAnalyzer {
    /// Create a new persisted query analyzer with an empty allowlist.
    pub fn new(config: PersistedQueriesConfig) -> Self {
        Self {
            config,
            allowlist: RwLock::new(HashMap::new()),
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Create analyzer and load allowlist from file.
    pub async fn with_allowlist(config: PersistedQueriesConfig) -> Result<Self, GraphQLError> {
        let analyzer = Self::new(config);
        analyzer.load_allowlist().await?;
        Ok(analyzer)
    }

    /// Load allowlist from configured file.
    pub async fn load_allowlist(&self) -> Result<(), GraphQLError> {
        let file_path = match &self.config.allowlist_file {
            Some(path) => path,
            None => return Ok(()), // No file configured
        };

        if !Path::new(file_path).exists() {
            warn!(path = %file_path, "Allowlist file not found, using empty allowlist");
            return Ok(());
        }

        let content = tokio::fs::read_to_string(file_path).await?;
        let entries = parse_allowlist(&content)?;
        let count = entries.len();
        *self.allowlist.write().unwrap_or_else(|e| e.into_inner()) = entries;

        debug!(path = %file_path, count, "Loaded query allowlist");

        Ok(())
    }

    /// Allow a query hash without query text (hash-only requests for it
    /// cannot be resolved and are rejected).
    pub fn allow_hash(&self, hash: &str) {
        self.allowlist
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .entry(hash.to_lowercase())
            .or_insert(None);
    }

    /// Allow a query by its text; its hash is computed here.
    pub fn allow_query(&self, query: &str) {
        self.allowlist
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(calculate_query_hash(query), Some(query.to_string()));
    }

    /// Check if a (computed) query hash is in the allowlist.
    fn is_allowed(&self, hash: &str) -> bool {
        self.allowlist
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&hash.to_lowercase())
    }

    /// Remember a verified hash -> query pair (cache mode).
    fn remember(&self, hash: String, query: &str) {
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        if cache.contains_key(&hash) {
            return;
        }
        if cache.len() >= MAX_CACHED_QUERIES {
            // Evict an arbitrary entry; an evicted query just costs the client
            // one PersistedQueryNotFound round trip.
            if let Some(evict) = cache.keys().next().cloned() {
                cache.remove(&evict);
            }
        }
        cache.insert(hash, query.to_string());
    }

    /// Look up the query text for a hash-only request.
    fn lookup(&self, hash: &str) -> Result<String, Violation> {
        match self.config.mode {
            PersistedQueryMode::Allowlist => {
                let allowlist = self.allowlist.read().unwrap_or_else(|e| e.into_inner());
                match allowlist.get(hash) {
                    Some(Some(query)) => Ok(query.clone()),
                    // Allowed, but the file has no text to analyze it with.
                    Some(None) => Err(Violation::persisted_query_not_found()),
                    None => Err(Violation::query_not_allowed()),
                }
            }
            PersistedQueryMode::Cache => self
                .cache
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(hash)
                .cloned()
                .ok_or_else(Violation::persisted_query_not_found),
        }
    }
}

/// Parse the allowlist file into hash -> optional query text.
///
/// An entry with query text is keyed by the hash of that text; a `hash` given
/// alongside it must agree, so the file cannot map a hash to other text.
fn parse_allowlist(content: &str) -> Result<HashMap<String, Option<String>>, GraphQLError> {
    let file: AllowlistFile = serde_json::from_str(content)?;
    let mut entries = HashMap::new();
    for (i, entry) in file.queries.into_iter().enumerate() {
        let label = entry.name.clone().unwrap_or_else(|| format!("#{}", i));
        match (entry.hash, entry.query) {
            (hash, Some(query)) => {
                let computed = calculate_query_hash(&query);
                if let Some(hash) = hash {
                    if hash.to_lowercase() != computed {
                        return Err(GraphQLError::Config(format!(
                            "allowlist entry {}: hash {} does not match its query (sha256 {})",
                            label, hash, computed
                        )));
                    }
                }
                entries.insert(computed, Some(query));
            }
            (Some(hash), None) => {
                entries.entry(hash.to_lowercase()).or_insert(None);
            }
            (None, None) => {
                return Err(GraphQLError::Config(format!(
                    "allowlist entry {}: needs a hash or a query",
                    label
                )));
            }
        }
    }
    Ok(entries)
}

#[async_trait(?Send)]
impl Analyzer for PersistedQueryAnalyzer {
    fn name(&self) -> &'static str {
        "persisted_queries"
    }

    fn resolve_query(
        &self,
        query: Option<&str>,
        extensions: &Option<serde_json::Value>,
    ) -> Option<Result<String, Violation>> {
        let client_hash = get_apq_hash(extensions).map(|h| h.to_lowercase());

        let resolved = match (query, client_hash) {
            // Query text present: the hash is ours to compute. A client hash
            // that disagrees is an attempt to pass one query off as another.
            (Some(query), Some(client_hash)) => {
                let computed = calculate_query_hash(query);
                if computed != client_hash {
                    debug!(
                        client_hash = %client_hash,
                        computed_hash = %computed,
                        "Persisted query hash does not match query text"
                    );
                    Err(Violation::persisted_query_hash_mismatch())
                } else {
                    if self.config.mode == PersistedQueryMode::Cache {
                        self.remember(computed, query);
                    }
                    Ok(query.to_string())
                }
            }
            (Some(query), None) => Ok(query.to_string()),
            // Hash only: resolve the text from the server-side store.
            (None, Some(client_hash)) => self.lookup(&client_hash),
            (None, None) => Err(Violation::invalid_request(
                "Missing 'query' field in GraphQL request",
            )),
        };
        Some(resolved)
    }

    async fn analyze(&self, document: &ParsedDocument, ctx: &AnalysisContext) -> AnalysisResult {
        // Check if hash is required
        if self.config.require_hash && get_apq_hash(&ctx.extensions).is_none() {
            debug!(
                correlation_id = %ctx.correlation_id,
                "Query rejected: APQ hash required but not provided"
            );
            return AnalysisResult::violation(Violation::new(
                crate::error::ViolationCode::QueryNotAllowed,
                "Persisted query hash is required",
            ));
        }

        // `document.query_hash` is computed from the text being analyzed,
        // never taken from the client.
        let query_hash = &document.query_hash;

        match self.config.mode {
            PersistedQueryMode::Allowlist => {
                if !self.is_allowed(query_hash) {
                    debug!(
                        correlation_id = %ctx.correlation_id,
                        hash = %query_hash,
                        "Query not in allowlist"
                    );
                    return AnalysisResult::violation(Violation::query_not_allowed());
                }

                debug!(
                    correlation_id = %ctx.correlation_id,
                    hash = %query_hash,
                    "Query found in allowlist"
                );
            }
            PersistedQueryMode::Cache => {
                // Any query is allowed; resolve_query remembered it so that
                // later hash-only requests are analyzed with its text.
                debug!(
                    correlation_id = %ctx.correlation_id,
                    hash = %query_hash,
                    "Query processed in cache mode"
                );
            }
        }

        AnalysisResult::ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ViolationCode;
    use crate::parser::parse_query;
    use serde_json::json;
    use std::collections::HashMap;

    fn test_config(mode: PersistedQueryMode) -> PersistedQueriesConfig {
        PersistedQueriesConfig {
            enabled: true,
            mode,
            allowlist_file: None,
            require_hash: false,
        }
    }

    fn test_context(extensions: Option<serde_json::Value>) -> AnalysisContext {
        AnalysisContext {
            correlation_id: "test".to_string(),
            client_ip: "127.0.0.1".to_string(),
            headers: HashMap::new(),
            operation_name: None,
            variables: None,
            extensions,
            is_batch: false,
            batch_count: 1,
            query: String::new(),
        }
    }

    fn apq(hash: &str) -> Option<serde_json::Value> {
        Some(json!({"persistedQuery": {"version": 1, "sha256Hash": hash}}))
    }

    /// Resolve then analyze, the way the agent does.
    async fn check(
        analyzer: &PersistedQueryAnalyzer,
        query: Option<&str>,
        extensions: Option<serde_json::Value>,
    ) -> Result<AnalysisResult, Violation> {
        let text = analyzer.resolve_query(query, &extensions).unwrap()?;
        let doc = parse_query(&text).unwrap();
        Ok(analyzer.analyze(&doc, &test_context(extensions)).await)
    }

    #[tokio::test]
    async fn test_allowlist_query_not_found() {
        let analyzer = PersistedQueryAnalyzer::new(test_config(PersistedQueryMode::Allowlist));
        let result = check(&analyzer, Some("{ users { id } }"), None)
            .await
            .unwrap();
        assert!(result.has_violations());
        assert_eq!(result.violations[0].code, ViolationCode::QueryNotAllowed);
    }

    #[tokio::test]
    async fn test_allowlist_query_found() {
        let analyzer = PersistedQueryAnalyzer::new(test_config(PersistedQueryMode::Allowlist));
        let query = "{ users { id } }";
        analyzer.allow_hash(&calculate_query_hash(query));

        let result = check(&analyzer, Some(query), None).await.unwrap();
        assert!(!result.has_violations());
    }

    /// The bypass from #5: a query that is not allowed, sent under the hash of
    /// one that is, must be blocked.
    #[tokio::test]
    async fn test_malicious_query_under_allowed_hash_is_blocked() {
        let analyzer = PersistedQueryAnalyzer::new(test_config(PersistedQueryMode::Allowlist));
        let allowed = "{ users { id } }";
        let allowed_hash = calculate_query_hash(allowed);
        analyzer.allow_query(allowed);

        let malicious = "{ users { id password ssn } }";
        let result = check(&analyzer, Some(malicious), apq(&allowed_hash)).await;
        let violation = result.expect_err("hash mismatch must be rejected");
        assert_eq!(violation.code, ViolationCode::QueryNotAllowed);
    }

    /// Even an arbitrary allowlisted hash (no text known) does not let other
    /// text through.
    #[tokio::test]
    async fn test_allowed_bare_hash_does_not_admit_other_text() {
        let analyzer = PersistedQueryAnalyzer::new(test_config(PersistedQueryMode::Allowlist));
        analyzer.allow_hash("abc123def456");

        let result = check(&analyzer, Some("{ users { id } }"), apq("abc123def456")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_matching_hash_and_query_allowed() {
        let analyzer = PersistedQueryAnalyzer::new(test_config(PersistedQueryMode::Allowlist));
        let query = "{ users { id } }";
        let hash = calculate_query_hash(query);
        analyzer.allow_query(query);

        // Client hashes are compared case-insensitively.
        let result = check(&analyzer, Some(query), apq(&hash.to_uppercase()))
            .await
            .unwrap();
        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_hash_only_resolved_from_allowlist() {
        let analyzer = PersistedQueryAnalyzer::new(test_config(PersistedQueryMode::Allowlist));
        let query = "{ users { id } }";
        let hash = calculate_query_hash(query);
        analyzer.allow_query(query);

        let resolved = analyzer.resolve_query(None, &apq(&hash)).unwrap().unwrap();
        assert_eq!(resolved, query);
        let result = check(&analyzer, None, apq(&hash)).await.unwrap();
        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_hash_only_unknown_hash_rejected() {
        let analyzer = PersistedQueryAnalyzer::new(test_config(PersistedQueryMode::Allowlist));
        analyzer.allow_query("{ users { id } }");

        let err = check(&analyzer, None, apq("deadbeef")).await.unwrap_err();
        assert_eq!(err.code, ViolationCode::QueryNotAllowed);
    }

    #[tokio::test]
    async fn test_hash_only_without_stored_text_rejected() {
        let analyzer = PersistedQueryAnalyzer::new(test_config(PersistedQueryMode::Allowlist));
        let hash = calculate_query_hash("{ users { id } }");
        analyzer.allow_hash(&hash);

        let err = check(&analyzer, None, apq(&hash)).await.unwrap_err();
        assert_eq!(err.code, ViolationCode::PersistedQueryNotFound);
    }

    #[tokio::test]
    async fn test_cache_mode_allows_all() {
        let analyzer = PersistedQueryAnalyzer::new(test_config(PersistedQueryMode::Cache));
        let result = check(&analyzer, Some("{ users { id } }"), None)
            .await
            .unwrap();
        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_cache_mode_apq_round_trip() {
        let analyzer = PersistedQueryAnalyzer::new(test_config(PersistedQueryMode::Cache));
        let query = "{ users { id } }";
        let hash = calculate_query_hash(query);

        // Unknown hash: the client is told to send the full query.
        let err = check(&analyzer, None, apq(&hash)).await.unwrap_err();
        assert_eq!(err.code, ViolationCode::PersistedQueryNotFound);
        assert_eq!(err.message, "PersistedQueryNotFound");

        // Full query + hash registers it ...
        assert!(check(&analyzer, Some(query), apq(&hash)).await.is_ok());

        // ... and the hash-only request now resolves to that text.
        let resolved = analyzer.resolve_query(None, &apq(&hash)).unwrap().unwrap();
        assert_eq!(resolved, query);
    }

    #[tokio::test]
    async fn test_cache_mode_does_not_register_mismatched_hash() {
        let analyzer = PersistedQueryAnalyzer::new(test_config(PersistedQueryMode::Cache));
        let innocent_hash = calculate_query_hash("{ users { id } }");

        // Poisoning attempt: register other text under someone else's hash.
        let err = check(
            &analyzer,
            Some("{ admin { secrets } }"),
            apq(&innocent_hash),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ViolationCode::QueryNotAllowed);

        let err = check(&analyzer, None, apq(&innocent_hash))
            .await
            .unwrap_err();
        assert_eq!(err.code, ViolationCode::PersistedQueryNotFound);
    }

    #[tokio::test]
    async fn test_require_hash() {
        let mut config = test_config(PersistedQueryMode::Allowlist);
        config.require_hash = true;
        let analyzer = PersistedQueryAnalyzer::new(config);
        let query = "{ users { id } }";
        analyzer.allow_query(query);

        // No APQ extension
        let result = check(&analyzer, Some(query), None).await.unwrap();
        assert!(result.has_violations());

        let hash = calculate_query_hash(query);
        let result = check(&analyzer, Some(query), apq(&hash)).await.unwrap();
        assert!(!result.has_violations());
    }

    #[test]
    fn test_parse_allowlist_file() {
        let query = "{ users { id } }";
        let hash = calculate_query_hash(query);
        let content = json!({
            "version": 1,
            "queries": [
                {"query": query, "name": "users"},
                {"hash": "ABCDEF"},
            ]
        })
        .to_string();
        let entries = parse_allowlist(&content).unwrap();
        assert_eq!(entries.get(&hash), Some(&Some(query.to_string())));
        assert_eq!(entries.get("abcdef"), Some(&None));
    }

    #[test]
    fn test_parse_allowlist_rejects_mismatched_entry() {
        let content = json!({
            "queries": [{"hash": "abcdef", "query": "{ users { id } }"}]
        })
        .to_string();
        assert!(parse_allowlist(&content).is_err());
    }

    #[tokio::test]
    async fn test_load_allowlist_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        let query = "{ users { id } }";
        std::fs::write(&path, json!({"queries": [{"query": query}]}).to_string()).unwrap();

        let mut config = test_config(PersistedQueryMode::Allowlist);
        config.allowlist_file = Some(path.to_string_lossy().into_owned());
        let analyzer = PersistedQueryAnalyzer::with_allowlist(config)
            .await
            .unwrap();

        let hash = calculate_query_hash(query);
        assert!(check(&analyzer, None, apq(&hash)).await.is_ok());
        assert!(check(&analyzer, Some("{ other }"), apq(&hash))
            .await
            .is_err());
    }
}
