//! Introspection analyzer.
//!
//! Detects and controls GraphQL introspection queries.

use super::{AnalysisContext, AnalysisResult, Analyzer};
use crate::config::IntrospectionConfig;
use crate::error::Violation;
use crate::parser::{FragmentInfo, ParsedDocument};
use apollo_parser::cst;
use async_trait::async_trait;
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use tracing::{debug, warn};

/// Analyzer that controls introspection queries.
pub struct IntrospectionAnalyzer {
    config: IntrospectionConfig,
    /// `allowed_clients` entries that are IP addresses or CIDR ranges
    allowed_networks: Vec<IpNet>,
    /// The other `allowed_clients` entries: values for `allowed_clients_header`
    allowed_header_values: HashSet<String>,
}

impl IntrospectionAnalyzer {
    /// Create a new introspection analyzer.
    pub fn new(config: IntrospectionConfig) -> Self {
        let mut allowed_networks = Vec::new();
        let mut allowed_header_values = HashSet::new();
        for entry in &config.allowed_clients {
            let entry = entry.trim();
            if let Ok(net) = entry.parse::<IpNet>() {
                allowed_networks.push(net.trunc());
            } else if let Ok(ip) = entry.parse::<IpAddr>() {
                allowed_networks.push(IpNet::from(ip.to_canonical()));
            } else if entry.contains('/')
                && entry
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || ".:/".contains(c))
            {
                // Looks like a mistyped range; never let it become a header secret.
                warn!(entry = %entry, "Ignoring invalid CIDR in introspection.allowed_clients");
            } else {
                allowed_header_values.insert(entry.to_string());
            }
        }
        if !allowed_header_values.is_empty() && config.allowed_clients_header.is_none() {
            warn!(
                "introspection.allowed_clients has non-IP entries but no allowed_clients_header; they never match"
            );
        }
        Self {
            config,
            allowed_networks,
            allowed_header_values,
        }
    }

    /// Check if a selection set contains introspection fields.
    fn contains_introspection(
        &self,
        selection_set: &cst::SelectionSet,
        fragments: &HashMap<String, FragmentInfo>,
        visited_fragments: &mut HashSet<String>,
    ) -> bool {
        for selection in selection_set.selections() {
            match selection {
                cst::Selection::Field(field) => {
                    let field_name = field
                        .name()
                        .map(|n| n.text().to_string())
                        .unwrap_or_default();

                    // Check for introspection fields
                    if self.is_blocked_introspection_field(&field_name) {
                        return true;
                    }

                    // Recurse into nested selection set
                    if let Some(ss) = field.selection_set() {
                        if self.contains_introspection(&ss, fragments, visited_fragments) {
                            return true;
                        }
                    }
                }
                cst::Selection::FragmentSpread(spread) => {
                    if let Some(name) = spread.fragment_name() {
                        if let Some(name_token) = name.name() {
                            let frag_name = name_token.text().to_string();

                            // Prevent infinite recursion
                            if visited_fragments.contains(&frag_name) {
                                continue;
                            }

                            visited_fragments.insert(frag_name.clone());
                            if self.check_fragment_introspection(
                                &frag_name,
                                fragments,
                                visited_fragments,
                            ) {
                                return true;
                            }
                            visited_fragments.remove(&frag_name);
                        }
                    }
                }
                cst::Selection::InlineFragment(inline) => {
                    if let Some(ss) = inline.selection_set() {
                        if self.contains_introspection(&ss, fragments, visited_fragments) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if a field name is a blocked introspection field.
    fn is_blocked_introspection_field(&self, name: &str) -> bool {
        // __typename is often needed for Apollo Client union/interface resolution
        if name == "__typename" && self.config.allow_typename {
            return false;
        }

        // Block all other __ prefixed fields (__schema, __type)
        name.starts_with("__")
    }

    /// Check if a fragment contains introspection.
    fn check_fragment_introspection(
        &self,
        fragment_name: &str,
        fragments: &HashMap<String, FragmentInfo>,
        visited_fragments: &mut HashSet<String>,
    ) -> bool {
        if let Some(frag_info) = fragments.get(fragment_name) {
            if !frag_info.selection_set_text.is_empty() {
                let query = format!("{{ {} }}", frag_info.selection_set_text);
                let parser = apollo_parser::Parser::new(&query);
                let cst = parser.parse();

                if cst.errors().len() == 0 {
                    for def in cst.document().definitions() {
                        if let cst::Definition::OperationDefinition(op) = def {
                            if let Some(ss) = op.selection_set() {
                                if self.contains_introspection(&ss, fragments, visited_fragments) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if the client is allowed to introspect.
    fn is_client_allowed(&self, ctx: &AnalysisContext) -> bool {
        // If introspection is generally allowed, permit it
        if self.config.allow {
            return true;
        }

        // Client address (as reported by Zentinel) in an allowed IP or range.
        // An address that does not parse matches nothing.
        if let Ok(ip) = ctx.client_ip.trim().parse::<IpAddr>() {
            let ip = ip.to_canonical();
            if self.allowed_networks.iter().any(|net| net.contains(&ip)) {
                return true;
            }
        }

        // Header-based allowlist. Only the non-IP entries are secrets; an IP
        // entry sent as the header value must not grant access.
        if let Some(ref header_name) = self.config.allowed_clients_header {
            if let Some(header_value) = ctx.header(header_name) {
                if self.allowed_header_values.contains(header_value.trim()) {
                    return true;
                }
            }
        }

        false
    }
}

#[async_trait(?Send)]
impl Analyzer for IntrospectionAnalyzer {
    fn name(&self) -> &'static str {
        "introspection"
    }

    async fn analyze(&self, document: &ParsedDocument, ctx: &AnalysisContext) -> AnalysisResult {
        let mut has_introspection = false;

        // Check each operation for introspection
        for definition in document.document.definitions() {
            if let cst::Definition::OperationDefinition(op) = definition {
                if let Some(selection_set) = op.selection_set() {
                    let mut visited = HashSet::new();
                    if self.contains_introspection(
                        &selection_set,
                        &document.fragments,
                        &mut visited,
                    ) {
                        has_introspection = true;
                        break;
                    }
                }
            }
        }

        let client_allowed = self.is_client_allowed(ctx);

        debug!(
            correlation_id = %ctx.correlation_id,
            has_introspection = has_introspection,
            client_allowed = client_allowed,
            allow_introspection = self.config.allow,
            "Introspection analysis complete"
        );

        // Block introspection if found and client is not allowed
        if has_introspection && !client_allowed {
            AnalysisResult::violation(Violation::introspection_blocked())
        } else {
            AnalysisResult::ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_query;

    fn test_config() -> IntrospectionConfig {
        IntrospectionConfig {
            enabled: true,
            allow: false,
            allowed_clients: Vec::new(),
            allowed_clients_header: None,
            allow_typename: true,
        }
    }

    fn test_context() -> AnalysisContext {
        AnalysisContext {
            correlation_id: "test".to_string(),
            client_ip: "127.0.0.1".to_string(),
            headers: HashMap::new(),
            operation_name: None,
            variables: None,
            extensions: None,
            is_batch: false,
            batch_count: 1,
            query: String::new(),
        }
    }

    #[tokio::test]
    async fn test_normal_query() {
        let analyzer = IntrospectionAnalyzer::new(test_config());
        let doc = parse_query("{ users { id name } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_typename_allowed() {
        let analyzer = IntrospectionAnalyzer::new(test_config());
        let doc = parse_query("{ users { __typename id name } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        // __typename is allowed by default
        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_typename_blocked() {
        let mut config = test_config();
        config.allow_typename = false;
        let analyzer = IntrospectionAnalyzer::new(config);
        let doc = parse_query("{ users { __typename id name } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::IntrospectionBlocked
        );
    }

    #[tokio::test]
    async fn test_schema_introspection_blocked() {
        let analyzer = IntrospectionAnalyzer::new(test_config());
        let doc = parse_query("{ __schema { types { name } } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::IntrospectionBlocked
        );
    }

    #[tokio::test]
    async fn test_type_introspection_blocked() {
        let analyzer = IntrospectionAnalyzer::new(test_config());
        let doc = parse_query("{ __type(name: \"User\") { name fields { name } } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
    }

    #[tokio::test]
    async fn test_introspection_allowed_globally() {
        let mut config = test_config();
        config.allow = true;
        let analyzer = IntrospectionAnalyzer::new(config);
        let doc = parse_query("{ __schema { types { name } } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_introspection_allowed_by_ip() {
        let mut config = test_config();
        config.allowed_clients = vec!["127.0.0.1".to_string()];
        let analyzer = IntrospectionAnalyzer::new(config);
        let doc = parse_query("{ __schema { types { name } } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
    }

    async fn introspection_blocked_for(config: IntrospectionConfig, ctx: &AnalysisContext) -> bool {
        let analyzer = IntrospectionAnalyzer::new(config);
        let doc = parse_query("{ __schema { types { name } } }").unwrap();
        analyzer.analyze(&doc, ctx).await.has_violations()
    }

    fn ctx_from(ip: &str) -> AnalysisContext {
        let mut ctx = test_context();
        ctx.client_ip = ip.to_string();
        ctx
    }

    #[tokio::test]
    async fn test_introspection_allowed_by_cidr() {
        let mut config = test_config();
        config.allowed_clients = vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()];

        assert!(!introspection_blocked_for(config.clone(), &ctx_from("10.1.2.3")).await);
        assert!(!introspection_blocked_for(config.clone(), &ctx_from("2001:db8::1")).await);
        // IPv4-mapped IPv6 form of an allowed IPv4 address
        assert!(!introspection_blocked_for(config.clone(), &ctx_from("::ffff:10.1.2.3")).await);
        assert!(introspection_blocked_for(config.clone(), &ctx_from("11.0.0.1")).await);
        assert!(introspection_blocked_for(config.clone(), &ctx_from("2001:db9::1")).await);
        // No usable address matches nothing.
        assert!(introspection_blocked_for(config.clone(), &ctx_from("unknown")).await);
        assert!(introspection_blocked_for(config, &ctx_from("")).await);
    }

    #[tokio::test]
    async fn test_introspection_exact_ip_and_host_bits() {
        let mut config = test_config();
        config.allowed_clients = vec!["192.0.2.7".to_string(), "198.51.100.77/24".to_string()];

        assert!(!introspection_blocked_for(config.clone(), &ctx_from("192.0.2.7")).await);
        assert!(introspection_blocked_for(config.clone(), &ctx_from("192.0.2.8")).await);
        assert!(!introspection_blocked_for(config.clone(), &ctx_from("198.51.100.1")).await);
    }

    #[tokio::test]
    async fn test_ip_entry_is_not_a_header_secret() {
        let mut config = test_config();
        config.allowed_clients = vec!["127.0.0.1".to_string(), "10.0.0.0/8".to_string()];
        config.allowed_clients_header = Some("x-introspection-key".to_string());

        for value in ["127.0.0.1", "10.0.0.0/8"] {
            let mut ctx = ctx_from("203.0.113.5");
            ctx.headers
                .insert("x-introspection-key".to_string(), vec![value.to_string()]);
            assert!(
                introspection_blocked_for(config.clone(), &ctx).await,
                "header value {value} granted introspection"
            );
        }
    }

    #[tokio::test]
    async fn test_introspection_allowed_by_header() {
        let mut config = test_config();
        config.allowed_clients = vec!["secret-key".to_string()];
        config.allowed_clients_header = Some("x-introspection-key".to_string());
        let analyzer = IntrospectionAnalyzer::new(config);
        let doc = parse_query("{ __schema { types { name } } }").unwrap();

        let mut ctx = test_context();
        ctx.headers.insert(
            "x-introspection-key".to_string(),
            vec!["secret-key".to_string()],
        );

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_introspection_blocked_wrong_header() {
        let mut config = test_config();
        config.allowed_clients = vec!["secret-key".to_string()];
        config.allowed_clients_header = Some("x-introspection-key".to_string());
        let analyzer = IntrospectionAnalyzer::new(config);
        let doc = parse_query("{ __schema { types { name } } }").unwrap();

        let mut ctx = test_context();
        ctx.headers.insert(
            "x-introspection-key".to_string(),
            vec!["wrong-key".to_string()],
        );

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
    }
}
