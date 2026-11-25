//! Alias analyzer.
//!
//! Counts aliases in a GraphQL query and enforces limits to prevent alias-based attacks.

use super::{AnalysisContext, AnalysisMetrics, AnalysisResult, Analyzer};
use crate::config::AliasConfig;
use crate::error::Violation;
use crate::parser::ParsedDocument;
use apollo_parser::cst;
use async_trait::async_trait;
use std::collections::HashMap;
use tracing::debug;

/// Analyzer that limits aliases in queries.
pub struct AliasAnalyzer {
    config: AliasConfig,
}

impl AliasAnalyzer {
    /// Create a new alias analyzer.
    pub fn new(config: AliasConfig) -> Self {
        Self { config }
    }

    /// Count aliases in a selection set, as many times as it appears.
    ///
    /// Fragment spreads are not followed: each fragment is counted on its own,
    /// with the number of times it is spread as `times`.
    fn count_aliases(
        &self,
        selection_set: &cst::SelectionSet,
        times: u64,
        alias_counts: &mut AliasCounters,
    ) {
        for selection in selection_set.selections() {
            match selection {
                cst::Selection::Field(field) => {
                    let field_name = field
                        .name()
                        .map(|n| n.text().to_string())
                        .unwrap_or_default();

                    // Check for alias
                    if let Some(alias) = field.alias() {
                        if alias.name().is_some() {
                            alias_counts.total_aliases =
                                alias_counts.total_aliases.saturating_add(times);
                            let count = alias_counts
                                .field_alias_counts
                                .entry(field_name.clone())
                                .or_insert(0);
                            *count = count.saturating_add(times);
                        }
                    }

                    // Recurse into nested selection set
                    if let Some(ss) = field.selection_set() {
                        self.count_aliases(&ss, times, alias_counts);
                    }
                }
                // Counted with the fragment itself
                cst::Selection::FragmentSpread(_) => {}
                cst::Selection::InlineFragment(inline) => {
                    if let Some(ss) = inline.selection_set() {
                        self.count_aliases(&ss, times, alias_counts);
                    }
                }
            }
        }
    }
}

/// Counters for alias tracking.
#[derive(Debug, Default)]
struct AliasCounters {
    /// Total number of aliases
    total_aliases: u64,
    /// Number of times each field is aliased
    field_alias_counts: HashMap<String, u64>,
}

/// Narrow a count to the `u32` the limits and metrics use, saturating.
fn clamp_to_u32(count: u64) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

#[async_trait(?Send)]
impl Analyzer for AliasAnalyzer {
    fn name(&self) -> &'static str {
        "aliases"
    }

    async fn analyze(&self, document: &ParsedDocument, ctx: &AnalysisContext) -> AnalysisResult {
        let mut alias_counts = AliasCounters::default();

        // Analyze each operation in the document
        let mut operations = Vec::new();
        for definition in document.document.definitions() {
            if let cst::Definition::OperationDefinition(op) = definition {
                if let Some(selection_set) = op.selection_set() {
                    self.count_aliases(&selection_set, 1, &mut alias_counts);
                    operations.push(selection_set);
                }
            }
        }

        // Each fragment the operations spread counts once for every spread
        let fragment_uses = document.fragment_uses(&operations);
        for name in &document.fragment_order {
            let times = fragment_uses.get(name.as_str()).copied().unwrap_or(0);
            if times == 0 {
                continue;
            }
            if let Some(selection_set) = document
                .fragments
                .get(name)
                .and_then(|fragment| fragment.selection_set.as_ref())
            {
                self.count_aliases(selection_set, times, &mut alias_counts);
            }
        }

        let total_aliases = clamp_to_u32(alias_counts.total_aliases);

        // Find max duplicate alias count
        let max_duplicate = alias_counts
            .field_alias_counts
            .values()
            .copied()
            .max()
            .map_or(0, clamp_to_u32);

        debug!(
            correlation_id = %ctx.correlation_id,
            total_aliases = total_aliases,
            max_duplicate = max_duplicate,
            max_aliases = self.config.max_aliases,
            max_duplicate_aliases = self.config.max_duplicate_aliases,
            "Alias analysis complete"
        );

        let metrics = AnalysisMetrics {
            aliases: Some(total_aliases),
            ..Default::default()
        };

        let mut violations = Vec::new();

        // Check total aliases
        if total_aliases > self.config.max_aliases {
            violations.push(Violation::too_many_aliases(
                total_aliases,
                self.config.max_aliases,
            ));
        }

        // Check duplicate aliases
        if max_duplicate > self.config.max_duplicate_aliases {
            violations.push(Violation::new(
                crate::error::ViolationCode::TooManyAliases,
                format!(
                    "Field aliased {} times, maximum allowed is {}",
                    max_duplicate, self.config.max_duplicate_aliases
                ),
            ));
        }

        AnalysisResult {
            violations,
            metrics,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_query;

    fn test_config() -> AliasConfig {
        AliasConfig {
            enabled: true,
            max_aliases: 5,
            max_duplicate_aliases: 2,
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
    async fn test_no_aliases() {
        let analyzer = AliasAnalyzer::new(test_config());
        let doc = parse_query("{ users { id name } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        assert_eq!(result.metrics.aliases, Some(0));
    }

    #[tokio::test]
    async fn test_within_alias_limit() {
        let analyzer = AliasAnalyzer::new(test_config());
        let doc = parse_query("{ a: user(id: 1) { id } b: user(id: 2) { id } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        assert_eq!(result.metrics.aliases, Some(2));
    }

    #[tokio::test]
    async fn test_exceeds_total_aliases() {
        let analyzer = AliasAnalyzer::new(test_config());
        let doc = parse_query(
            "{ a: user(id: 1) { id } b: user(id: 2) { id } c: user(id: 3) { id } d: user(id: 4) { id } e: user(id: 5) { id } f: user(id: 6) { id } }",
        )
        .unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::TooManyAliases
        );
        assert_eq!(result.metrics.aliases, Some(6));
    }

    #[tokio::test]
    async fn test_exceeds_duplicate_aliases() {
        let mut config = test_config();
        config.max_aliases = 10;
        config.max_duplicate_aliases = 2;
        let analyzer = AliasAnalyzer::new(config);
        let doc =
            parse_query("{ a: user(id: 1) { id } b: user(id: 2) { id } c: user(id: 3) { id } }")
                .unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
        // 3 aliases of "user" exceeds max_duplicate_aliases of 2
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::TooManyAliases
        );
    }

    #[tokio::test]
    async fn test_nested_aliases() {
        let analyzer = AliasAnalyzer::new(test_config());
        let doc = parse_query("{ users { a: posts { id } b: posts { id } } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        assert_eq!(result.metrics.aliases, Some(2));
    }

    async fn aliases_of(config: AliasConfig, query: &str) -> AnalysisResult {
        let analyzer = AliasAnalyzer::new(config);
        let doc = parse_query(query).unwrap();
        analyzer.analyze(&doc, &test_context()).await
    }

    #[tokio::test]
    async fn test_named_fragment_aliases_match_inline() {
        let with_fragment = aliases_of(
            test_config(),
            "{ ...F } fragment F on Query { a: x b: x c: y d: y e: z f: z }",
        )
        .await;
        let inline = aliases_of(test_config(), "{ a: x b: x c: y d: y e: z f: z }").await;

        assert_eq!(inline.metrics.aliases, Some(6));
        assert_eq!(with_fragment.metrics.aliases, inline.metrics.aliases);
        assert_eq!(
            with_fragment.violations[0].code,
            crate::error::ViolationCode::TooManyAliases
        );
    }

    #[tokio::test]
    async fn test_fragment_aliases_count_toward_duplicates() {
        let mut config = test_config();
        config.max_aliases = 10;
        let result = aliases_of(
            config,
            "{ a: user ...F } fragment F on Query { b: user c: user }",
        )
        .await;

        // 3 aliases of "user" exceeds max_duplicate_aliases of 2
        assert_eq!(result.metrics.aliases, Some(3));
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::TooManyAliases
        );
    }

    #[tokio::test]
    async fn test_aliases_in_nested_fragments_are_counted() {
        let result = aliases_of(
            test_config(),
            "{ users { ...A ... on User { ...B } } } \
             fragment A on User { a1: x a2: y { a3: z } } \
             fragment B on User { b1: x b2: y b3: z }",
        )
        .await;

        assert_eq!(result.metrics.aliases, Some(6));
        assert!(result.has_violations());
    }

    #[tokio::test]
    async fn test_repeated_spreads_count_aliases_each_time() {
        let mut config = test_config();
        config.max_aliases = 10;
        config.max_duplicate_aliases = 10;
        let with_fragment = aliases_of(
            config.clone(),
            "{ ...F ...F ...F } fragment F on Query { a: x b: y }",
        )
        .await;
        let inline = aliases_of(config, "{ a: x b: y a: x b: y a: x b: y }").await;

        assert_eq!(inline.metrics.aliases, Some(6));
        assert_eq!(with_fragment.metrics.aliases, inline.metrics.aliases);
    }

    #[tokio::test]
    async fn test_duplicate_count_includes_repeated_spreads() {
        let mut config = test_config();
        config.max_aliases = 100;
        // `x` is aliased once per spread: 3 times, over the limit of 2.
        let result = aliases_of(config, "{ ...F ...F ...F } fragment F on Query { a: x }").await;

        assert_eq!(result.metrics.aliases, Some(3));
        assert_eq!(result.violations.len(), 1);
        assert!(result.violations[0].message.contains("3 times"));
    }

    #[tokio::test]
    async fn test_unknown_fragment_adds_no_aliases() {
        let result = aliases_of(test_config(), "{ a: x ...Missing }").await;

        assert_eq!(result.metrics.aliases, Some(1));
        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_repeated_spread_chain_alias_count_is_exact() {
        // 2^5 copies of one alias.
        let mut config = test_config();
        config.max_aliases = 100;
        config.max_duplicate_aliases = 100;
        let query = crate::analyzer::doubling_fragment_chain(6, "a: b");
        let result = aliases_of(config, &query).await;

        assert_eq!(result.metrics.aliases, Some(32));
        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_alias_count_saturates_instead_of_wrapping() {
        // 2^39 copies: the count does not fit in 32 bits.
        let query = crate::analyzer::doubling_fragment_chain(40, "a: b");
        let result = aliases_of(test_config(), &query).await;

        assert_eq!(result.metrics.aliases, Some(u32::MAX));
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::TooManyAliases
        );
    }

    #[tokio::test]
    async fn test_fragment_cycle_in_a_document_that_was_not_checked_ends() {
        let doc = crate::parser::parse_query_unchecked(
            "{ ...Alpha } \
             fragment Alpha on Query { a: x ...Beta } \
             fragment Beta on Query { b: y ...Alpha }",
        );
        let result = AliasAnalyzer::new(test_config())
            .analyze(&doc, &test_context())
            .await;

        assert!(result.metrics.aliases.is_some());
    }
}
