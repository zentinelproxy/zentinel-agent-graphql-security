//! Query depth analyzer.
//!
//! Calculates the maximum nesting depth of a GraphQL query and enforces limits.

use super::{AnalysisContext, AnalysisMetrics, AnalysisResult, Analyzer};
use crate::config::DepthConfig;
use crate::error::Violation;
use crate::parser::{spread_name, ParsedDocument};
use apollo_parser::cst;
use async_trait::async_trait;
use std::collections::HashMap;
use tracing::debug;

/// Analyzer that limits query depth.
pub struct DepthAnalyzer {
    config: DepthConfig,
}

impl DepthAnalyzer {
    /// Create a new depth analyzer.
    pub fn new(config: DepthConfig) -> Self {
        Self { config }
    }

    /// Calculate the maximum depth of a selection set.
    ///
    /// `fragment_depths` holds the depth of each fragment already worked out;
    /// a spread is as deep as its fragment.
    fn calculate_depth(
        &self,
        selection_set: &cst::SelectionSet,
        fragment_depths: &HashMap<&str, u32>,
    ) -> u32 {
        let mut max_depth = 0;

        for selection in selection_set.selections() {
            let depth = match selection {
                cst::Selection::Field(field) => {
                    let field_name = field
                        .name()
                        .map(|n| n.text().to_string())
                        .unwrap_or_default();

                    // Skip introspection fields if configured
                    if self.config.ignore_introspection && is_introspection_field(&field_name) {
                        0
                    } else {
                        let nested_depth = field
                            .selection_set()
                            .map(|ss| self.calculate_depth(&ss, fragment_depths))
                            .unwrap_or(0);
                        1 + nested_depth
                    }
                }
                cst::Selection::FragmentSpread(spread) => spread_name(&spread)
                    .and_then(|name| fragment_depths.get(name.as_str()).copied())
                    .unwrap_or(0),
                cst::Selection::InlineFragment(inline) => inline
                    .selection_set()
                    .map(|ss| self.calculate_depth(&ss, fragment_depths))
                    .unwrap_or(0),
            };

            max_depth = max_depth.max(depth);
        }

        max_depth
    }
}

/// Check if a field name is an introspection field.
fn is_introspection_field(name: &str) -> bool {
    name.starts_with("__")
}

#[async_trait(?Send)]
impl Analyzer for DepthAnalyzer {
    fn name(&self) -> &'static str {
        "depth"
    }

    async fn analyze(&self, document: &ParsedDocument, ctx: &AnalysisContext) -> AnalysisResult {
        let mut max_depth: u32 = 0;

        let fragment_depths = document.fold_fragments(|fragment, depths| {
            fragment
                .selection_set
                .as_ref()
                .map(|ss| self.calculate_depth(ss, depths))
                .unwrap_or(0)
        });

        // Analyze each operation in the document
        for definition in document.document.definitions() {
            if let cst::Definition::OperationDefinition(op) = definition {
                if let Some(selection_set) = op.selection_set() {
                    let depth = self.calculate_depth(&selection_set, &fragment_depths);
                    max_depth = max_depth.max(depth);
                }
            }
        }

        debug!(
            correlation_id = %ctx.correlation_id,
            depth = max_depth,
            max_depth = self.config.max_depth,
            "Depth analysis complete"
        );

        let metrics = AnalysisMetrics {
            depth: Some(max_depth),
            ..Default::default()
        };

        if max_depth > self.config.max_depth {
            AnalysisResult {
                violations: vec![Violation::depth_exceeded(max_depth, self.config.max_depth)],
                metrics,
            }
        } else {
            AnalysisResult::with_metrics(metrics)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_query;

    fn test_config() -> DepthConfig {
        DepthConfig {
            enabled: true,
            max_depth: 5,
            ignore_introspection: true,
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
    async fn test_simple_query_depth() {
        let analyzer = DepthAnalyzer::new(test_config());
        let doc = parse_query("{ users { id name } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        assert_eq!(result.metrics.depth, Some(2));
    }

    #[tokio::test]
    async fn test_nested_query_depth() {
        let analyzer = DepthAnalyzer::new(test_config());
        let doc = parse_query("{ users { posts { comments { author { name } } } } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        assert_eq!(result.metrics.depth, Some(5));
    }

    #[tokio::test]
    async fn test_exceeds_depth() {
        let analyzer = DepthAnalyzer::new(test_config());
        let doc = parse_query("{ a { b { c { d { e { f { g } } } } } } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::DepthExceeded
        );
        assert_eq!(result.metrics.depth, Some(7));
    }

    #[tokio::test]
    async fn test_introspection_ignored() {
        let analyzer = DepthAnalyzer::new(test_config());
        let doc = parse_query("{ __schema { types { name fields { name } } } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        // Introspection should be ignored, depth = 0
        assert!(!result.has_violations());
        assert_eq!(result.metrics.depth, Some(0));
    }

    #[tokio::test]
    async fn test_introspection_counted_when_disabled() {
        let config = DepthConfig {
            enabled: true,
            max_depth: 5,
            ignore_introspection: false,
        };
        let analyzer = DepthAnalyzer::new(config);
        let doc = parse_query("{ __schema { types { name fields { name } } } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        // Introspection counted, depth = 4
        assert!(!result.has_violations());
        assert_eq!(result.metrics.depth, Some(4));
    }

    #[tokio::test]
    async fn test_inline_fragment_depth() {
        let analyzer = DepthAnalyzer::new(test_config());
        let doc = parse_query("{ users { ... on User { posts { title } } } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        // users(1) -> inline fragment(0) -> posts(1) -> title(1) = 3
        // The inline fragment doesn't add depth, but the nested fields do
        assert_eq!(result.metrics.depth, Some(3));
    }

    /// Depth of `query` under the test limit.
    async fn depth_of(query: &str) -> AnalysisResult {
        let analyzer = DepthAnalyzer::new(test_config());
        let doc = parse_query(query).unwrap();
        analyzer.analyze(&doc, &test_context()).await
    }

    #[tokio::test]
    async fn test_named_fragment_depth_matches_inline() {
        let with_fragment = depth_of(
            "{ users { ...UserFields } } \
             fragment UserFields on User { posts { comments { author { friends { name } } } } }",
        )
        .await;
        let inline =
            depth_of("{ users { posts { comments { author { friends { name } } } } } }").await;

        assert_eq!(inline.metrics.depth, Some(6));
        assert_eq!(with_fragment.metrics.depth, inline.metrics.depth);
        assert_eq!(
            with_fragment.violations[0].code,
            crate::error::ViolationCode::DepthExceeded
        );
    }

    #[tokio::test]
    async fn test_nested_named_fragment_depth() {
        let result = depth_of(
            "{ a { ...A } } \
             fragment A on T { b { ...B } } \
             fragment B on T { c { d { e { f } } } }",
        )
        .await;

        assert_eq!(result.metrics.depth, Some(6));
        assert!(result.has_violations());
    }

    #[tokio::test]
    async fn test_spread_inside_inline_fragment_depth() {
        let result = depth_of(
            "{ a { ... on T { ...F } } } \
             fragment F on T { b { c { d { e { f } } } } }",
        )
        .await;

        assert_eq!(result.metrics.depth, Some(6));
        assert!(result.has_violations());
    }

    #[tokio::test]
    async fn test_shallow_named_fragment_is_within_limit() {
        let result = depth_of("{ a { ...F } } fragment F on T { b { c } }").await;

        assert_eq!(result.metrics.depth, Some(3));
        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_unknown_fragment_adds_no_depth() {
        let result = depth_of("{ a { ...Missing } }").await;

        assert_eq!(result.metrics.depth, Some(1));
        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_repeated_spreads_do_not_multiply_depth() {
        let query = crate::analyzer::doubling_fragment_chain(40, "a { b }");
        let result = depth_of(&query).await;

        assert_eq!(result.metrics.depth, Some(2));
        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_fragment_cycle_in_a_document_that_was_not_checked_ends() {
        let doc = crate::parser::parse_query_unchecked(
            "{ ...Alpha } \
             fragment Alpha on Query { a { b } ...Beta } \
             fragment Beta on Query { c ...Alpha }",
        );
        let result = DepthAnalyzer::new(test_config())
            .analyze(&doc, &test_context())
            .await;

        assert_eq!(result.metrics.depth, Some(2));
    }
}
