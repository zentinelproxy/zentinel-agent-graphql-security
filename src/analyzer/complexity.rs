//! Query complexity analyzer.
//!
//! Calculates the cost of a GraphQL query based on field costs and list multipliers.

use super::{AnalysisContext, AnalysisMetrics, AnalysisResult, Analyzer};
use crate::config::ComplexityConfig;
use crate::error::Violation;
use crate::parser::{spread_name, ParsedDocument};
use apollo_parser::cst;
use async_trait::async_trait;
use std::collections::HashMap;
use tracing::debug;

/// The cost of a selection set, split by what the list multiplier of the
/// field above it applies to.
///
/// A field costs its own cost times that multiplier, plus the cost of its
/// selection set, which carries the multiplier of the field itself. So the
/// cost of a selection set is linear in the multiplier it is reached with,
/// and a fragment's cost can be worked out once and used at every spread.
#[derive(Debug, Clone, Copy, Default)]
struct Cost {
    /// Cost that is multiplied by the multiplier the selection set is reached with
    scaled: u64,
    /// Cost that is not
    fixed: u64,
}

impl Cost {
    fn add(&mut self, other: Cost) {
        self.scaled = self.scaled.saturating_add(other.scaled);
        self.fixed = self.fixed.saturating_add(other.fixed);
    }

    /// The cost when reached with `multiplier`. Saturates at `u64::MAX`.
    fn at(self, multiplier: u64) -> u64 {
        self.scaled
            .saturating_mul(multiplier)
            .saturating_add(self.fixed)
    }
}

/// Analyzer that limits query complexity.
pub struct ComplexityAnalyzer {
    config: ComplexityConfig,
}

impl ComplexityAnalyzer {
    /// Create a new complexity analyzer.
    pub fn new(config: ComplexityConfig) -> Self {
        Self { config }
    }

    /// Calculate the complexity of a selection set.
    ///
    /// `fragment_costs` holds the cost of each fragment already worked out.
    fn calculate_complexity(
        &self,
        selection_set: &cst::SelectionSet,
        fragment_costs: &HashMap<&str, Cost>,
        parent_type: Option<&str>,
    ) -> Cost {
        let mut total = Cost::default();

        for selection in selection_set.selections() {
            match selection {
                cst::Selection::Field(field) => {
                    let field_name = field
                        .name()
                        .map(|n| n.text().to_string())
                        .unwrap_or_default();

                    // Get field cost
                    let field_cost = self.get_field_cost(&field_name, parent_type);

                    // Get list multiplier from arguments
                    let multiplier = self.get_list_multiplier(&field);

                    // Calculate nested complexity
                    let nested_complexity = field
                        .selection_set()
                        .map(|ss| {
                            // We don't know the nested type without schema
                            self.calculate_complexity(&ss, fragment_costs, None)
                                .at(multiplier)
                        })
                        .unwrap_or(0);

                    // Total: base cost (times the parent multiplier) + (nested cost * multiplier)
                    total.add(Cost {
                        scaled: field_cost,
                        fixed: nested_complexity,
                    });
                }
                cst::Selection::FragmentSpread(spread) => {
                    if let Some(cost) =
                        spread_name(&spread).and_then(|name| fragment_costs.get(name.as_str()))
                    {
                        total.add(*cost);
                    }
                }
                cst::Selection::InlineFragment(inline) => {
                    let type_cond = inline
                        .type_condition()
                        .and_then(|tc| tc.named_type())
                        .and_then(|nt| nt.name())
                        .map(|n| n.text().to_string());

                    if let Some(ss) = inline.selection_set() {
                        total.add(self.calculate_complexity(
                            &ss,
                            fragment_costs,
                            type_cond.as_deref(),
                        ));
                    }
                }
            }
        }

        total
    }

    /// Get the cost for a field.
    fn get_field_cost(&self, field_name: &str, parent_type: Option<&str>) -> u64 {
        // Check for specific field cost first
        if let Some(parent) = parent_type {
            let full_name = format!("{}.{}", parent, field_name);
            if let Some(cost) = self.config.field_costs.get(&full_name) {
                return *cost;
            }
        }

        // Check for Query.field or Mutation.field
        let query_field = format!("Query.{}", field_name);
        if let Some(cost) = self.config.field_costs.get(&query_field) {
            return *cost;
        }

        let mutation_field = format!("Mutation.{}", field_name);
        if let Some(cost) = self.config.field_costs.get(&mutation_field) {
            return *cost;
        }

        // Check for type cost
        if let Some(parent) = parent_type {
            if let Some(cost) = self.config.type_costs.get(parent) {
                return *cost;
            }
        }

        // Default cost
        self.config.default_field_cost
    }

    /// Get the list multiplier from field arguments.
    fn get_list_multiplier(&self, field: &cst::Field) -> u64 {
        if let Some(args) = field.arguments() {
            for arg in args.arguments() {
                if let Some(arg_name) = arg.name() {
                    let name = arg_name.text();
                    if self
                        .config
                        .list_size_arguments
                        .iter()
                        .any(|s| s.as_str() == name.as_str())
                    {
                        // Try to extract the value
                        if let Some(value) = arg.value() {
                            if let Some(num) = extract_int_value(&value) {
                                return num.max(1) as u64;
                            }
                        }
                    }
                }
            }
        }

        // Default multiplier if no list size argument found
        self.config.default_list_multiplier
    }
}

/// Extract integer value from a CST value.
fn extract_int_value(value: &cst::Value) -> Option<i64> {
    match value {
        cst::Value::IntValue(v) => v.int_token().and_then(|t| t.text().parse().ok()),
        cst::Value::Variable(_) => {
            // Can't evaluate variables without runtime context
            // Use default multiplier
            None
        }
        _ => None,
    }
}

#[async_trait(?Send)]
impl Analyzer for ComplexityAnalyzer {
    fn name(&self) -> &'static str {
        "complexity"
    }

    async fn analyze(&self, document: &ParsedDocument, ctx: &AnalysisContext) -> AnalysisResult {
        let mut total_complexity: u64 = 0;

        let fragment_costs = document.fold_fragments(|fragment, costs| {
            fragment
                .selection_set
                .as_ref()
                .map(|ss| self.calculate_complexity(ss, costs, Some(&fragment.type_condition)))
                .unwrap_or_default()
        });

        for definition in document.document.definitions() {
            if let cst::Definition::OperationDefinition(op) = definition {
                if let Some(selection_set) = op.selection_set() {
                    let complexity = self
                        .calculate_complexity(&selection_set, &fragment_costs, None)
                        .at(1); // Base multiplier
                    total_complexity = total_complexity.saturating_add(complexity);
                }
            }
        }

        debug!(
            correlation_id = %ctx.correlation_id,
            complexity = total_complexity,
            max_complexity = self.config.max_complexity,
            "Complexity analysis complete"
        );

        let metrics = AnalysisMetrics {
            complexity: Some(total_complexity),
            ..Default::default()
        };

        if total_complexity > self.config.max_complexity {
            AnalysisResult {
                violations: vec![Violation::complexity_exceeded(
                    total_complexity,
                    self.config.max_complexity,
                )],
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

    fn test_config() -> ComplexityConfig {
        ComplexityConfig {
            enabled: true,
            max_complexity: 100,
            default_field_cost: 1,
            default_list_multiplier: 10,
            type_costs: HashMap::new(),
            field_costs: HashMap::new(),
            list_size_arguments: vec!["first".to_string(), "last".to_string(), "limit".to_string()],
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
    async fn test_simple_complexity() {
        let analyzer = ComplexityAnalyzer::new(test_config());
        let doc = parse_query("{ users { id name } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        // users(1) + id(1*10) + name(1*10) = 21
        assert_eq!(result.metrics.complexity, Some(21));
    }

    #[tokio::test]
    async fn test_complexity_with_limit() {
        let analyzer = ComplexityAnalyzer::new(test_config());
        let doc = parse_query("{ users(first: 5) { id name } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        // users(1) + id(1*5) + name(1*5) = 11
        assert_eq!(result.metrics.complexity, Some(11));
    }

    #[tokio::test]
    async fn test_exceeds_complexity() {
        let mut config = test_config();
        config.max_complexity = 10;
        let analyzer = ComplexityAnalyzer::new(config);
        let doc = parse_query("{ users { id name email } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::ComplexityExceeded
        );
    }

    #[tokio::test]
    async fn test_custom_field_cost() {
        let mut config = test_config();
        config.field_costs.insert("Query.users".to_string(), 10);
        let analyzer = ComplexityAnalyzer::new(config);
        let doc = parse_query("{ users { id } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        // users(10) + id(1*10) = 20
        assert_eq!(result.metrics.complexity, Some(20));
    }

    #[tokio::test]
    async fn test_nested_list_multipliers() {
        let analyzer = ComplexityAnalyzer::new(test_config());
        let doc = parse_query("{ users(first: 10) { posts(first: 5) { title } } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        // users(1) + posts(1*10) + title(1*5) = 16
        // Note: In this simple model, nested multipliers don't compound
        assert_eq!(result.metrics.complexity, Some(16));
    }

    async fn complexity_of(config: ComplexityConfig, query: &str) -> AnalysisResult {
        let analyzer = ComplexityAnalyzer::new(config);
        let doc = parse_query(query).unwrap();
        analyzer.analyze(&doc, &test_context()).await
    }

    #[tokio::test]
    async fn test_named_fragment_complexity_matches_inline() {
        let with_fragment = complexity_of(
            test_config(),
            "{ users { ...F } } fragment F on User { id name }",
        )
        .await;
        let inline = complexity_of(test_config(), "{ users { id name } }").await;

        // users(1) + id(1*10) + name(1*10) = 21
        assert_eq!(inline.metrics.complexity, Some(21));
        assert_eq!(with_fragment.metrics.complexity, inline.metrics.complexity);
    }

    #[tokio::test]
    async fn test_named_fragment_uses_list_multiplier_of_its_field() {
        let with_fragment = complexity_of(
            test_config(),
            "{ users(first: 5) { ...F } } fragment F on User { id name }",
        )
        .await;
        let inline = complexity_of(test_config(), "{ users(first: 5) { id name } }").await;

        // users(1) + id(1*5) + name(1*5) = 11
        assert_eq!(inline.metrics.complexity, Some(11));
        assert_eq!(with_fragment.metrics.complexity, inline.metrics.complexity);
    }

    #[tokio::test]
    async fn test_nested_named_fragments_complexity_matches_inline() {
        let with_fragments = complexity_of(
            test_config(),
            "{ ...Q } \
             fragment Q on Query { users(first: 2) { ...U } } \
             fragment U on User { id posts { ...P } } \
             fragment P on Post { title }",
        )
        .await;
        let inline =
            complexity_of(test_config(), "{ users(first: 2) { id posts { title } } }").await;

        // users(1) + id(1*2) + posts(1*2) + title(1*10) = 15
        assert_eq!(inline.metrics.complexity, Some(15));
        assert_eq!(with_fragments.metrics.complexity, inline.metrics.complexity);
    }

    #[tokio::test]
    async fn test_spread_inside_inline_fragment_complexity_matches_inline() {
        let with_fragment = complexity_of(
            test_config(),
            "{ users { ... on User { ...F } } } fragment F on User { id }",
        )
        .await;
        let inline = complexity_of(test_config(), "{ users { ... on User { id } } }").await;

        assert_eq!(inline.metrics.complexity, Some(11));
        assert_eq!(with_fragment.metrics.complexity, inline.metrics.complexity);
    }

    #[tokio::test]
    async fn test_fragment_type_condition_selects_type_cost() {
        let mut config = test_config();
        config.type_costs.insert("User".to_string(), 7);
        let with_fragment = complexity_of(
            config.clone(),
            "{ users { ...F } } fragment F on User { id }",
        )
        .await;
        let inline = complexity_of(config, "{ users { ... on User { id } } }").await;

        // users(1) + id(7*10) = 71
        assert_eq!(inline.metrics.complexity, Some(71));
        assert_eq!(with_fragment.metrics.complexity, inline.metrics.complexity);
    }

    #[tokio::test]
    async fn test_repeated_spreads_are_counted_each_time() {
        let with_fragment = complexity_of(
            test_config(),
            "{ ...F ...F ...F } fragment F on Query { users { id } }",
        )
        .await;
        let inline =
            complexity_of(test_config(), "{ users { id } users { id } users { id } }").await;

        // 3 * (users(1) + id(1*10)) = 33
        assert_eq!(inline.metrics.complexity, Some(33));
        assert_eq!(with_fragment.metrics.complexity, inline.metrics.complexity);
    }

    #[tokio::test]
    async fn test_named_fragment_complexity_exceeds_limit() {
        let mut config = test_config();
        config.max_complexity = 10;
        let result = complexity_of(
            config,
            "{ users { ...F } } fragment F on User { id name email }",
        )
        .await;

        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::ComplexityExceeded
        );
    }

    #[tokio::test]
    async fn test_unknown_fragment_adds_no_complexity() {
        let result = complexity_of(test_config(), "{ users { ...Missing } }").await;

        assert_eq!(result.metrics.complexity, Some(1));
        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_repeated_spread_chain_complexity_is_exact() {
        // 2^29 copies of `a`, each costing 1.
        let query = crate::analyzer::doubling_fragment_chain(30, "a");
        let result = complexity_of(test_config(), &query).await;

        assert_eq!(result.metrics.complexity, Some(1 << 29));
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::ComplexityExceeded
        );
    }

    #[tokio::test]
    async fn test_complexity_saturates_instead_of_wrapping() {
        // 2^69 copies: the count does not fit in 64 bits.
        let query = crate::analyzer::doubling_fragment_chain(70, "a { b }");
        let result = complexity_of(test_config(), &query).await;

        assert_eq!(result.metrics.complexity, Some(u64::MAX));
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::ComplexityExceeded
        );
    }

    #[tokio::test]
    async fn test_fragment_cycle_in_a_document_that_was_not_checked_ends() {
        let doc = crate::parser::parse_query_unchecked(
            "{ ...Alpha } \
             fragment Alpha on Query { a ...Beta } \
             fragment Beta on Query { b ...Alpha }",
        );
        let result = ComplexityAnalyzer::new(test_config())
            .analyze(&doc, &test_context())
            .await;

        assert!(result.metrics.complexity.is_some());
    }

    #[tokio::test]
    async fn test_fragment_spread_under_different_multipliers_matches_inline() {
        let with_fragment = complexity_of(
            test_config(),
            "{ a(first: 2) { ...F } b(first: 5) { ...F } } fragment F on T { x y { z } }",
        )
        .await;
        let inline = complexity_of(
            test_config(),
            "{ a(first: 2) { x y { z } } b(first: 5) { x y { z } } }",
        )
        .await;

        // a(1) + x(1*2) + y(1*2) + z(1*10) = 15, b(1) + x(1*5) + y(1*5) + z(1*10) = 21
        assert_eq!(inline.metrics.complexity, Some(36));
        assert_eq!(with_fragment.metrics.complexity, inline.metrics.complexity);
    }

    #[tokio::test]
    async fn test_fragment_spread_at_root_and_under_a_multiplier_matches_inline() {
        let with_fragment = complexity_of(
            test_config(),
            "{ ...F a(first: 3) { ...F } } fragment F on T { x y { ...G } } fragment G on T { z }",
        )
        .await;
        let inline = complexity_of(test_config(), "{ x y { z } a(first: 3) { x y { z } } }").await;

        assert_eq!(with_fragment.metrics.complexity, inline.metrics.complexity);
    }
}
