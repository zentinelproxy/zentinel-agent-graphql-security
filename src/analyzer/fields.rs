//! Field authorization analyzer.
//!
//! Provides field-level authorization based on roles and scopes.

use super::{AnalysisContext, AnalysisMetrics, AnalysisResult, Analyzer};
use crate::config::{FieldAuthConfig, FieldAuthRule};
use crate::error::Violation;
use crate::parser::{extract_fields, FieldInfo, ParsedDocument};
use apollo_parser::cst;
use async_trait::async_trait;
use glob::Pattern;
use std::collections::HashSet;
use tracing::debug;

/// Analyzer that enforces field-level authorization.
pub struct FieldAuthAnalyzer {
    config: FieldAuthConfig,
    /// Compiled glob patterns for each rule
    compiled_rules: Vec<CompiledRule>,
}

/// A rule with compiled glob patterns.
struct CompiledRule {
    /// Original rule
    rule: FieldAuthRule,
    /// Compiled patterns
    patterns: Vec<Pattern>,
}

impl FieldAuthAnalyzer {
    /// Create a new field authorization analyzer.
    pub fn new(config: FieldAuthConfig) -> Self {
        let compiled_rules = config
            .rules
            .iter()
            .map(|rule| {
                let patterns = rule
                    .fields
                    .iter()
                    .filter_map(|f| Pattern::new(f).ok())
                    .collect();
                CompiledRule {
                    rule: rule.clone(),
                    patterns,
                }
            })
            .collect();

        Self {
            config,
            compiled_rules,
        }
    }

    /// Get all fields from the document.
    ///
    /// The returned fields are those of each operation and of each fragment an
    /// operation spreads, the fields of a fragment once however often it is
    /// spread. The count is the number of fields the operations would have if
    /// every spread were replaced by its fragment's selections.
    fn extract_all_fields(&self, document: &ParsedDocument) -> (Vec<FieldInfo>, u64) {
        let mut fields = Vec::new();
        let mut field_count: u64 = 0;
        let mut operations = Vec::new();

        for definition in document.document.definitions() {
            if let cst::Definition::OperationDefinition(op) = definition {
                // Determine the root type based on operation type
                let root_type = op
                    .operation_type()
                    .map(|ot| {
                        if ot.mutation_token().is_some() {
                            "Mutation"
                        } else if ot.subscription_token().is_some() {
                            "Subscription"
                        } else {
                            "Query"
                        }
                    })
                    .unwrap_or("Query");

                if let Some(selection_set) = op.selection_set() {
                    let operation_fields = extract_fields(&selection_set, Some(root_type));
                    field_count = field_count.saturating_add(operation_fields.len() as u64);
                    fields.extend(operation_fields);
                    operations.push(selection_set);
                }
            }
        }

        let fragment_uses = document.fragment_uses(&operations);
        for name in &document.fragment_order {
            let times = fragment_uses.get(name.as_str()).copied().unwrap_or(0);
            if times == 0 {
                continue;
            }
            if let Some((selection_set, type_condition)) =
                document.fragments.get(name).and_then(|fragment| {
                    fragment
                        .selection_set
                        .as_ref()
                        .map(|ss| (ss, &fragment.type_condition))
                })
            {
                let fragment_fields = extract_fields(selection_set, Some(type_condition));
                field_count =
                    field_count.saturating_add(times.saturating_mul(fragment_fields.len() as u64));
                fields.extend(fragment_fields);
            }
        }

        (fields, field_count)
    }

    /// Check if a field matches a rule.
    fn field_matches_rule(&self, field: &FieldInfo, compiled_rule: &CompiledRule) -> bool {
        // Build field identifiers to match against
        let identifiers = self.build_field_identifiers(field);

        // Check if any identifier matches any pattern
        for identifier in &identifiers {
            for pattern in &compiled_rule.patterns {
                if pattern.matches(identifier) {
                    return true;
                }
            }
        }

        false
    }

    /// Build possible field identifiers for matching.
    fn build_field_identifiers(&self, field: &FieldInfo) -> Vec<String> {
        let mut identifiers = Vec::new();

        // Add just the field name
        identifiers.push(field.name.clone());

        // Add Type.field if parent type is known
        if let Some(ref parent) = field.parent_type {
            identifiers.push(format!("{}.{}", parent, field.name));
        }

        identifiers
    }

    /// Check if the client has the required authorization for a rule.
    fn client_authorized(&self, ctx: &AnalysisContext, rule: &FieldAuthRule) -> bool {
        // If no requirements, consider it open (shouldn't happen in practice)
        if rule.require_roles.is_empty() && rule.require_scopes.is_empty() {
            return true;
        }

        // Get client roles from header
        let client_roles = self.get_client_roles(ctx, rule);

        // Get client scopes from header
        let client_scopes = self.get_client_scopes(ctx, rule);

        // Check if client has ANY required role
        if !rule.require_roles.is_empty() {
            for required_role in &rule.require_roles {
                if client_roles.contains(required_role) {
                    return true;
                }
            }
        }

        // Check if client has ANY required scope
        if !rule.require_scopes.is_empty() {
            for required_scope in &rule.require_scopes {
                if client_scopes.contains(required_scope) {
                    return true;
                }
            }
        }

        // If we have role requirements but no roles matched, and we have
        // scope requirements but no scopes matched, deny access
        false
    }

    /// Get client roles from headers.
    fn get_client_roles(&self, ctx: &AnalysisContext, rule: &FieldAuthRule) -> HashSet<String> {
        let header_name = rule.roles_header.as_deref().unwrap_or("x-user-roles");

        ctx.header_csv(header_name).into_iter().collect()
    }

    /// Get client scopes from headers.
    fn get_client_scopes(&self, ctx: &AnalysisContext, rule: &FieldAuthRule) -> HashSet<String> {
        let header_name = rule.scopes_header.as_deref().unwrap_or("x-user-scopes");

        ctx.header_csv(header_name).into_iter().collect()
    }
}

#[async_trait(?Send)]
impl Analyzer for FieldAuthAnalyzer {
    fn name(&self) -> &'static str {
        "field_auth"
    }

    async fn analyze(&self, document: &ParsedDocument, ctx: &AnalysisContext) -> AnalysisResult {
        // Skip if no rules configured
        if self.config.rules.is_empty() {
            return AnalysisResult::ok();
        }

        // Extract all fields from the query
        let (fields, field_count) = self.extract_all_fields(document);

        let mut violations = Vec::new();
        let mut checked_fields = HashSet::new();

        // Check each field against each rule
        for field in &fields {
            // Build field identifier for deduplication
            let field_id = if let Some(ref parent) = field.parent_type {
                format!("{}.{}", parent, field.name)
            } else {
                field.name.clone()
            };

            // Skip if we've already checked this field
            if checked_fields.contains(&field_id) {
                continue;
            }
            checked_fields.insert(field_id.clone());

            // Check against each rule
            for compiled_rule in &self.compiled_rules {
                if self.field_matches_rule(field, compiled_rule)
                    && !self.client_authorized(ctx, &compiled_rule.rule)
                {
                    debug!(
                        correlation_id = %ctx.correlation_id,
                        field = %field_id,
                        "Field access denied"
                    );
                    violations.push(Violation::field_unauthorized(&field_id));
                    break; // One violation per field is enough
                }
            }
        }

        let metrics = AnalysisMetrics {
            fields: Some(u32::try_from(field_count).unwrap_or(u32::MAX)),
            ..Default::default()
        };

        debug!(
            correlation_id = %ctx.correlation_id,
            total_fields = field_count,
            violations = violations.len(),
            "Field auth analysis complete"
        );

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
    use std::collections::HashMap;

    fn test_config_with_rules(rules: Vec<FieldAuthRule>) -> FieldAuthConfig {
        FieldAuthConfig {
            enabled: true,
            rules,
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

    fn admin_rule() -> FieldAuthRule {
        FieldAuthRule {
            fields: vec!["Query.admin*".to_string(), "Mutation.delete*".to_string()],
            require_roles: vec!["admin".to_string()],
            roles_header: None,
            require_scopes: Vec::new(),
            scopes_header: None,
        }
    }

    #[tokio::test]
    async fn test_no_rules() {
        let config = FieldAuthConfig {
            enabled: true,
            rules: Vec::new(),
        };
        let analyzer = FieldAuthAnalyzer::new(config);
        let doc = parse_query("{ users { id } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_unprotected_field() {
        let config = test_config_with_rules(vec![admin_rule()]);
        let analyzer = FieldAuthAnalyzer::new(config);
        let doc = parse_query("{ users { id name } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_protected_field_no_role() {
        let config = test_config_with_rules(vec![admin_rule()]);
        let analyzer = FieldAuthAnalyzer::new(config);
        let doc = parse_query("{ adminUsers { id } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::FieldUnauthorized
        );
    }

    #[tokio::test]
    async fn test_protected_field_with_role() {
        let config = test_config_with_rules(vec![admin_rule()]);
        let analyzer = FieldAuthAnalyzer::new(config);
        let doc = parse_query("{ adminUsers { id } }").unwrap();

        let mut ctx = test_context();
        ctx.headers
            .insert("x-user-roles".to_string(), vec!["admin, user".to_string()]);

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_mutation_protection() {
        let config = test_config_with_rules(vec![admin_rule()]);
        let analyzer = FieldAuthAnalyzer::new(config);
        let doc = parse_query("mutation { deleteUser(id: 1) { success } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
    }

    #[tokio::test]
    async fn test_scope_based_auth() {
        let rule = FieldAuthRule {
            fields: vec!["User.email".to_string()],
            require_roles: Vec::new(),
            roles_header: None,
            require_scopes: vec!["read:email".to_string()],
            scopes_header: Some("x-scopes".to_string()),
        };
        let config = test_config_with_rules(vec![rule]);
        let analyzer = FieldAuthAnalyzer::new(config);
        let doc = parse_query("{ user { id email } }").unwrap();

        let mut ctx = test_context();
        ctx.headers.insert(
            "x-scopes".to_string(),
            vec!["read:profile, read:email".to_string()],
        );

        let result = analyzer.analyze(&doc, &ctx).await;

        // Note: without schema info, we don't know that email's parent is User
        // So this test would pass because we can't match "User.email"
        // In production, this would work with schema-aware analysis
        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_glob_pattern_wildcard() {
        // Using patterns that can match field names directly
        let rule = FieldAuthRule {
            fields: vec!["password".to_string(), "secret*".to_string()],
            require_roles: vec!["admin".to_string()],
            roles_header: None,
            require_scopes: Vec::new(),
            scopes_header: None,
        };
        let config = test_config_with_rules(vec![rule]);
        let analyzer = FieldAuthAnalyzer::new(config);
        let doc = parse_query("{ user { password } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        // "password" field matches "password" pattern
        assert!(result.has_violations());
    }

    #[tokio::test]
    async fn test_custom_roles_header() {
        let rule = FieldAuthRule {
            fields: vec!["Query.admin*".to_string()],
            require_roles: vec!["admin".to_string()],
            roles_header: Some("authorization-roles".to_string()),
            require_scopes: Vec::new(),
            scopes_header: None,
        };
        let config = test_config_with_rules(vec![rule]);
        let analyzer = FieldAuthAnalyzer::new(config);
        let doc = parse_query("{ adminDashboard { stats } }").unwrap();

        let mut ctx = test_context();
        ctx.headers
            .insert("authorization-roles".to_string(), vec!["admin".to_string()]);

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
    }

    fn admin_analyzer() -> FieldAuthAnalyzer {
        FieldAuthAnalyzer::new(test_config_with_rules(vec![admin_rule()]))
    }

    async fn field_auth_result(analyzer: &FieldAuthAnalyzer, query: &str) -> AnalysisResult {
        let doc = parse_query(query).unwrap();
        analyzer.analyze(&doc, &test_context()).await
    }

    #[tokio::test]
    async fn test_protected_field_in_named_fragment() {
        let result = field_auth_result(
            &admin_analyzer(),
            "{ ...F } fragment F on Query { adminUsers { id } }",
        )
        .await;

        assert_eq!(result.violations.len(), 1);
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::FieldUnauthorized
        );
    }

    #[tokio::test]
    async fn test_protected_field_in_nested_named_fragment() {
        let result = field_auth_result(
            &admin_analyzer(),
            "{ ...A } \
             fragment A on Query { ... on Query { ...B } } \
             fragment B on Query { id adminNotes }",
        )
        .await;

        assert_eq!(result.violations.len(), 1);
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::FieldUnauthorized
        );
    }

    #[tokio::test]
    async fn test_protected_field_in_named_fragment_with_role() {
        let analyzer = admin_analyzer();
        let doc = parse_query("{ ...F } fragment F on Query { adminUsers { id } }").unwrap();
        let mut ctx = test_context();
        ctx.headers
            .insert("x-user-roles".to_string(), vec!["admin".to_string()]);

        assert!(!analyzer.analyze(&doc, &ctx).await.has_violations());
    }

    #[tokio::test]
    async fn test_unprotected_named_fragment_passes() {
        let result = field_auth_result(
            &admin_analyzer(),
            "{ ...F } fragment F on Query { users { id name } }",
        )
        .await;

        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_unknown_fragment_adds_no_fields() {
        let result = field_auth_result(&admin_analyzer(), "{ users { ...Missing } }").await;

        assert!(!result.has_violations());
        assert_eq!(result.metrics.fields, Some(1));
    }

    #[tokio::test]
    async fn test_repeated_spreads_are_counted_in_the_field_metric() {
        let result = field_auth_result(
            &admin_analyzer(),
            "{ ...F ...F } fragment F on Query { users { id } adminUsers }",
        )
        .await;

        // users, id, adminUsers, twice; the protected field is reported once.
        assert_eq!(result.metrics.fields, Some(6));
        assert_eq!(result.violations.len(), 1);
    }

    #[tokio::test]
    async fn test_repeated_spread_chain_reports_field_once() {
        // 2^29 copies of the protected field.
        let query = crate::analyzer::doubling_fragment_chain(30, "adminTotals");
        let result = field_auth_result(&admin_analyzer(), &query).await;

        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.metrics.fields, Some(1 << 29));
    }

    #[tokio::test]
    async fn test_field_count_saturates_instead_of_wrapping() {
        let query = crate::analyzer::doubling_fragment_chain(40, "adminTotals");
        let result = field_auth_result(&admin_analyzer(), &query).await;

        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.metrics.fields, Some(u32::MAX));
    }

    #[tokio::test]
    async fn test_fragment_cycle_in_a_document_that_was_not_checked_ends() {
        let doc = crate::parser::parse_query_unchecked(
            "{ ...Alpha } \
             fragment Alpha on Query { adminStats ...Beta } \
             fragment Beta on Query { ...Alpha }",
        );
        let result = admin_analyzer().analyze(&doc, &test_context()).await;

        assert_eq!(result.violations.len(), 1);
    }

    #[tokio::test]
    async fn test_type_rule_matches_fields_of_a_fragment_on_that_type() {
        let rule = FieldAuthRule {
            fields: vec!["User.email".to_string()],
            require_roles: vec!["admin".to_string()],
            roles_header: None,
            require_scopes: Vec::new(),
            scopes_header: None,
        };
        let analyzer = FieldAuthAnalyzer::new(test_config_with_rules(vec![rule]));
        let doc = parse_query("{ user { ...F } } fragment F on User { email }").unwrap();

        let result = analyzer.analyze(&doc, &test_context()).await;
        assert_eq!(result.violations.len(), 1);
        assert!(result.violations[0].message.contains("User.email"));

        let mut ctx = test_context();
        ctx.headers
            .insert("x-user-roles".to_string(), vec!["admin".to_string()]);
        assert!(!analyzer.analyze(&doc, &ctx).await.has_violations());
    }

    #[tokio::test]
    async fn test_fragment_spread_by_two_operations_is_checked_and_counted_for_each() {
        let result = field_auth_result(
            &admin_analyzer(),
            "query One { ...F } query Two { ...F } fragment F on Query { adminUsers }",
        )
        .await;

        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.metrics.fields, Some(2));
    }
}
