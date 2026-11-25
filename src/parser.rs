//! GraphQL parsing utilities.

use crate::error::Violation;
use apollo_parser::cst::{self, CstNode};
use apollo_parser::Parser;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};

/// A parsed GraphQL request.
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    /// The GraphQL query string. `None` for a hash-only persisted-query
    /// request (`extensions.persistedQuery.sha256Hash` without `query`); the
    /// query text is then resolved from a server-side store.
    pub query: Option<String>,
    /// Operation name (if provided)
    pub operation_name: Option<String>,
    /// Variables (if provided)
    pub variables: Option<Value>,
    /// Extensions (e.g., APQ hash)
    pub extensions: Option<Value>,
    /// Whether this is a batch request
    pub is_batch: bool,
    /// Number of queries in batch
    pub batch_count: usize,
}

/// A parsed GraphQL document with CST.
///
/// Fragments are parsed once, with the rest of the document. An analyzer that
/// follows fragment spreads should not recurse from a spread into the
/// fragment: `fold_fragments` gives it one value per fragment to look up at
/// each spread, and `fragment_uses` says how often each fragment is spread.
/// Either way the work is proportional to the size of the document, however
/// often a fragment is spread.
#[derive(Debug)]
pub struct ParsedDocument {
    /// The parsed CST document
    pub document: cst::Document,
    /// Fragment definitions for resolving spreads. When two definitions share
    /// a name, the later one is kept.
    pub fragments: HashMap<String, FragmentInfo>,
    /// The names in `fragments`, each after every fragment it spreads. Spreads
    /// of fragments that are not defined are ignored. `parse_query` rejects
    /// documents whose fragments spread each other in a cycle, so no
    /// fragment is left out of the order.
    pub fragment_order: Vec<String>,
    /// SHA-256 hash of the normalized query
    pub query_hash: String,
}

/// Information about a fragment definition.
#[derive(Debug, Clone)]
pub struct FragmentInfo {
    /// Fragment name
    pub name: String,
    /// Type condition
    pub type_condition: String,
    /// Selection set, from the parse of the whole document
    pub selection_set: Option<cst::SelectionSet>,
    /// Fragments spread anywhere in the selection set (also inside nested
    /// fields and inline fragments), one entry per spread
    pub spreads: Vec<String>,
}

impl ParsedDocument {
    /// Compute one value per fragment from the values of the fragments it spreads.
    ///
    /// `eval` is called once per fragment, after the fragments it spreads,
    /// with the values computed so far, keyed by fragment name. A spread
    /// whose fragment is not defined has no entry. Reading the value of a
    /// spread is a lookup, so the cost of a fragment does not depend on how
    /// often it is spread, and nothing recurses from one fragment into the
    /// next.
    pub(crate) fn fold_fragments<'a, T>(
        &'a self,
        mut eval: impl FnMut(&FragmentInfo, &HashMap<&'a str, T>) -> T,
    ) -> HashMap<&'a str, T> {
        let mut values = HashMap::with_capacity(self.fragment_order.len());
        for name in &self.fragment_order {
            if let Some(fragment) = self.fragments.get(name) {
                let value = eval(fragment, &values);
                values.insert(name.as_str(), value);
            }
        }
        values
    }

    /// Count how often each fragment would appear if every spread, starting
    /// from the selection sets in `roots`, were replaced by the fragment's
    /// selections.
    ///
    /// A fragment that cannot be reached from `roots` has no entry. Counts
    /// saturate at `u64::MAX`.
    pub(crate) fn fragment_uses(&self, roots: &[cst::SelectionSet]) -> HashMap<&str, u64> {
        let mut uses = HashMap::new();

        let mut root_spreads = Vec::new();
        for root in roots {
            collect_spreads(root, &mut root_spreads);
        }
        for name in &root_spreads {
            self.add_uses(&mut uses, name, 1);
        }

        // Dependents come before the fragments they spread, so a fragment's
        // count is complete when it is passed on to the fragments it spreads.
        for name in self.fragment_order.iter().rev() {
            let Some(&count) = uses.get(name.as_str()) else {
                continue;
            };
            if let Some(fragment) = self.fragments.get(name) {
                for spread in &fragment.spreads {
                    self.add_uses(&mut uses, spread, count);
                }
            }
        }

        uses
    }

    fn add_uses<'a>(&'a self, uses: &mut HashMap<&'a str, u64>, name: &str, count: u64) {
        if let Some((defined, _)) = self.fragments.get_key_value(name) {
            let total = uses.entry(defined.as_str()).or_insert(0);
            *total = total.saturating_add(count);
        }
    }
}

/// GraphQL request body format.
#[derive(Debug, Clone, Deserialize)]
struct GraphQLRequestBody {
    query: Option<String>,
    #[serde(rename = "operationName")]
    operation_name: Option<String>,
    variables: Option<Value>,
    extensions: Option<Value>,
}

/// Parse a GraphQL request from raw body bytes.
///
/// Handles both single requests and batch requests (JSON array).
pub fn parse_request(body: &[u8]) -> Result<Vec<ParsedRequest>, Violation> {
    // Try to parse as JSON
    let json: Value = serde_json::from_slice(body)
        .map_err(|e| Violation::invalid_request(&format!("Invalid JSON: {}", e)))?;

    // Check if it's a batch request (array)
    if let Some(array) = json.as_array() {
        let mut requests = Vec::with_capacity(array.len());
        for (i, item) in array.iter().enumerate() {
            let req = parse_single_request(item).map_err(|mut v| {
                v.message = format!("Batch item {}: {}", i, v.message);
                v
            })?;
            requests.push(ParsedRequest {
                is_batch: true,
                batch_count: array.len(),
                ..req
            });
        }
        Ok(requests)
    } else {
        // Single request
        let req = parse_single_request(&json)?;
        Ok(vec![req])
    }
}

/// Parse a single GraphQL request from a JSON value.
fn parse_single_request(json: &Value) -> Result<ParsedRequest, Violation> {
    let body: GraphQLRequestBody = serde_json::from_value(json.clone()).map_err(|e| {
        Violation::invalid_request(&format!("Invalid GraphQL request format: {}", e))
    })?;

    // A request without `query` is only meaningful as a hash-only persisted
    // query; anything else is malformed.
    if body.query.is_none() && get_apq_hash(&body.extensions).is_none() {
        return Err(Violation::invalid_request(
            "Missing 'query' field in GraphQL request",
        ));
    }

    Ok(ParsedRequest {
        query: body.query,
        operation_name: body.operation_name,
        variables: body.variables,
        extensions: body.extensions,
        is_batch: false,
        batch_count: 1,
    })
}

/// Parse a GraphQL query string into a document.
pub fn parse_query(query: &str) -> Result<ParsedDocument, Violation> {
    let parser = Parser::new(query);
    let cst = parser.parse();

    // Check for parse errors
    if cst.errors().len() > 0 {
        let errors: Vec<String> = cst.errors().map(|e| e.message().to_string()).collect();
        return Err(Violation::parse_error(&errors.join("; ")));
    }

    let document = cst.document();

    // Extract fragments
    let fragments = extract_fragments(&document);
    let fragment_order = order_fragments(&fragments).map_err(|cycle| {
        Violation::invalid_request(&format!(
            "Fragments must not form cycles: {}",
            describe_cycle(&cycle)
        ))
    })?;

    // Calculate query hash
    let query_hash = calculate_query_hash(query);

    Ok(ParsedDocument {
        document,
        fragments,
        fragment_order,
        query_hash,
    })
}

/// Parse a query without rejecting fragment cycles, listing the fragments in
/// name order. `parse_query` never returns such a document; tests use this to
/// check that analysis of one still ends.
#[cfg(test)]
pub(crate) fn parse_query_unchecked(query: &str) -> ParsedDocument {
    let document = Parser::new(query).parse().document();
    let fragments = extract_fragments(&document);
    let mut fragment_order: Vec<String> = fragments.keys().cloned().collect();
    fragment_order.sort();
    ParsedDocument {
        document,
        fragments,
        fragment_order,
        query_hash: calculate_query_hash(query),
    }
}

/// Extract fragment definitions from a document.
fn extract_fragments(document: &cst::Document) -> HashMap<String, FragmentInfo> {
    let mut fragments = HashMap::new();

    for definition in document.definitions() {
        if let cst::Definition::FragmentDefinition(fragment) = definition {
            if let Some(name) = fragment.fragment_name() {
                if let Some(name_token) = name.name() {
                    let frag_name = name_token.text().to_string();
                    let type_condition = fragment
                        .type_condition()
                        .and_then(|tc| tc.named_type())
                        .and_then(|nt| nt.name())
                        .map(|n| n.text().to_string())
                        .unwrap_or_default();

                    let selection_set = fragment.selection_set();
                    let mut spreads = Vec::new();
                    if let Some(ss) = &selection_set {
                        collect_spreads(ss, &mut spreads);
                    }

                    fragments.insert(
                        frag_name.clone(),
                        FragmentInfo {
                            name: frag_name,
                            type_condition,
                            selection_set,
                            spreads,
                        },
                    );
                }
            }
        }
    }

    fragments
}

/// The name of the fragment a spread refers to.
pub(crate) fn spread_name(spread: &cst::FragmentSpread) -> Option<String> {
    spread.fragment_name()?.name().map(|n| n.text().to_string())
}

/// Append the fragments spread in a selection set, nested fields and inline
/// fragments included, one entry per spread.
fn collect_spreads(selection_set: &cst::SelectionSet, spreads: &mut Vec<String>) {
    for selection in selection_set.selections() {
        match selection {
            cst::Selection::Field(field) => {
                if let Some(nested) = field.selection_set() {
                    collect_spreads(&nested, spreads);
                }
            }
            cst::Selection::FragmentSpread(spread) => spreads.extend(spread_name(&spread)),
            cst::Selection::InlineFragment(inline) => {
                if let Some(nested) = inline.selection_set() {
                    collect_spreads(&nested, spreads);
                }
            }
        }
    }
}

/// Order fragment names so that each comes after the fragments it spreads.
///
/// Spreads of fragments that are not defined are ignored. The order is the
/// same for the same document. If fragments spread each other in a cycle, the
/// error holds one such cycle, ending with the name it starts with.
fn order_fragments(fragments: &HashMap<String, FragmentInfo>) -> Result<Vec<String>, Vec<String>> {
    let mut names: Vec<&str> = fragments.keys().map(String::as_str).collect();
    names.sort_unstable();

    // How many fragments each one still waits for, and who waits for it.
    let mut waiting_for: HashMap<&str, usize> = HashMap::with_capacity(names.len());
    let mut waiting: HashMap<&str, Vec<&str>> = HashMap::new();
    for &name in &names {
        let mut spread: Vec<&str> = fragments[name]
            .spreads
            .iter()
            .filter_map(|s| fragments.get_key_value(s.as_str()))
            .map(|(defined, _)| defined.as_str())
            .collect();
        spread.sort_unstable();
        spread.dedup();
        waiting_for.insert(name, spread.len());
        for dependency in spread {
            waiting.entry(dependency).or_default().push(name);
        }
    }

    let mut ready: VecDeque<&str> = names
        .iter()
        .copied()
        .filter(|name| waiting_for[name] == 0)
        .collect();
    let mut order = Vec::with_capacity(names.len());
    while let Some(name) = ready.pop_front() {
        order.push(name.to_string());
        for &dependent in waiting.get(name).into_iter().flatten() {
            if let Some(count) = waiting_for.get_mut(dependent) {
                *count -= 1;
                if *count == 0 {
                    ready.push_back(dependent);
                }
            }
        }
    }

    if order.len() == names.len() {
        return Ok(order);
    }

    // Some fragments never became ready. Each of them waits for a fragment
    // that is itself left, so following those spreads reaches a name twice.
    let placed: HashSet<&str> = order.iter().map(String::as_str).collect();
    let left_out = |names: &[&str]| -> Vec<String> {
        names
            .iter()
            .filter(|name| !placed.contains(**name))
            .map(|name| name.to_string())
            .collect()
    };
    let Some(&start) = names.iter().find(|name| !placed.contains(**name)) else {
        // Not reachable: fewer names were ordered than there are names. Refuse
        // the document rather than return an order that leaves fragments out.
        debug_assert!(false, "all fragments were ordered");
        return Err(left_out(&names));
    };
    let mut path = vec![start];
    let mut position = HashMap::from([(start, 0)]);
    let mut current = start;
    loop {
        let next = fragments.get(current).and_then(|fragment| {
            fragment
                .spreads
                .iter()
                .map(String::as_str)
                .find(|spread| fragments.contains_key(*spread) && !placed.contains(spread))
        });
        let Some(next) = next else {
            // Not reachable: a fragment that was not ordered spreads another
            // that was not ordered. Refuse the document all the same.
            debug_assert!(false, "a fragment left out of the order waits for another");
            return Err(left_out(&names));
        };
        if let Some(&first) = position.get(next) {
            let mut cycle: Vec<String> = path[first..].iter().map(|n| n.to_string()).collect();
            cycle.push(next.to_string());
            return Err(cycle);
        }
        position.insert(next, path.len());
        path.push(next);
        current = next;
    }
}

/// Write a cycle of fragment names as `A -> B -> A`, naming at most the first
/// few fragments of a long cycle and at most about 200 bytes of text.
fn describe_cycle(cycle: &[String]) -> String {
    const SHOWN: usize = 8;
    const MAX_BYTES: usize = 200;
    let mut text = cycle
        .iter()
        .take(SHOWN)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" -> ");
    if text.len() > MAX_BYTES {
        let mut end = MAX_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("...");
    } else if cycle.len() > SHOWN {
        text.push_str(" -> ...");
    }
    text
}

/// Calculate SHA-256 hash of a query string.
pub fn calculate_query_hash(query: &str) -> String {
    // Normalize by trimming whitespace
    let normalized = query.trim();
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hex::encode(hasher.finalize())
}

/// Get the APQ (Automatic Persisted Queries) hash from extensions.
pub fn get_apq_hash(extensions: &Option<Value>) -> Option<String> {
    extensions
        .as_ref()?
        .get("persistedQuery")?
        .get("sha256Hash")?
        .as_str()
        .map(String::from)
}

/// Information about a field in the query.
#[derive(Debug, Clone)]
pub struct FieldInfo {
    /// Field name (without alias)
    pub name: String,
    /// Alias (if any)
    pub alias: Option<String>,
    /// Parent type (if known)
    pub parent_type: Option<String>,
    /// Arguments
    pub arguments: HashMap<String, Value>,
}

/// Extract the fields of a selection set recursively, including those in
/// nested fields and inline fragments.
///
/// Fragment spreads are not followed. The fields of a fragment come from
/// calling this on its selection set, with its type condition as the parent
/// type; `ParsedDocument::fragment_uses` says how often it is spread.
pub fn extract_fields(
    selection_set: &cst::SelectionSet,
    parent_type: Option<&str>,
) -> Vec<FieldInfo> {
    let mut fields = Vec::new();

    for selection in selection_set.selections() {
        match selection {
            cst::Selection::Field(field) => {
                let name = field
                    .name()
                    .map(|n| n.text().to_string())
                    .unwrap_or_default();
                let alias = field
                    .alias()
                    .and_then(|a| a.name())
                    .map(|n| n.text().to_string());

                // Extract arguments
                let mut arguments = HashMap::new();
                if let Some(args) = field.arguments() {
                    for arg in args.arguments() {
                        if let Some(arg_name) = arg.name() {
                            let arg_value = arg
                                .value()
                                .map(|v| value_to_json(&v))
                                .unwrap_or(Value::Null);
                            arguments.insert(arg_name.text().to_string(), arg_value);
                        }
                    }
                }

                fields.push(FieldInfo {
                    name: name.clone(),
                    alias,
                    parent_type: parent_type.map(String::from),
                    arguments,
                });

                // Recurse into nested selection set
                if let Some(nested_ss) = field.selection_set() {
                    // For nested fields, we don't know the type without schema
                    fields.extend(extract_fields(&nested_ss, None));
                }
            }
            // The fields of a fragment are extracted from the fragment itself
            cst::Selection::FragmentSpread(_) => {}
            cst::Selection::InlineFragment(inline) => {
                let type_cond = inline
                    .type_condition()
                    .and_then(|tc| tc.named_type())
                    .and_then(|nt| nt.name())
                    .map(|n| n.text().to_string());

                if let Some(ss) = inline.selection_set() {
                    fields.extend(extract_fields(&ss, type_cond.as_deref()));
                }
            }
        }
    }

    fields
}

/// Convert a CST value to JSON.
fn value_to_json(value: &cst::Value) -> Value {
    match value {
        cst::Value::IntValue(v) => v
            .int_token()
            .and_then(|t| t.text().parse::<i64>().ok())
            .map(Value::from)
            .unwrap_or(Value::Null),
        cst::Value::FloatValue(v) => v
            .float_token()
            .and_then(|t| t.text().parse::<f64>().ok())
            .map(Value::from)
            .unwrap_or(Value::Null),
        cst::Value::StringValue(v) => {
            let text = v.syntax().text().to_string();
            // Remove quotes
            let stripped = text.trim_matches('"').trim_matches('\'');
            Value::String(stripped.to_string())
        }
        cst::Value::BooleanValue(v) => v
            .true_token()
            .map(|_| Value::Bool(true))
            .or_else(|| v.false_token().map(|_| Value::Bool(false)))
            .unwrap_or(Value::Null),
        cst::Value::NullValue(_) => Value::Null,
        cst::Value::EnumValue(v) => v
            .name()
            .map(|n| Value::String(n.text().to_string()))
            .unwrap_or(Value::Null),
        cst::Value::ListValue(v) => {
            let items: Vec<Value> = v.values().map(|val| value_to_json(&val)).collect();
            Value::Array(items)
        }
        cst::Value::ObjectValue(v) => {
            let mut map = serde_json::Map::new();
            for field in v.object_fields() {
                if let Some(name) = field.name() {
                    let key = name.text().to_string();
                    let val = field
                        .value()
                        .map(|v| value_to_json(&v))
                        .unwrap_or(Value::Null);
                    map.insert(key, val);
                }
            }
            Value::Object(map)
        }
        cst::Value::Variable(v) => v
            .name()
            .map(|n| Value::String(format!("${}", n.text())))
            .unwrap_or(Value::Null),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_query() {
        let query = "{ users { id name } }";
        let result = parse_query(query);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_query_with_variables() {
        let query = r#"
            query GetUser($id: ID!) {
                user(id: $id) {
                    id
                    name
                    email
                }
            }
        "#;
        let result = parse_query(query);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_invalid_query() {
        let query = "{ users { id name ";
        let result = parse_query(query);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, crate::error::ViolationCode::ParseError);
    }

    #[test]
    fn test_parse_request() {
        let body = br#"{"query": "{ users { id } }"}"#;
        let result = parse_request(body);
        assert!(result.is_ok());
        let requests = result.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(!requests[0].is_batch);
    }

    #[test]
    fn test_parse_batch_request() {
        let body = br#"[
            {"query": "{ users { id } }"},
            {"query": "{ posts { id } }"}
        ]"#;
        let result = parse_request(body);
        assert!(result.is_ok());
        let requests = result.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].is_batch);
        assert_eq!(requests[0].batch_count, 2);
    }

    #[test]
    fn test_parse_request_missing_query() {
        let result = parse_request(br#"{"variables": {}}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hash_only_request() {
        let body = br#"{"extensions": {"persistedQuery": {"version": 1, "sha256Hash": "abc"}}}"#;
        let requests = parse_request(body).unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].query.is_none());
    }

    #[test]
    fn test_query_hash() {
        let query1 = "{ users { id } }";
        let query2 = "  { users { id } }  ";
        // Hashes should be the same after normalization
        assert_eq!(calculate_query_hash(query1), calculate_query_hash(query2));
    }

    #[test]
    fn test_get_apq_hash() {
        let extensions = Some(serde_json::json!({
            "persistedQuery": {
                "version": 1,
                "sha256Hash": "abc123"
            }
        }));
        assert_eq!(get_apq_hash(&extensions), Some("abc123".to_string()));
    }

    #[test]
    fn test_get_apq_hash_missing() {
        let extensions: Option<Value> = None;
        assert_eq!(get_apq_hash(&extensions), None);
    }

    #[test]
    fn test_fragment_cycle_is_rejected() {
        let err = parse_query(
            "{ ...Alpha } fragment Alpha on Query { ...Beta } fragment Beta on Query { ...Alpha }",
        )
        .unwrap_err();

        assert_eq!(err.code, crate::error::ViolationCode::InvalidRequest);
        assert!(err.message.contains("Alpha") && err.message.contains("Beta"));
    }

    #[test]
    fn test_fragment_spreading_itself_is_rejected() {
        let err =
            parse_query("{ ...Alpha } fragment Alpha on Query { x { ...Alpha } }").unwrap_err();

        assert_eq!(err.code, crate::error::ViolationCode::InvalidRequest);
        assert!(err.message.contains("Alpha"));
    }

    #[test]
    fn test_cycle_through_inline_fragment_is_rejected() {
        let err = parse_query(
            "{ a } \
             fragment Alpha on Query { x { ... on Query { ...Beta } } } \
             fragment Beta on Query { ...Gamma } \
             fragment Gamma on Query { ...Alpha }",
        )
        .unwrap_err();

        assert_eq!(err.code, crate::error::ViolationCode::InvalidRequest);
        for name in ["Alpha", "Beta", "Gamma"] {
            assert!(err.message.contains(name), "{}", err.message);
        }
    }

    #[test]
    fn test_cycle_in_unused_fragments_is_rejected() {
        assert!(
            parse_query("{ a } fragment A on Query { ...B } fragment B on Query { ...A }").is_err()
        );
    }

    #[test]
    fn test_fragments_spreading_a_shared_fragment_are_accepted() {
        let result = parse_query(
            "{ ...A ...B } \
             fragment A on Query { ...C } \
             fragment B on Query { ...C } \
             fragment C on Query { x }",
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_spread_of_undefined_fragment_is_accepted() {
        assert!(parse_query("{ ...Missing }").is_ok());
    }

    #[test]
    fn test_duplicate_fragment_names_keep_the_last_definition() {
        let doc = parse_query("{ ...F } fragment F on A { x } fragment F on B { y }").unwrap();

        assert_eq!(doc.fragments.len(), 1);
        assert_eq!(doc.fragments["F"].type_condition, "B");
    }

    fn operation_selection_sets(doc: &ParsedDocument) -> Vec<cst::SelectionSet> {
        doc.document
            .definitions()
            .filter_map(|definition| match definition {
                cst::Definition::OperationDefinition(op) => op.selection_set(),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_fragment_cycle_names_the_fragments_in_it() {
        let err = parse_query(
            "{ ...Entry } \
             fragment Entry on Query { ...Alpha } \
             fragment Alpha on Query { ...Beta } \
             fragment Beta on Query { ...Alpha }",
        )
        .unwrap_err();

        assert!(
            err.message.ends_with("Alpha -> Beta -> Alpha"),
            "{}",
            err.message
        );
        assert!(!err.message.contains("Entry"), "{}", err.message);
    }

    #[test]
    fn test_long_fragment_cycle_is_rejected_with_a_short_message() {
        let count = 5_000;
        let mut query = String::from("{ ...F0 }");
        for i in 0..count {
            query.push_str(&format!(
                " fragment F{i} on Query {{ ...F{} }}",
                (i + 1) % count
            ));
        }
        let err = parse_query(&query).unwrap_err();

        assert_eq!(err.code, crate::error::ViolationCode::InvalidRequest);
        assert!(err.message.ends_with(" -> ..."), "{}", err.message);
        assert!(err.message.len() < 200, "{}", err.message);
    }

    #[test]
    fn test_fragments_are_listed_after_the_fragments_they_spread() {
        let query = "{ ...A } \
                     fragment A on Query { x { ...B } ...C } \
                     fragment B on Query { ... on Query { ...C } } \
                     fragment C on Query { ...Missing y } \
                     fragment Unused on Query { ...A }";
        let doc = parse_query(query).unwrap();

        assert_eq!(doc.fragment_order, ["C", "B", "A", "Unused"]);
        // The same document gives the same order.
        assert_eq!(
            parse_query(query).unwrap().fragment_order,
            doc.fragment_order
        );
    }

    #[test]
    fn test_fragment_uses_count_every_spread() {
        let doc = parse_query(
            "{ ...A ...A } \
             fragment A on Query { ...B ...B x { ...C } } \
             fragment B on Query { ...C } \
             fragment C on Query { y } \
             fragment Unused on Query { ...C }",
        )
        .unwrap();
        let uses = doc.fragment_uses(&operation_selection_sets(&doc));

        // A is spread twice, B twice by each A, C once by each A and by each B.
        assert_eq!(uses.get("A"), Some(&2));
        assert_eq!(uses.get("B"), Some(&4));
        assert_eq!(uses.get("C"), Some(&6));
        assert_eq!(uses.get("Unused"), None);
    }

    #[test]
    fn test_fragment_uses_saturate() {
        let query = crate::analyzer::doubling_fragment_chain(70, "x");
        let doc = parse_query(&query).unwrap();
        let uses = doc.fragment_uses(&operation_selection_sets(&doc));

        // F0 is spread once, F1 twice, F2 four times, and so on.
        assert_eq!(uses.get("F63"), Some(&(1 << 63)));
        assert_eq!(uses.get("F64"), Some(&u64::MAX));
        assert_eq!(uses.get("F69"), Some(&u64::MAX));
    }

    #[test]
    fn test_fold_fragments_evaluates_each_fragment_once_after_its_spreads() {
        let query = crate::analyzer::doubling_fragment_chain(50, "x");
        let doc = parse_query(&query).unwrap();
        let mut evaluations = 0;
        let depths = doc.fold_fragments(|fragment, done| {
            evaluations += 1;
            fragment
                .spreads
                .first()
                .map_or(0, |next| done[next.as_str()] + 1)
        });

        assert_eq!(evaluations, 50);
        assert_eq!(depths["F0"], 49);
    }

    #[test]
    fn test_extract_fields_does_not_follow_spreads() {
        let doc =
            parse_query("{ a { ...F } b ... on Query { c } } fragment F on User { d }").unwrap();
        let operations = operation_selection_sets(&doc);

        let fields = extract_fields(&operations[0], Some("Query"));
        let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["a", "b", "c"]);
        assert_eq!(fields[2].parent_type.as_deref(), Some("Query"));

        let fragment = &doc.fragments["F"];
        let fields = extract_fields(fragment.selection_set.as_ref().unwrap(), Some("User"));
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "d");
    }

    #[test]
    fn test_fragment_cycle_message_is_cut_for_long_names() {
        let long = "N".repeat(1_000);
        let query = format!(
            "{{ ...{long}a }} fragment {long}a on Query {{ ...{long}b }} fragment {long}b on Query {{ ...{long}a }}"
        );
        let err = parse_query(&query).unwrap_err();

        assert_eq!(err.code, crate::error::ViolationCode::InvalidRequest);
        assert!(err.message.len() < 300, "{} bytes", err.message.len());
        assert!(err.message.ends_with("..."), "{}", err.message);
    }

    #[test]
    fn test_cycle_description_is_cut_at_a_character_boundary() {
        // 3 bytes per character: byte 200 is inside a character.
        let cycle = vec!["\u{20ac}".repeat(100), "\u{20ac}".repeat(100)];
        let text = describe_cycle(&cycle);

        assert!(text.len() <= 203, "{} bytes", text.len());
        assert!(text.ends_with("\u{20ac}..."), "{text}");
    }

    #[test]
    fn test_fragment_uses_add_up_over_operations() {
        let doc = parse_query(
            "query One { ...F } \
             query Two { ...F ...G } \
             fragment F on Query { ...G } \
             fragment G on Query { x }",
        )
        .unwrap();
        let uses = doc.fragment_uses(&operation_selection_sets(&doc));

        assert_eq!(uses.get("F"), Some(&2));
        // Once by `Two`, and once by each of the two spreads of `F`.
        assert_eq!(uses.get("G"), Some(&3));
    }
}
