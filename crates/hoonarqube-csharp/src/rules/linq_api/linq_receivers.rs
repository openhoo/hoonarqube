use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{
    callee_name, expression_name, invocation_arguments, invocation_receiver,
};
use crate::rules::literals::declarator_initializer;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::symbol_table::nearest_ancestor_of_kinds;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6602/S6603/S6605/S6608/S6609/S6613 — list-like and
/// set-like receivers have dedicated instance members that beat the
/// LINQ extensions. Bound: only receivers resolvable through the local
/// type map; unknown receivers are never flagged.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    // One type map per enclosing type, built on first use.
    let mut cached_scope: Option<(usize, std::collections::HashMap<String, String>)> = None;
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let scope_root = nearest_ancestor_of_kinds(call, &TYPE_DECLARATION_KINDS).unwrap_or(root);
        let scope_id = scope_root.id();
        if cached_scope.as_ref().map(|(id, _)| *id) != Some(scope_id) {
            cached_scope = Some((scope_id, build_local_type_map(scope_root, source)));
        }
        let Some((_, type_map)) = cached_scope.as_ref() else {
            continue;
        };
        let Some(receiver) = invocation_receiver(call) else {
            continue;
        };
        let Some(receiver_type) = mapped_receiver_type(receiver, source, type_map) else {
            continue;
        };
        let callee = callee_name(call, source).unwrap_or("");
        let arguments = invocation_arguments(call);
        let replacement = if LIST_LIKE_TYPES.contains(&receiver_type.as_str()) {
            match (callee, arguments.len()) {
                ("FirstOrDefault", 1..=2) => Some(("Find", "S6602")),
                ("All", 1) => Some(("TrueForAll", "S6603")),
                ("Any", 1) => Some(("Exists", "S6605")),
                ("ElementAt", 1) | ("First" | "Last", 0) => Some(("indexing", "S6608")),
                _ => None,
            }
        } else {
            match (callee, arguments.len()) {
                ("Min", 0)
                    if matches!(
                        receiver_type.as_str(),
                        "SortedSet" | "ImmutableSortedSet" | "HashSet"
                    ) =>
                {
                    Some(("Min property", "S6609"))
                }
                ("Max", 0)
                    if matches!(receiver_type.as_str(), "SortedSet" | "ImmutableSortedSet") =>
                {
                    Some(("Max property", "S6609"))
                }
                ("First" | "Last", 0) if receiver_type == "LinkedList" => {
                    Some(("First/Last property", "S6613"))
                }
                _ => None,
            }
        };
        if let Some((suggestion, rule)) = replacement {
            let message =
                format!("Use '{suggestion}' on this '{receiver_type}' instead of '{callee}'.");
            issues.push(issue(language, rule, message, range_of(call)));
        }
    }
    issues
}

/// Collection types with instance members that beat their LINQ
/// counterparts.
const LIST_LIKE_TYPES: [&str; 4] = ["List", "IList", "IReadOnlyList", "ArrayList"];

/// The inferred type of an expression, if the local type map knows it.
fn mapped_receiver_type(
    expression: Node<'_>,
    source: &str,
    type_map: &std::collections::HashMap<String, String>,
) -> Option<String> {
    match expression.kind() {
        "identifier" => type_map.get(node_text(expression, source)).cloned(),
        "member_access_expression" => expression_name(expression, source).map(str::to_owned),
        _ => None,
    }
}

/// Builds the per-member local type map: declarations whose type is
/// spelled (`List<int> xs`) or inferable from a constructor initializer
/// (`var xs = new List<int>()`).
fn build_local_type_map(body: Node<'_>, source: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for declaration in collect_kinds(body, &["variable_declaration", "field_declaration"]) {
        // `field_declaration` wraps its `variable_declaration`, so fall
        // back to that child when the declaration has no direct type.
        let type_node = declaration.child_by_field_name("type").or_else(|| {
            collect_kinds(declaration, &["variable_declaration"])
                .into_iter()
                .next()
                .and_then(|variable| variable.child_by_field_name("type"))
        });
        let Some(type_node) = type_node else {
            continue;
        };
        let explicit_type = simple_name(node_text(type_node, source));
        for declarator in collect_kinds(declaration, &["variable_declarator"]) {
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            let name_text = node_text(name, source).to_owned();
            if explicit_type != "var" {
                map.insert(name_text, explicit_type.to_owned());
                continue;
            }
            let inferred = declarator_initializer(declarator, name).and_then(|value| {
                value
                    .child_by_field_name("type")
                    .filter(|_| value.kind() == "object_creation_expression")
                    .map(|type_node| simple_name(node_text(type_node, source)).to_owned())
            });
            if let Some(inferred) = inferred {
                map.insert(name_text, inferred);
            }
        }
    }
    for parameter in collect_kinds(body, &["parameter"]) {
        if let (Some(type_node), Some(name)) = (
            parameter.child_by_field_name("type"),
            parameter.child_by_field_name("name"),
        ) {
            map.insert(
                node_text(name, source).to_owned(),
                simple_name(node_text(type_node, source)).to_owned(),
            );
        }
    }
    for property in collect_kinds(body, &["property_declaration"]) {
        if let (Some(type_node), Some(name)) = (
            property.child_by_field_name("type"),
            property.child_by_field_name("name"),
        ) {
            map.insert(
                node_text(name, source).to_owned(),
                simple_name(node_text(type_node, source)).to_owned(),
            );
        }
    }
    map
}
