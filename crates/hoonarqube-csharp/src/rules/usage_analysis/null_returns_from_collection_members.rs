use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of,
    simple_name,
};
use crate::rules::expressions::{enclosing_type, first_named_child};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1168 — collection-returning methods return empty, not null.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method)
            || has_modifier(&modifiers_of(method, source), "override")
            || !method
                .child_by_field_name("returns")
                .is_some_and(|returns| is_collection_return(returns, source))
            || enclosing_type(method)
                .is_some_and(|owner| !base_simple_names(owner, source).is_empty())
        {
            continue;
        }
        let body = body_of(method);
        let mut flagged = false;
        if let Some(body) = body {
            for return_statement in collect_kinds(body, &["return_statement"]) {
                if is_error_tainted(return_statement)
                    || first_named_child(return_statement)
                        .is_none_or(|expression| expression.kind() != "null_literal")
                {
                    continue;
                }
                issues.push(issue(
                    language,
                    "S1168",
                    "Return an empty collection instead of null.",
                    range_of(return_statement, source),
                ));
                flagged = true;
            }
        }
        if body.is_some() || flagged {
            continue;
        }
        for arrow in collect_kinds(method, &["arrow_expression_clause"]) {
            if !is_error_tainted(arrow)
                && first_named_child(arrow)
                    .is_some_and(|expression| expression.kind() == "null_literal")
            {
                issues.push(issue(
                    language,
                    "S1168",
                    "Return an empty collection instead of null.",
                    range_of(arrow, source),
                ));
            }
        }
    }
    issues
}

/// Collection type heads whose members should yield empty values, not `null`.
const COLLECTION_TYPE_NAMES: [&str; 16] = [
    "List",
    "Dictionary",
    "HashSet",
    "SortedSet",
    "SortedDictionary",
    "IEnumerable",
    "ICollection",
    "IList",
    "IDictionary",
    "IReadOnlyCollection",
    "IReadOnlyList",
    "IReadOnlyDictionary",
    "Queue",
    "Stack",
    "LinkedList",
    "ReadOnlyCollection",
];

/// Whether a return-type node denotes an array or collection.
fn is_collection_return(returns: Node<'_>, source: &str) -> bool {
    let text = node_text(returns, source).trim();
    text.ends_with("[]") || COLLECTION_TYPE_NAMES.contains(&simple_name(text))
}
