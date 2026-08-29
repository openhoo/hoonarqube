use super::support::collect_in_callable;
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
        if !is_eligible_method(method, source) {
            continue;
        }
        if let Some(body) = body_of(method) {
            flag_block_returns(body, source, language, &mut issues);
            continue;
        }
        flag_arrow_returns(method, source, language, &mut issues);
    }
    issues
}

fn is_eligible_method(method: Node<'_>, source: &str) -> bool {
    !is_error_tainted(method)
        && !has_modifier(&modifiers_of(method, source), "override")
        && method
            .child_by_field_name("returns")
            .is_some_and(|returns| is_collection_return(returns, source))
        && enclosing_type(method).is_none_or(|owner| base_simple_names(owner, source).is_empty())
}

fn flag_block_returns(body: Node<'_>, source: &str, language: CsLanguage, issues: &mut Vec<Issue>) {
    for return_statement in collect_in_callable(body, "return_statement") {
        if is_error_tainted(return_statement) {
            continue;
        }
        if let Some(expression) = null_expression(return_statement) {
            push_issue(expression, source, language, issues);
        }
    }
}

fn flag_arrow_returns(
    method: Node<'_>,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<Issue>,
) {
    for arrow in collect_in_callable(method, "arrow_expression_clause") {
        if !is_error_tainted(arrow)
            && let Some(expression) = null_expression(arrow)
        {
            push_issue(expression, source, language, issues);
        }
    }
}

fn null_expression(node: Node<'_>) -> Option<Node<'_>> {
    first_named_child(node).filter(|expression| expression.kind() == "null_literal")
}

fn push_issue(expression: Node<'_>, source: &str, language: CsLanguage, issues: &mut Vec<Issue>) {
    issues.push(issue(
        language,
        "S1168",
        "Return an empty collection instead of null.",
        range_of(expression, source),
    ));
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

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1168_ignores_null_returns_inside_nested_functions() {
        let report = analyze_default(
            "class C\n{\n    System.Collections.Generic.IEnumerable<int> Values()\n    {\n        object Local() => null;\n        System.Func<object> later = () => null;\n        return new int[0];\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1168").is_empty());
    }
}
