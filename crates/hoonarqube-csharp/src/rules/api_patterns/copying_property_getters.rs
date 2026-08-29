use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::dataflow::collect_owned_kinds;
use crate::rules::expressions::{callee_name, invocation_function};
use crate::rules::structure::{accessor_keyword, name_anchor};
use hoonarqube_ir::Issue;
use std::collections::HashSet;
use tree_sitter::Node;

/// csharpsquid:S2365 — getters that copy their collection allocate a
/// fresh collection per read and mislead callers into thinking they own it.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) {
            continue;
        }
        let property_name = node_text(name_anchor(property), source);
        let mut seen = HashSet::new();
        let mut regions = direct_arrow_bodies(property);
        regions.extend(direct_getter_bodies(property, source));
        for region in regions {
            for call in collect_owned_kinds(region, &["invocation_expression"])
                .into_iter()
                .filter(|call| is_returned_from_property(*call, property))
                .filter(|call| canonical(callee_name(*call, source).unwrap_or("")) == "ToList")
            {
                if !seen.insert(call.id()) {
                    continue;
                }
                issues.push(issue(
                    language,
                    "S2365",
                    format!(
                        "Refactor '{property_name}' into a method, properties should not copy collections."
                    ),
                    range_of(invocation_function(call).unwrap_or(call), source),
                ));
            }
        }
    }
    issues
}

fn canonical(name: &str) -> &str {
    name.strip_prefix('@').unwrap_or(name)
}

fn direct_arrow_bodies(property: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = property.walk();
    property
        .children(&mut cursor)
        .filter(|child| child.kind() == "arrow_expression_clause")
        .collect()
}

fn direct_getter_bodies<'t>(property: Node<'t>, source: &str) -> Vec<Node<'t>> {
    collect_kinds(property, &["accessor_declaration"])
        .into_iter()
        .filter(|accessor| {
            ancestors_of(*accessor)
                .find(|ancestor| ancestor.kind() == "property_declaration")
                .is_some_and(|owner| owner.id() == property.id())
        })
        .filter(|accessor| accessor_keyword(*accessor, source) == "get")
        .collect()
}

fn is_returned_from_property(call: Node<'_>, property: Node<'_>) -> bool {
    for ancestor in ancestors_of(call) {
        if ancestor.id() == property.id() {
            break;
        }
        if matches!(
            ancestor.kind(),
            "return_statement" | "arrow_expression_clause"
        ) {
            return true;
        }
        if matches!(
            ancestor.kind(),
            "lambda_expression" | "anonymous_method_expression" | "local_function_statement"
        ) {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2365_flags_list_copies_but_not_array_snapshots() {
        let report = analyze_default(
            "class C { IEnumerable<int> items; public List<int> Items => items.ToList(); public int[] Values => items.ToArray(); }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2365").len(), 1);
    }

    #[test]
    fn s2365_ignores_incidental_and_nested_callable_copies() {
        let report = analyze_default(
            "class C { IEnumerable<int> items; public IEnumerable<int> Items { get { Log(items.ToList()); Func<List<int>> later = () => items.ToList(); return items; } } }\n",
        );
        assert!(with_key(&report, "csharpsquid:S2365").is_empty());
    }
}
