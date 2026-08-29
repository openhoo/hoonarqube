use super::support::type_parameter_list_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, parameters_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4018 — every method type parameter must appear in the
/// parameter list.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let Some((list, _)) = type_parameter_list_of(method) else {
            continue;
        };
        let used: std::collections::HashSet<&str> = parameters_of(method)
            .into_iter()
            .filter_map(|parameter| parameter.child_by_field_name("type"))
            .flat_map(|parameter_type| collect_kinds(parameter_type, &["identifier"]))
            .map(|identifier| node_text(identifier, source))
            .collect();
        let mut list_cursor = list.walk();
        let has_unused = list
            .children(&mut list_cursor)
            .filter(|child| child.kind() == "type_parameter")
            .filter_map(|parameter| parameter.child_by_field_name("name"))
            .any(|name| !used.contains(node_text(name, source)));
        if has_unused {
            let Some(name) = method.child_by_field_name("name") else {
                continue;
            };
            issues.push(issue(
                language,
                "S4018",
                "Refactor this method to use all type parameters in the parameter list to enable type inference.",
                range_of(name, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4018_does_not_treat_parameter_name_as_type_parameter_use() {
        let report = analyze_default("class C\n{\n    public void M<T>(int T) { }\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S4018").len(), 1);
    }
}
