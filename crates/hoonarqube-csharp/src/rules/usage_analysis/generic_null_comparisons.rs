use super::support::{enclosing_callable, unconstrained_generic_parameters};
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, node_text, range_of, signature_regions, simple_name,
};
use crate::rules::expressions::{comparisons, operator_of};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2955 — unconstrained generic values mislead `null` checks.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let values = unconstrained_generic_values(root, source);
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        if !matches!(operator_of(expression), Some("==" | "!="))
            || ![left, right]
                .iter()
                .any(|side| side.kind() == "null_literal")
        {
            continue;
        }
        if [left, right].iter().any(|operand| {
            operand.kind() == "identifier"
                && values.iter().any(|value| {
                    value.name == node_text(*operand, source)
                        && value.scope.start_byte() <= operand.start_byte()
                        && value.scope.end_byte() >= operand.end_byte()
                })
        }) {
            issues.push(issue(
                language,
                "S2955",
                "Use a comparison to 'default(T)' instead or add a constraint to 'T' so that it can't be a value type.",
                range_of(
                    if left.kind() == "null_literal" { left } else { right },
                    source,
                ),
            ));
        }
    }
    issues
}

/// Names of parameters and locals typed by an unconstrained generic
/// parameter of their enclosing declaration.
struct GenericValue<'t> {
    name: String,
    scope: Node<'t>,
}

fn unconstrained_generic_values<'t>(root: Node<'t>, source: &str) -> Vec<GenericValue<'t>> {
    let mut declarations = collect_kinds(root, &TYPE_DECLARATION_KINDS);
    declarations.extend(collect_kinds(root, &["method_declaration"]));
    let mut values = Vec::new();
    for declaration in declarations {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(generic_names) = unconstrained_generic_parameters(declaration, source) else {
            continue;
        };
        collect_generic_parameters(declaration, source, &generic_names, &mut values);
        collect_generic_locals(declaration, source, &generic_names, &mut values);
    }
    values
}

fn collect_generic_parameters<'t>(
    declaration: Node<'t>,
    source: &str,
    generic_names: &std::collections::HashSet<String>,
    values: &mut Vec<GenericValue<'t>>,
) {
    for region in signature_regions(declaration) {
        for parameter in collect_kinds(region, &["parameter"]) {
            let Some((type_node, name)) = parameter
                .child_by_field_name("type")
                .zip(parameter.child_by_field_name("name"))
            else {
                continue;
            };
            if generic_names.contains(simple_name(node_text(type_node, source))) {
                values.push(GenericValue {
                    name: node_text(name, source).to_string(),
                    scope: declaration,
                });
            }
        }
    }
}

fn collect_generic_locals<'t>(
    declaration: Node<'t>,
    source: &str,
    generic_names: &std::collections::HashSet<String>,
    values: &mut Vec<GenericValue<'t>>,
) {
    for variable_declaration in collect_kinds(declaration, &["variable_declaration"]) {
        let Some(type_node) = variable_declaration.child_by_field_name("type") else {
            continue;
        };
        if !generic_names.contains(simple_name(node_text(type_node, source))) {
            continue;
        }
        for declarator in collect_kinds(variable_declaration, &["variable_declarator"]) {
            if let Some(name) = declarator.child_by_field_name("name") {
                values.push(GenericValue {
                    name: node_text(name, source).to_string(),
                    scope: enclosing_callable(declarator).unwrap_or(declaration),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2955_ignores_non_generic_null_comparison() {
        let report = analyze_default(
            "class C\n{\n    void M(int x)\n    {\n        if (x == null)\n        {\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2955").is_empty());
    }

    #[test]
    fn s2955_flags_not_equal_operator() {
        let report = analyze_default(
            "class C\n{\n    bool Ne<T>(T value)\n    {\n        return value != null;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2955");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s2955_flags_reversed_null_operand() {
        let report = analyze_default(
            "class C\n{\n    bool Reversed<T>(T value)\n    {\n        return null == value;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2955");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s2955_ignores_double_null_comparison() {
        let report = analyze_default(
            "class C\n{\n    bool Both()\n    {\n        return null == null;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2955").is_empty());
    }

    #[test]
    fn s2955_reports_each_unconstrained_comparison_distinctly() {
        let report = analyze_default(
            "class C\n{\n    bool Two<T>(T first, T second)\n    {\n        if (first == null)\n        {\n            return true;\n        }\n\n        return second != null;\n    }\n}\n",
        );
        let mut lines: Vec<u32> = with_key(&report, "csharpsquid:S2955")
            .iter()
            .map(|issue| issue.range.start.line)
            .collect();
        lines.sort_unstable();
        assert_eq!(lines, vec![5, 10]);
    }

    #[test]
    fn s2955_tracks_generic_typed_locals() {
        let report = analyze_default(
            "class C\n{\n    void M<T>(T parameter)\n    {\n        T local = default(T);\n        if (local == null)\n        {\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2955");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }

    #[test]
    fn s2955_does_not_leak_generic_names_into_other_methods() {
        let report = analyze_default(
            "class C\n{\n    bool Generic<T>(T value) => value == null;\n\n    bool Concrete(string value) => value == null;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2955");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s2955_does_not_leak_generic_names_between_types() {
        let report = analyze_default(
            "class A\n{\n    bool Generic<T>(T candidate) => candidate != null;\n}\n\nclass B\n{\n    bool Concrete(object candidate) => candidate != null;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2955");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }
}
