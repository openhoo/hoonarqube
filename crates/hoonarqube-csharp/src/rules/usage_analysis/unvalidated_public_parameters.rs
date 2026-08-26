use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, parameters_of, range_of,
};
use crate::rules::expressions::{
    callee_name, comparisons, expression_name, first_named_child, invocation_arguments,
    invocation_function, operator_of,
};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3900 — public methods validate annotated nullable
/// reference parameters before using them. Restricted to `?`-annotated
/// parameters so single-file analysis stays sound.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) || !has_modifier(&modifiers_of(method, source), "public") {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        for parameter in parameters_of(method) {
            if is_error_tainted(parameter)
                || modifiers_of(parameter, source)
                    .iter()
                    .any(|modifier| matches!(*modifier, "this"))
            {
                continue;
            }
            let Some(type_node) = parameter.child_by_field_name("type") else {
                continue;
            };
            if !node_text(type_node, source).trim().ends_with('?') {
                continue;
            }
            let Some(name_node) = parameter.child_by_field_name("name") else {
                continue;
            };
            let name = node_text(name_node, source);
            if null_guards_parameter(body, name, source) {
                continue;
            }
            let dereference = collect_kinds(body, &["identifier"])
                .into_iter()
                .find(|identifier| {
                    !is_error_tainted(*identifier)
                        && node_text(*identifier, source) == name
                        && identifier.parent().is_some_and(|parent| {
                            matches!(
                                parent.kind(),
                                "member_access_expression"
                                    | "element_access_expression"
                                    | "element_binding_expression"
                            ) && first_named_child(parent)
                                .is_some_and(|base| base.id() == identifier.id())
                                || (parent.kind() == "invocation_expression"
                                    && invocation_function(parent) == Some(*identifier))
                        })
                });
            if let Some(dereference) = dereference {
                issues.push(issue(
                    language,
                    "S3900",
                    format!("Validate parameter '{name}' against null before using it."),
                    range_of(dereference, source),
                ));
            }
        }
    }
    issues
}

/// Whether the body guards `parameter` against null explicitly.
fn null_guards_parameter(body: Node<'_>, parameter: &str, source: &str) -> bool {
    let comparison_guard = comparisons(body).iter().any(|(expression, left, right)| {
        matches!(operator_of(*expression), Some("==" | "!="))
            && [left, right]
                .iter()
                .any(|side| side.kind() == "identifier" && node_text(**side, source) == parameter)
            && [left, right]
                .iter()
                .any(|side| side.kind() == "null_literal")
    });
    comparison_guard
        || node_text(body, source).contains(&format!("{parameter} is null"))
        || node_text(body, source).contains(&format!("{parameter} is not null"))
        || collect_kinds(body, &["invocation_expression"])
            .iter()
            .any(|invocation| {
                callee_name(*invocation, source)
                    .is_some_and(|callee| callee.ends_with("ThrowIfNull"))
                    && invocation_arguments(*invocation)
                        .iter()
                        .any(|argument| expression_name(*argument, source) == Some(parameter))
            })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3900_minimal_class_produces_no_findings() {
        let report = analyze_default("class A\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S3900").is_empty());
    }

    #[test]
    fn s3900_flags_each_dereference_shape_at_its_own_line() {
        let report = analyze_default(
            "class C\n{\n    public int A(string? t)\n    {\n        return t.Length;\n    }\n\n    public void B(string? d)\n    {\n        d();\n    }\n\n    public char H(string? s)\n    {\n        return s[0];\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3900");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 10);
        assert_eq!(flagged[2].range.start.line, 15);
        assert_eq!(
            flagged[0].message,
            "Validate parameter 't' against null before using it."
        );
    }

    #[test]
    fn s3900_ignores_non_public_and_non_annotated_parameters() {
        let private = analyze_default(
            "class C\n{\n    int A(string? t)\n    {\n        return t.Length;\n    }\n}\n",
        );
        assert!(with_key(&private, "csharpsquid:S3900").is_empty());

        let non_annotated = analyze_default(
            "class C\n{\n    public int A(string t)\n    {\n        return t.Length;\n    }\n}\n",
        );
        assert!(with_key(&non_annotated, "csharpsquid:S3900").is_empty());
    }

    #[test]
    fn s3900_ignores_this_modifiers_on_extension_parameters() {
        let report = analyze_default(
            "class C\n{\n    public void Ext(this string? text)\n    {\n        Log(text.Length);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3900").is_empty());
    }

    #[test]
    fn s3900_accepts_inverted_comparison_guards() {
        let report = analyze_default(
            "class C\n{\n    public int A(string? t)\n    {\n        if (t != null)\n        {\n            return t.Length;\n        }\n        return 0;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3900").is_empty());
    }

    #[test]
    fn s3900_accepts_is_not_null_pattern_guards() {
        let report = analyze_default(
            "class C\n{\n    public int A(string? t)\n    {\n        if (t is not null)\n        {\n            return t.Length;\n        }\n        return -1;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3900").is_empty());
    }
}
