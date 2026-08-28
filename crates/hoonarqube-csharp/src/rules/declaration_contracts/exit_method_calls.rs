use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::invocation_function;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1147 — killing the process bypasses cleanup and error
/// handling; return or throw instead.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation) {
            continue;
        }
        let Some(function) = invocation_function(invocation) else {
            continue;
        };
        let function_text = node_text(function, source);
        let owner = if function_text.ends_with("Environment.Exit") {
            Some("Environment.Exit")
        } else if function_text.ends_with("Application.Exit") {
            Some("Application.Exit")
        } else {
            None
        };
        if let Some(owner) = owner {
            issues.push(issue(
                language,
                "S1147",
                format!("Remove this call to '{owner}' or ensure it is really required."),
                range_of(
                    function.child_by_field_name("name").unwrap_or(function),
                    source,
                ),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1147_flags_fail_fast_and_application_exit() {
        let report = analyze_default(
            "class C\n{\n    void Bail()\n    {\n        Environment.FailFast(\"fatal\");\n        System.Windows.Forms.Application.Exit();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1147").len(), 1);
    }
}
