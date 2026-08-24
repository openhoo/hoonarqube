use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::invocation_targets;
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
        let exits = invocation_targets(
            invocation,
            source,
            Some("Environment"),
            &["Exit", "FailFast"],
        ) || invocation_targets(invocation, source, Some("Application"), &["Exit"]);
        if exits {
            issues.push(issue(
                language,
                "S1147",
                "Remove this call to an exit method.",
                range_of(invocation),
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
        assert_eq!(with_key(&report, "csharpsquid:S1147").len(), 2);
    }
}
