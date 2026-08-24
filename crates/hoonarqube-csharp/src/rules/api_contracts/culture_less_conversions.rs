use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4056 — culture-less `ToString`/`Parse` calls pick the
/// machine's locale instead of a stated one.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let arguments = invocation_arguments(call);
        let flagged = match callee_name(call, source) {
            Some("ToString") => arguments.is_empty(),
            Some("Parse") => arguments.len() == 1,
            _ => false,
        };
        if flagged {
            issues.push(issue(
                language,
                "S4056",
                "Call the overload that takes an 'IFormatProvider'.",
                range_of(call),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4056_argument_count_boundaries_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = value.ToString(\"N2\");\n        number = int.Parse();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4056").is_empty());
    }

    #[test]
    fn s4056_flags_inner_conversion_in_a_chain_once() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = value.ToString().Trim();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4056").len(), 1);
    }
}
