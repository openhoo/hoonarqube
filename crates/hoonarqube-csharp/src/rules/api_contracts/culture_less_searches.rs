use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments, invocation_function};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1449 — searches and comparisons need an explicit culture or
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let count = invocation_arguments(call).len();
        let flagged = matches!(callee_name(call, source), Some("CompareTo") if count == 1)
            || matches!(callee_name(call, source), Some("IndexOf" | "LastIndexOf") if count <= 1);
        if flagged {
            let callee = callee_name(call, source).unwrap_or("operation");
            let name = invocation_function(call)
                .and_then(|function| function.child_by_field_name("name"))
                .unwrap_or(call);
            let message = if callee == "CompareTo" {
                "Use 'CompareOrdinal' or 'Compare' with the locale specified instead of 'CompareTo'."
            } else {
                "Define the locale to be used in this string operation."
            };
            issues.push(issue(language, "S1449", message, range_of(name, source)));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1449_zero_argument_searches_flag_too() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        first = text.IndexOf();\n        last = text.LastIndexOf();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1449").len(), 2);
    }

    #[test]
    fn s1449_two_argument_compareto_stays_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        ordered = text.CompareTo(other, StringComparison.Ordinal);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1449").is_empty());
    }
}
