use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, first_named_child, invocation_function};
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["expression_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter_map(|statement| first_named_child(statement))
        .filter(|expression| {
            expression.kind() == "invocation_expression" && is_pure_static_call(*expression, source)
        })
        .map(|expression| {
            issue(
                language,
                "S2201",
                "The result of this side-effect-free call is unused; remove the call or use its value.",
                range_of(expression, source),
            )
        })
        .collect()
}

/// csharpsquid:S2201 — discarded results of side-effect-free static calls.
/// Subset: a curated pure-API owner/method table (`Math`, `string`,
/// `DateTime`) called as a bare statement; user-declared pure functions and
/// discard-pattern assignments stay uncovered.
const PURE_STATIC_APIS: &[(&str, &[&str])] = &[
    (
        "Math",
        &[
            "Abs",
            "BigMul",
            "Ceiling",
            "Clamp",
            "Exp",
            "Floor",
            "IEEERemainder",
            "Log",
            "Log10",
            "Log2",
            "Max",
            "MaxMagnitude",
            "Min",
            "MinMagnitude",
            "Pow",
            "Round",
            "Sign",
            "Sqrt",
            "Truncate",
        ],
    ),
    (
        "string",
        &[
            "Compare",
            "CompareOrdinal",
            "IsNullOrEmpty",
            "IsNullOrWhiteSpace",
        ],
    ),
    ("DateTime", &["Compare", "DaysInMonth", "IsLeapYear"]),
];

/// Whether the call is a listed pure static API invoked through its owner.
fn is_pure_static_call(call: Node<'_>, source: &str) -> bool {
    let Some(function) = invocation_function(call) else {
        return false;
    };
    if function.kind() != "member_access_expression" {
        return false;
    }
    PURE_STATIC_APIS.iter().any(|(owner, methods)| {
        methods.contains(&callee_name(call, source).unwrap_or(""))
            && first_named_child(function)
                .is_some_and(|receiver| node_text(receiver, source).trim().ends_with(owner))
    })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2201_ignores_sources_without_statements() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S2201").is_empty());
    }

    #[test]
    fn s2201_ignores_results_assigned_or_kept() {
        let report = analyze_default(
            "class C\n{\n    int total;\n    void M()\n    {\n        total = Math.Max(total, 0);\n        var kept = Math.Abs(-1);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2201").is_empty());
    }

    #[test]
    fn s2201_ignores_case_sensitive_owner_mismatch() {
        let report = analyze_default("math.Abs(-3);\n");
        assert!(with_key(&report, "csharpsquid:S2201").is_empty());
    }

    #[test]
    fn s2201_ignores_unlisted_methods_and_owners() {
        let report = analyze_default(
            "class C\n{\n    string name = \"x\";\n    void M()\n    {\n        Console.WriteLine(\"hi\");\n        name.Trim();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2201").is_empty());
    }

    #[test]
    fn s2201_flags_qualified_owner_suffix_match() {
        let report = analyze_default("System.Math.Floor(2.7);\nMyMath.Clamp(value, 0, 10);\n");
        let found = with_key(&report, "csharpsquid:S2201");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 1);
        assert_eq!(found[1].range.start.line, 2);
    }

    #[test]
    fn s2201_flags_string_and_datetime_owners() {
        let report = analyze_default(
            "Math.Round(2.5);\nstring.IsNullOrWhiteSpace(input);\nDateTime.DaysInMonth(2026, 2);\n",
        );
        let found = with_key(&report, "csharpsquid:S2201");
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].range.start.line, 1);
        assert_eq!(found[1].range.start.line, 2);
        assert_eq!(found[2].range.start.line, 3);
    }
}
