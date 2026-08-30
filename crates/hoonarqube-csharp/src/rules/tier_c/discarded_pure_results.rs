use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, first_named_child};
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["expression_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter_map(first_named_child)
        .filter(|expression| {
            expression.kind() == "invocation_expression"
                && PURE_METHODS.contains(&callee_name(*expression, source).unwrap_or(""))
        })
        .map(|expression| {
            issue(
                language,
                "S2201",
                format!(
                    "Use the return value of method '{}'.",
                    callee_name(expression, source).unwrap_or("method")
                ),
                range_of(expression, source),
            )
        })
        .collect()
}

/// csharpsquid:S2201 — discarded results of side-effect-free static calls.
/// Subset: a curated pure-API owner/method table (`Math`, `string`,
/// `DateTime`) called as a bare statement; user-declared pure functions and
/// discard-pattern assignments stay uncovered.
const PURE_METHODS: [&str; 7] = [
    "Where",
    "Select",
    "OrderBy",
    "OrderByDescending",
    "All",
    "Any",
    "Contains",
];

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
    fn s2201_flags_discarded_linq_results() {
        let report = analyze_default("values.Where(x => x > 0);\nvalues.OrderBy(x => x);\n");
        let found = with_key(&report, "csharpsquid:S2201");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 1);
        assert_eq!(found[1].range.start.line, 2);
    }

    #[test]
    fn s2201_ignores_non_linq_pure_apis_without_semantic_types() {
        let report = analyze_default(
            "Math.Round(2.5);\nstring.IsNullOrWhiteSpace(input);\nDateTime.DaysInMonth(2026, 2);\n",
        );
        assert!(with_key(&report, "csharpsquid:S2201").is_empty());
    }
}
