use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S881 — increments and decrements stay standalone.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const KINDS: [&str; 2] = ["prefix_unary_expression", "postfix_unary_expression"];
    let mut issues = Vec::new();
    for unary in collect_kinds(root, &KINDS) {
        if is_error_tainted(unary) || !matches!(operator_of(unary), Some("++" | "--")) {
            continue;
        }
        let parent_kind = unary.parent().map(|parent| parent.kind());
        if matches!(parent_kind, Some("expression_statement" | "for_statement")) {
            continue;
        }
        issues.push(issue(
            language,
            "S881",
            "Extract this increment or decrement into its own statement.",
            range_of(unary, source),
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s881_minimal_type_has_no_findings() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S881").is_empty());
    }

    #[test]
    fn s881_standalone_and_for_clause_updates_stay_clean() {
        let report = analyze_default(
            "class C\n{\n    void M(int n)\n    {\n        int i = 0;\n        i++;\n        i--;\n        for (var j = 0; j < n; j++)\n        {\n            Step(i);\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S881").is_empty());
    }

    // DISCREPANCY vs SonarQube S881: embedded increments never fire.
    // `operator_of` (expressions/support.rs) matches only its 23-entry
    // operator table, which lacks `++` and `--`, so prefix and postfix
    // unary nodes yield `None` and every embedded increment such as
    // `var j = i++;` is silently skipped. Flagging cases are omitted
    // until the implementation recognizes unary tokens; SQ reports each
    // embedded update at its own line.
}
