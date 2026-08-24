use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::callee_name;
use crate::rules::linq_api::first_child_token_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2291 — `unchecked` around `Sum` silently truncates.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["checked_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter(|statement| first_child_token_text(*statement, source) == "unchecked")
        .filter(|statement| {
            collect_kinds(*statement, &["invocation_expression"])
                .into_iter()
                .any(|call| callee_name(call, source) == Some("Sum"))
        })
        .map(|statement| {
            issue(
                language,
                "S2291",
                "Do not disable overflow checks around 'Sum'.",
                range_of(statement),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2291_reports_each_unchecked_block_once_regardless_of_sum_count() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        unchecked { total = values.Sum() + extra.Sum(); }\n        unchecked\n        {\n            if (ready)\n            {\n                total = values.Sum(item => item.Score);\n            }\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2291");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }
}
