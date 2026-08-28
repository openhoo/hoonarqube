use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::callee_name;
use crate::rules::linq_api::first_child_token_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2291 — `unchecked` around `Sum` silently truncates.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for statement in collect_kinds(root, &["checked_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter(|statement| first_child_token_text(*statement, source) == "unchecked")
    {
        for call in collect_kinds(statement, &["invocation_expression"])
            .into_iter()
            .filter(|call| callee_name(*call, source) == Some("Sum"))
        {
            let name = crate::rules::expressions::invocation_function(call)
                .and_then(|function| function.child_by_field_name("name"))
                .unwrap_or(call);
            issues.push(issue(
                language,
                "S2291",
                "Refactor this code to handle 'OverflowException'.",
                range_of(name, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2291_reports_each_sum_inside_unchecked_code() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        unchecked { total = values.Sum() + extra.Sum(); }\n        unchecked\n        {\n            if (ready)\n            {\n                total = values.Sum(item => item.Score);\n            }\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2291");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 5);
        assert_eq!(flagged[2].range.start.line, 10);
    }
}
