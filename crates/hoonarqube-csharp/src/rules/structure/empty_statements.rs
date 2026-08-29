use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1116 — stray empty statements are removed.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["empty_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter(|statement| {
            statement.parent().is_none_or(|parent| {
                !matches!(
                    parent.kind(),
                    "for_statement" | "foreach_statement" | "while_statement" | "do_statement"
                ) || parent.child_by_field_name("body") != Some(*statement)
            })
        })
        .map(|statement| {
            issue(
                language,
                "S1116",
                "Remove this empty statement.",
                range_of(statement, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1116_keeps_deliberate_empty_loop_bodies() {
        let report = analyze_default(
            "class C { void M() { ; for (var i = 0; i < 3; i++) ; while (Ready()) ; } }",
        );
        let issues = with_key(&report, "csharpsquid:S1116");
        assert_eq!(issues.len(), 1);
    }
}
