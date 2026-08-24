use super::support::catch_type_tail;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2221 — catching bare `Exception` also swallows unrelated
/// runtime failures.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|clause| !is_error_tainted(*clause))
        .filter(|clause| catch_type_tail(*clause, source) == Some("Exception"))
        .map(|clause| {
            issue(
                language,
                "S2221",
                "Catch a more specific exception than 'Exception'.",
                range_of(clause),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2221_flags_unqualified_and_qualified_general_catches() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); }\n        catch (Exception first) { Recover(); }\n        try { Run(); }\n        catch (System.Exception second) { Recover(); }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2221").len(), 2);
    }

    #[test]
    fn s2221_catches_without_type_declarations_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); }\n        catch { Recover(); }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2221").is_empty());
    }
}
