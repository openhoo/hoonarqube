use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1163 — throwing from `finally` swallows in-flight failures.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["throw_statement"])
        .into_iter()
        .filter(|throw| ancestors_of(*throw).any(|ancestor| ancestor.kind() == "finally_clause"))
        .map(|throw| {
            issue(
                language,
                "S1163",
                "Do not throw from a finally block.",
                range_of(throw),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1163_flags_bare_rethrows_but_not_catch_throws() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Work(); }\n        catch (IOException io) { Log(io); throw; }\n        finally { throw; }\n        try { Work(); }\n        finally { if (done) { throw new TimeoutException(); } }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1163");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 7);
        assert_eq!(flagged[1].range.start.line, 9);
    }
}
