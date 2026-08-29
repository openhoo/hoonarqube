use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1163 — throwing from `finally` swallows in-flight failures.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["throw_statement"])
        .into_iter()
        .filter(|throw| executes_in_finally(*throw))
        .map(|throw| {
            issue(
                language,
                "S1163",
                "Refactor this code to not throw exceptions in finally blocks.",
                range_of(throw, source),
            )
        })
        .collect()
}

/// A local function or delegate declared in a finally clause has its own
/// execution scope; only throws executed by the clause are relevant.
fn executes_in_finally(throw_statement: Node<'_>) -> bool {
    for ancestor in ancestors_of(throw_statement) {
        match ancestor.kind() {
            "finally_clause" => return true,
            "lambda_expression" | "anonymous_method_expression" | "local_function_statement" => {
                return false;
            }
            _ => {}
        }
    }
    false
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

    #[test]
    fn s1163_ignores_deferred_throws_declared_in_finally() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Work(); }\n        finally\n        {\n            Action later = () => throw new InvalidOperationException();\n            void ThrowLater() { throw new IOException(); }\n            throw new TimeoutException();\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1163");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 10);
    }
}
