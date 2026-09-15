use super::support::catch_type_tail;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::block_statements;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2486 — swallowing bare `Exception` hides unrelated bugs.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|clause| !is_error_tainted(*clause))
        .filter(|clause| is_ignored_exception_catch(*clause, source))
        .filter(|clause| {
            clause.child_by_field_name("body").is_some_and(|body| {
                block_statements(body).is_empty() && collect_kinds(body, &["comment"]).is_empty()
            })
        })
        .map(|clause| {
            issue(
                language,
                "S2486",
                "Handle the exception or explain in a comment why it can be ignored.",
                range_of(clause, source),
            )
        })
        .collect()
}

/// `catch { }`, `catch (Exception) { }`, and `catch (Exception ex) { }` all
/// swallow the exception silently; the dapper oracle reports all four real
/// findings on bare `catch { }` while comment-explained bodies
/// (`catch { /* don't spoil any existing exception */ }`) stay clear, as do
/// typed non-`Exception` catches such as `catch (ArgumentException ex)`.
fn is_ignored_exception_catch(clause: Node<'_>, source: &str) -> bool {
    let typed = {
        let mut cursor = clause.walk();
        clause
            .children(&mut cursor)
            .any(|child| child.kind() == "catch_declaration")
    };
    !typed || catch_type_tail(clause, source) == Some("Exception")
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2486_comment_only_bodies_are_explained() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); }\n        catch (System.Exception)\n        {\n            // Nothing to see here.\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2486").is_empty());
    }

    /// dapper Dapper.ProviderTools/BulkCopy.cs:78 and three siblings: a bare
    /// `catch { }` swallows everything and is reported by the reference.
    #[test]
    fn s2486_bare_empty_catches_are_reported() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); }\n        catch { }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2486");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Handle the exception or explain in a comment why it can be ignored."
        );
    }

    /// dapper Dapper/SqlMapper.cs:1173: a comment explaining the swallow is
    /// the documented exemption, so the reference reports nothing there.
    #[test]
    fn s2486_explained_bare_catches_stay_clear() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); }\n        catch { /* don't spoil any existing exception */ }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2486").is_empty());
    }

    /// dapper Dapper/SqlMapper.cs:1191: typed non-`Exception` catches keep
    /// their dedicated semantics and stay out of this rule.
    #[test]
    fn s2486_typed_non_exception_catches_stay_clear() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); }\n        catch (System.ArgumentException ex) { }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2486").is_empty());
    }

    /// dapper Dapper.ProviderTools/DbConnectionExtensions.cs:122: a bare
    /// catch with a handling body is not a silent swallow.
    #[test]
    fn s2486_handled_bare_catches_stay_clear() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); }\n        catch\n        {\n            Recover();\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2486").is_empty());
    }

    #[test]
    fn s2486_empty_exception_typed_catches_are_reported() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); }\n        catch (System.Exception ex) { }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2486").len(), 1);
    }
}
