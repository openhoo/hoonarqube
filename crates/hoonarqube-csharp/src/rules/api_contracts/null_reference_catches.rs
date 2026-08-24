use super::support::catch_type_tail;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1696 — catching `NullReferenceException` hides dereference
/// bugs.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|clause| !is_error_tainted(*clause))
        .filter(|clause| catch_type_tail(*clause, source) == Some("NullReferenceException"))
        .map(|clause| {
            issue(
                language,
                "S1696",
                "Do not catch 'NullReferenceException'.",
                range_of(clause),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1696_flags_qualified_null_reference_catches() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { } catch (System.NullReferenceException broken) { Recover(); }\n        try { } catch (System.ArgumentNullException other) { Recover(); }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1696").len(), 1);
    }

    #[test]
    fn s1696_flags_filtered_null_reference_catches() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { }\n        catch (NullReferenceException broken) when (broken.InnerException == null)\n        {\n            Recover();\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1696").len(), 1);
    }

    #[test]
    fn s1696_allows_untyped_catches_and_counts_repeats() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { } catch { Recover(); }\n        try { } catch (NullReferenceException first) { Recover(); }\n        try { } catch (NullReferenceException second) { Recover(); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1696");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 6);
        assert_eq!(flagged[1].range.start.line, 7);
    }
}
