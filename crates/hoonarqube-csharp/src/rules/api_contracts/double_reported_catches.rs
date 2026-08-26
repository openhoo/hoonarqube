use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::logging::logging_calls;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2139 — logging and rethrowing reports the failure twice.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|clause| !is_error_tainted(*clause))
        .filter_map(|clause| {
            let body = clause.child_by_field_name("body")?;
            Some((
                clause,
                !logging_calls(body, source).is_empty(),
                !collect_kinds(body, &["throw_statement"]).is_empty(),
            ))
        })
        .filter(|(_, logs, rethrows)| *logs && *rethrows)
        .map(|(clause, _, _)| {
            issue(
                language,
                "S2139",
                "Choose either logging or rethrowing in this catch clause.",
                range_of(clause, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2139_flags_only_the_double_reporting_clause() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); }\n        catch (System.Exception ex)\n        {\n            logger.LogError(\"First {Code}\", ex);\n        }\n        catch (System.Exception ex)\n        {\n            logger.LogError(\"Second {Code}\", ex);\n            throw;\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2139");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 10);
    }

    #[test]
    fn s2139_throwing_a_new_exception_still_counts_as_rethrow() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); }\n        catch (System.Exception ex)\n        {\n            logger.LogError(\"Wrapped {Code}\", ex);\n            throw new System.Exception(\"boom\", ex);\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2139").len(), 1);
    }
}
