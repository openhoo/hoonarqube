use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, range_of};
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
                logging_calls(body, source)
                    .into_iter()
                    .any(|call| belongs_to_catch_body(call, body)),
                collect_kinds(body, &["throw_statement"])
                    .into_iter()
                    .any(|throw| belongs_to_catch_body(throw, body)),
            ))
        })
        .filter(|(_, logs, rethrows)| *logs && *rethrows)
        .map(|(clause, _, _)| {
            let anchor = collect_kinds(clause, &["catch_declaration"])
                .first()
                .and_then(|declaration| declaration.child_by_field_name("name"))
                .unwrap_or(clause);
            issue(
                language,
                "S2139",
                "Either log this exception and handle it, or rethrow it with some contextual information.",
                range_of(anchor, source),
            )
        })
        .collect()
}

/// Nested catch handlers and deferred callable bodies have their own failure
/// reporting scope and must not contribute logging/throws to this clause.
fn belongs_to_catch_body(node: Node<'_>, body: Node<'_>) -> bool {
    for ancestor in ancestors_of(node) {
        if ancestor.id() == body.id() {
            return true;
        }
        if matches!(
            ancestor.kind(),
            "catch_clause"
                | "local_function_statement"
                | "lambda_expression"
                | "anonymous_method_expression"
        ) {
            return false;
        }
    }
    false
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

    #[test]
    fn s2139_does_not_mix_outer_and_nested_callable_actions() {
        let nested_throw = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); }\n        catch (System.Exception ex)\n        {\n            logger.LogError(\"Outer\", ex);\n            void Later() { throw ex; }\n        }\n    }\n}\n",
        );
        assert!(with_key(&nested_throw, "csharpsquid:S2139").is_empty());

        let nested_log = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); }\n        catch (System.Exception ex)\n        {\n            System.Action later = () => logger.LogError(\"Later\", ex);\n            throw;\n        }\n    }\n}\n",
        );
        assert!(with_key(&nested_log, "csharpsquid:S2139").is_empty());
    }

    #[test]
    fn s2139_nested_catch_reports_only_its_own_actions() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); }\n        catch (System.Exception outer)\n        {\n            try { Recover(); }\n            catch (System.Exception inner)\n            {\n                logger.LogError(\"Inner\", inner);\n                throw;\n            }\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2139").len(), 1);
    }
}
