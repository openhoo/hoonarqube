use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::first_named_child;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3445 — `throw ex;` restarts the stack trace at the catch.
pub(crate) fn check(source_root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(source_root, &["throw_statement"])
        .into_iter()
        .filter(|throw| !is_error_tainted(*throw))
        .filter(|throw| {
            first_named_child(*throw).is_some_and(|expression| expression.kind() == "identifier")
        })
        .map(|throw| {
            issue(
                language,
                "S3445",
                "Consider using 'throw;' to preserve the stack trace.",
                range_of(throw, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3445_new_exceptions_and_bare_throws_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); }\n        catch (IOException ex)\n        {\n            throw new IOException(\"wrap\", ex);\n        }\n        catch (IOException other)\n        {\n            throw;\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3445").is_empty());
    }

    #[test]
    fn s3445_flags_thrown_identifiers_outside_catch_clauses() {
        let report = analyze_default(
            "class A\n{\n    void Fail(System.Exception ex)\n    {\n        throw ex;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3445").len(), 1);
    }
}
