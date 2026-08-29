use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::first_named_child;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3445 — `throw ex;` restarts the stack trace at the catch.
pub(crate) fn check(source_root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(source_root, &["throw_statement"])
        .into_iter()
        .filter(|throw| !is_error_tainted(*throw))
        .filter(|throw| {
            let Some(expression) =
                first_named_child(*throw).filter(|expression| expression.kind() == "identifier")
            else {
                return false;
            };
            enclosing_catch_name(*throw, source)
                .is_some_and(|caught| caught == node_text(expression, source))
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

fn enclosing_catch_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let clause = ancestors_of(node).find(|ancestor| ancestor.kind() == "catch_clause")?;
    let mut cursor = clause.walk();
    clause
        .children(&mut cursor)
        .find(|child| child.kind() == "catch_declaration")
        .and_then(|declaration| declaration.child_by_field_name("name"))
        .map(|name| node_text(name, source))
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
    fn s3445_spares_thrown_identifiers_outside_catch_clauses() {
        let report = analyze_default(
            "class A\n{\n    void Fail(System.Exception ex)\n    {\n        throw ex;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3445").is_empty());
    }

    #[test]
    fn s3445_only_flags_the_current_catch_variable() {
        let report = analyze_default(
            "class A\n{\n    void M(System.Exception other)\n    {\n        try { Run(); }\n        catch (System.Exception caught)\n        {\n            if (retry) throw other;\n            throw caught;\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3445").len(), 1);
    }
}
