use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2737 — a catch clause that only rethrows adds nothing.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|clause| !is_error_tainted(*clause))
        .filter(|clause| {
            clause.child_by_field_name("body").is_some_and(|body| {
                let mut cursor = body.walk();
                let mut children = body.named_children(&mut cursor);
                children.next().is_some_and(|statement| {
                    statement.kind() == "throw_statement"
                        && statement.named_child_count() == 0
                        && children.next().is_none()
                })
            })
        })
        .map(|clause| {
            issue(
                language,
                "S2737",
                "Add logic to this catch clause or eliminate it and rethrow the exception automatically.",
                range_of(clause, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2737_flags_untyped_typed_and_filtered_rethrows() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { } catch { throw; }\n        try { } catch (InvalidOperationException typed) { throw typed; }\n        try { } catch (IOException io) when (io.Data != null) { throw; }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2737");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 7);
    }

    #[test]
    fn s2737_allows_logging_or_conditionals_before_rethrowing() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { } catch (Exception ex) { Log(ex); throw; }\n        try { } catch (Exception ex) { if (ex.InnerException == null) throw; }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2737").is_empty());
    }

    #[test]
    fn s2737_does_not_ignore_conditional_compilation_in_catch_body() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); }\n        catch (Exception ex)\n        {\n#if DEBUG\n            Log(ex);\n#endif\n            throw;\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2737").is_empty());
    }
}
