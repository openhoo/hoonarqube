use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_from_byte_offsets};
use crate::rules::expressions::block_statements;
use crate::rules::structure::{else_alternative, embedded_bodies};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3240 — conditions use their simplest shape: negation beats
/// comparing against `false`, ternaries over boolean literals collapse to
/// their condition.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for if_statement in collect_kinds(root, &["if_statement"]) {
        if is_error_tainted(if_statement) || else_alternative(if_statement).is_none() {
            continue;
        }
        let bodies = embedded_bodies(if_statement);
        let simple_branches = bodies.len() == 2
            && bodies.iter().all(|body| {
                let statements = if body.kind() == "block" {
                    block_statements(*body)
                } else {
                    vec![*body]
                };
                statements.len() == 1
                    && matches!(
                        statements[0].kind(),
                        "return_statement" | "expression_statement"
                    )
            });
        if simple_branches {
            issues.push(issue(
                language,
                "S3240",
                "Use the '?:' operator here.",
                range_from_byte_offsets(
                    if_statement.start_byte(),
                    if_statement.start_byte() + "if".len(),
                    source,
                ),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3240_flags_if_else_assignments() {
        let bad = analyze_default(
            "class C { int A(bool value) { if (value) { return 1; } else { return 0; } } }",
        );
        assert_eq!(with_key(&bad, "csharpsquid:S3240").len(), 1);

        let good = analyze_default(
            "class C { bool A(bool value) => !value; bool B(bool value) => value; }",
        );
        assert!(with_key(&good, "csharpsquid:S3240").is_empty());
    }
}
