use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{block_statements, callee_name, first_named_child};
use crate::rules::structure::{else_alternative, embedded_bodies};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3267 — a foreach whose whole body conditionally appends one
/// item is a LINQ projection in disguise.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    /// The single `x.Add(y)` statement inside an if body, if present.
    fn lone_add_statement(if_statement: Node<'_>, source: &str) -> bool {
        let bodies = embedded_bodies(if_statement);
        match bodies.as_slice() {
            [body] => {
                let statements = if body.kind() == "block" {
                    block_statements(*body)
                } else {
                    vec![*body]
                };
                match statements.as_slice() {
                    [statement] => {
                        statement.kind() == "expression_statement"
                            && first_named_child(*statement)
                                .and_then(|expression| {
                                    (expression.kind() == "invocation_expression")
                                        .then_some(expression)
                                })
                                .and_then(|invocation| callee_name(invocation, source))
                                == Some("Add")
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    let mut issues = Vec::new();
    for foreach_statement in collect_kinds(root, &["foreach_statement"]) {
        if is_error_tainted(foreach_statement) || else_alternative(foreach_statement).is_some() {
            continue;
        }
        let convertible = embedded_bodies(foreach_statement)
            .first()
            .is_some_and(|body| {
                body.kind() == "block" && {
                    let statements = block_statements(*body);
                    match statements.as_slice() {
                        [only] => {
                            only.kind() == "if_statement"
                                && !is_error_tainted(*only)
                                && lone_add_statement(*only, source)
                        }
                        _ => false,
                    }
                }
            });
        if convertible {
            issues.push(issue(
                language,
                "S3267",
                "Rewrite this loop as a LINQ expression.",
                range_of(foreach_statement),
            ));
        }
    }
    issues
}
