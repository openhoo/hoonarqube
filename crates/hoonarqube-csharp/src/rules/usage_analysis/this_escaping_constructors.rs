use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, walk_all};
use crate::rules::expressions::binary_operands;
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3366 — constructors must not publish `this` early.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for constructor in collect_kinds(root, &["constructor_declaration"]) {
        if is_error_tainted(constructor) {
            continue;
        }
        let Some(body) = body_of(constructor) else {
            continue;
        };
        let mut this_sites: Vec<Node> = Vec::new();
        walk_all(body, &mut |node| {
            if matches!(node.kind(), "this" | "this_expression") {
                this_sites.push(node);
            }
        });
        for this_expression in this_sites {
            let Some(parent) = this_expression.parent() else {
                continue;
            };
            let escapes = match parent.kind() {
                "argument" | "return_statement" => true,
                "assignment_expression" => binary_operands(parent)
                    .is_some_and(|(_, right)| right.id() == this_expression.id()),
                _ => false,
            };
            if escapes {
                issues.push(issue(
                    language,
                    "S3366",
                    "Constructor leaks 'this' before the object is fully initialized.",
                    range_of(this_expression),
                ));
            }
        }
    }
    issues
}
