use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::block_statements;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1751 — loops that provably run at most once: the final
/// body statement leaves the loop unconditionally. Entry-false
/// conditions belong to S2252; `do`-while run-once idioms are exempt.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &["while_statement", "for_statement"]) {
        if is_error_tainted(header) {
            continue;
        }
        let Some(body) = header.child_by_field_name("body") else {
            continue;
        };
        if trailing_statement_exits(body) {
            issues.push(issue(
                language,
                "S1751",
                "This loop will execute at most once.",
                range_of(header),
            ));
        }
    }
    issues
}

/// Whether a loop body's final statement leaves the loop unconditionally.
fn trailing_statement_exits(body: Node<'_>) -> bool {
    let statements = if body.kind() == "block" {
        block_statements(body)
    } else {
        vec![body]
    };
    statements.last().is_some_and(|last| {
        matches!(
            last.kind(),
            "break_statement" | "return_statement" | "throw_statement"
        )
    })
}
