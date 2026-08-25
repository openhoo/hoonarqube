// --- python:S4144 — identical sibling function implementations

use crate::support::{issue_at, ranges_textually_equal, suite_span};
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn body_is_trivial(body: &[Stmt]) -> bool {
    match body.len() {
        0 => true,
        1 => matches!(&body[0], Stmt::Pass(_) | Stmt::Expr(_)),
        _ => false,
    }
}

pub(crate) fn flag_identical_function_pairs(
    suite: &[Stmt],
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let definitions: Vec<&ruff_python_ast::StmtFunctionDef> = suite
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::FunctionDef(function) => Some(function),
            _ => None,
        })
        .collect();
    for (position, later) in definitions.iter().enumerate().skip(1) {
        for earlier in &definitions[..position] {
            if body_is_trivial(&earlier.body)
                || body_is_trivial(&later.body)
                || !ranges_textually_equal(
                    suite_span(&earlier.body),
                    suite_span(&later.body),
                    source,
                )
            {
                continue;
            }
            issues.push(issue_at(
                "python:S4144",
                &format!(
                    "Refactor this function; it duplicates the implementation of '{}'.",
                    earlier.name.as_str()
                ),
                later.name.range(),
                index,
                source,
            ));
            break;
        }
    }
}
