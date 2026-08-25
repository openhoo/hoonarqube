use crate::support::for_each_nursery_block;
use crate::support::for_each_stmt_in_scope;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_control_flow_in_nurseries(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_nursery_block(parsed.syntax().body.as_slice(), &mut |with_stmt| {
        scan_nursery_body(with_stmt.body.as_slice(), 0, &mut issues, index, source);
    });
    issues
}

/// Walks nursery body statements; flags Return always, Break/Continue only
/// when `loop_depth` is 0 (i.e. no inner loop owns the jump).
fn scan_nursery_body(
    suite: &[Stmt],
    loop_depth: usize,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for stmt in suite {
        match stmt {
            Stmt::Return(_) => {
                issues.push(issue_at(
                    "python:S7514",
                    "Do not jump out of a nursery block.",
                    stmt.range(),
                    index,
                    source,
                ));
            }
            Stmt::Break(_) | Stmt::Continue(_) if loop_depth == 0 => {
                issues.push(issue_at(
                    "python:S7514",
                    "Do not jump out of a nursery block.",
                    stmt.range(),
                    index,
                    source,
                ));
            }
            Stmt::For(s) => {
                scan_nursery_body(s.body.as_slice(), loop_depth + 1, issues, index, source);
                scan_nursery_body(s.orelse.as_slice(), loop_depth, issues, index, source);
            }
            Stmt::While(s) => {
                scan_nursery_body(s.body.as_slice(), loop_depth + 1, issues, index, source);
                scan_nursery_body(s.orelse.as_slice(), loop_depth, issues, index, source);
            }
            Stmt::If(s) => {
                for clause in &s.elif_else_clauses {
                    scan_nursery_body(clause.body.as_slice(), loop_depth, issues, index, source);
                }
                scan_nursery_body(s.body.as_slice(), loop_depth, issues, index, source);
            }
            Stmt::With(s) => {
                scan_nursery_body(s.body.as_slice(), loop_depth, issues, index, source);
            }
            Stmt::Try(s) => {
                scan_nursery_body(s.body.as_slice(), loop_depth, issues, index, source);
                for handler in &s.handlers {
                    if let ruff_python_ast::ExceptHandler::ExceptHandler(h) = handler {
                        scan_nursery_body(h.body.as_slice(), loop_depth, issues, index, source);
                    }
                }
                scan_nursery_body(s.orelse.as_slice(), loop_depth, issues, index, source);
                scan_nursery_body(s.finalbody.as_slice(), loop_depth, issues, index, source);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s7514_flags_control_flow_out_of_nurseries() {
        let flagged = scan(concat!(
            "async def esc():\n",
            "    async with trio.open_nursery() as nursery:\n",
            "        nursery.start_soon(a)\n",
            "        nursery.start_soon(b)\n",
            "        return\n"
        ));
        let found = findings(&flagged, "python:S7514");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 5);
    }
}
