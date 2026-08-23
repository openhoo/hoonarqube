use crate::support::child_bodies;
use crate::support::issue_at;
use crate::support::subscript_assignment_key;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_overwritten_collection_items(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    fn visit_suite(suite: &[Stmt], issues: &mut Vec<Issue>, index: &LineIndex, source: &str) {
        for pair in suite.windows(2) {
            let (Stmt::Assign(previous), Stmt::Assign(current)) = (&pair[0], &pair[1]) else {
                continue;
            };
            let previous_key = subscript_assignment_key(previous, source);
            let current_key = subscript_assignment_key(current, source);
            if let (Some(previous_key), Some(current_key)) = (previous_key, current_key)
                && previous_key == current_key
            {
                issues.push(issue_at(
                    "python:S4143",
                    "This element is overwritten without being read.",
                    current.range(),
                    index,
                    source,
                ));
            }
        }
        for stmt in suite {
            for body in child_bodies(stmt) {
                visit_suite(body, issues, index, source);
            }
        }
    }
    let mut issues = Vec::new();
    visit_suite(parsed.syntax().body.as_slice(), &mut issues, index, source);
    issues
}
