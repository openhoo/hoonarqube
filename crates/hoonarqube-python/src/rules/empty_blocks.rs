use crate::support::child_bodies;
use crate::support::issue_at;
use crate::support::placeholder_only_suite;
use crate::support::suite_span;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

// --- python:S108 — empty non-function suites ----------------------------------
//
// Any suite consisting solely of `pass`/`...` placeholders is left empty.
// Function bodies belong to python:S1186 and are skipped here; a docstring
// counts as content everywhere, so documentation-only classes stay clean.

pub(crate) fn check_empty_blocks(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_suite(parsed.syntax().body.as_slice(), &mut issues, index, source);
    issues
}

fn visit_suite(suite: &[Stmt], issues: &mut Vec<Issue>, index: &LineIndex, source: &str) {
    if placeholder_only_suite(suite) {
        issues.push(issue_at(
            "python:S108",
            "Either remove or fill this block of code.",
            suite_span(suite),
            index,
            source,
        ));
        return;
    }
    for stmt in suite {
        // Function bodies are python:S1186's subject; their suites never
        // satisfy this rule even when they hold only `pass`.
        if matches!(stmt, Stmt::FunctionDef(_)) {
            continue;
        }
        for body in child_bodies(stmt) {
            visit_suite(body, issues, index, source);
        }
    }
}
