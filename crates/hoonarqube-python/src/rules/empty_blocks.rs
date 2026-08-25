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
        // Function bodies are python:S1186's subject, but nested suites
        // inside them (if/for/while/try) are still checked here.
        if let Stmt::FunctionDef(s) = stmt {
            visit_nested_non_function(s.body.as_slice(), issues, index, source);
            continue;
        }
        for body in child_bodies(stmt) {
            visit_suite(body, issues, index, source);
        }
    }
}

/// Visits suites inside a function body, skipping direct function definitions
/// (those belong to S1186) but checking all other nested suites.
fn visit_nested_non_function(
    suite: &[Stmt],
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for stmt in suite {
        if matches!(stmt, Stmt::FunctionDef(_)) {
            continue;
        }
        for body in child_bodies(stmt) {
            visit_suite(body, issues, index, source);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s108_flags_empty_if_inside_function() {
        let flagged = scan("def f():\n    if x:\n        pass\n");
        assert!(!findings(&flagged, "python:S108").is_empty());
    }

    #[test]
    fn s108_function_body_with_pass_is_clean() {
        let flagged = scan("def f():\n    pass\n");
        assert!(findings(&flagged, "python:S108").is_empty());
    }

    #[test]
    fn s108_flags_empty_for_inside_method() {
        let flagged = scan("class C:\n    def m(self):\n        for x in xs:\n            pass\n");
        assert!(!findings(&flagged, "python:S108").is_empty());
    }
}
