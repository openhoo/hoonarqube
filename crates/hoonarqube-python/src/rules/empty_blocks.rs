use crate::support::issue_at;
use crate::support::suite_span;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

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
    visit_suite(
        parsed.syntax().body.as_slice(),
        ParentKind::Module,
        parsed,
        &mut issues,
        index,
        source,
    );
    issues
}

/// The statement kind owning a suite. Function, class, and `except` suites
/// are never flagged: functions belong to python:S1186, classes are allowed
/// to be empty, and `except: pass` is idiomatic.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ParentKind {
    Module,
    Function,
    Class,
    Except,
    Other,
}

fn visit_suite(
    suite: &[Stmt],
    parent: ParentKind,
    parsed: &Parsed<ModModule>,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if !matches!(parent, ParentKind::Function | ParentKind::Class | ParentKind::Except)
        && pass_only_suite(suite)
        && !block_has_comment(suite, parsed, source)
    {
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
        visit_children(stmt, parsed, issues, index, source);
    }
}

/// A suite is empty only when every statement is `pass`; `...` and
/// docstrings count as content.
fn pass_only_suite(suite: &[Stmt]) -> bool {
    !suite.is_empty() && suite.iter().all(|stmt| matches!(stmt, Stmt::Pass(_)))
}

/// The reference exempts a pass-only block when any comment appears between
/// the parent statement's first newline and the token after the suite's
/// last token (comments inside the block or trailing the final `pass`).
fn block_has_comment(suite: &[Stmt], parsed: &Parsed<ModModule>, source: &str) -> bool {
    let span = suite_span(suite);
    // The reference scans tokens from the parent statement's first newline
    // through the token after the suite's last token. The parent header ends
    // at the last structural token before the suite (`:`); comments from
    // that token's line onward exempt the block.
    let header_end = parsed
        .tokens()
        .iter()
        .filter(|token| {
            !token.kind().is_trivia()
                && !matches!(
                    token.kind(),
                    ruff_python_ast::token::TokenKind::Indent
                        | ruff_python_ast::token::TokenKind::Dedent
                        | ruff_python_ast::token::TokenKind::Newline
                )
                && token.range().end() <= span.start()
        })
        .last()
        .map(|token| token.range().start())
        .unwrap_or_default();
    let header_line_start = source[..usize::from(header_end)]
        .rfind('\n')
        .map_or(0, |pos| pos + 1);
    let mut after = parsed
        .tokens()
        .iter()
        .filter(|token| !token.kind().is_trivia() && token.range().start() >= span.end());
    let bound = after
        .next()
        .and_then(|_| after.next())
        .map(|token| token.range().start());
    parsed.tokens().iter().any(|token| {
        token.kind() == ruff_python_ast::token::TokenKind::Comment
            && usize::from(token.range().start()) >= header_line_start
            && bound.is_none_or(|bound| token.range().start() < bound)
    })
}

fn visit_children(
    stmt: &Stmt,
    parsed: &Parsed<ModModule>,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    match stmt {
        Stmt::FunctionDef(function) => {
            // Nested suites inside a function are still checked; the
            // function body itself belongs to python:S1186.
            for inner in function.body.as_slice() {
                visit_children(inner, parsed, issues, index, source);
            }
        }
        Stmt::ClassDef(class) => {
            visit_suite(class.body.as_slice(), ParentKind::Class, parsed, issues, index, source);
        }
        Stmt::For(node) => {
            visit_suite(&node.body, ParentKind::Other, parsed, issues, index, source);
            visit_suite(&node.orelse, ParentKind::Other, parsed, issues, index, source);
        }
        Stmt::While(node) => {
            visit_suite(&node.body, ParentKind::Other, parsed, issues, index, source);
            visit_suite(&node.orelse, ParentKind::Other, parsed, issues, index, source);
        }
        Stmt::If(node) => {
            visit_suite(&node.body, ParentKind::Other, parsed, issues, index, source);
            for clause in &node.elif_else_clauses {
                visit_suite(&clause.body, ParentKind::Other, parsed, issues, index, source);
            }
        }
        Stmt::With(node) => {
            visit_suite(&node.body, ParentKind::Other, parsed, issues, index, source);
        }
        Stmt::Match(node) => {
            for case in &node.cases {
                visit_suite(&case.body, ParentKind::Other, parsed, issues, index, source);
            }
        }
        Stmt::Try(node) => {
            visit_suite(&node.body, ParentKind::Other, parsed, issues, index, source);
            visit_suite(&node.orelse, ParentKind::Other, parsed, issues, index, source);
            visit_suite(&node.finalbody, ParentKind::Other, parsed, issues, index, source);
            for handler in &node.handlers {
                let ExceptHandler::ExceptHandler(handler) = handler;
                visit_suite(&handler.body, ParentKind::Except, parsed, issues, index, source);
            }
        }
        _ => {}
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
