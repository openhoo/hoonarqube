use crate::support::call_path_matches;
use crate::support::for_each_call;
use crate::support::is_call_method;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S4829 — reading the Standard Input is security-sensitive ---------

pub(crate) fn check_s4829_standard_input(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const STDIN_READERS: [&str; 6] = [
        "sys.stdin.read",
        "sys.stdin.readline",
        "sys.stdin.readlines",
        "sys.stdin.buffer.read",
        "sys.stdin.buffer.readline",
        "sys.stdin.buffer.readlines",
    ];
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let reads_input = is_call_method(call, "input")
            && matches!(call.func.as_ref(), Expr::Name(_))
            || call_path_matches(call, &STDIN_READERS, &[], &[]);
        if reads_input {
            issues.push(issue_at(
                "python:S4829",
                "Make sure that reading the standard input is safe here.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
