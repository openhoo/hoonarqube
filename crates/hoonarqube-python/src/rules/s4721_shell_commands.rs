use crate::support::call_path_matches;
use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::is_call_method;
use crate::support::is_true_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S4721 — OS commands should not run through a shell interpreter ---

pub(crate) fn check_s4721_shell_commands(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const SHELL_RUNNERS: [&str; 2] = ["os.system", "os.popen"];
    const SUBPROCESS_LAUNCHERS: [&str; 6] = [
        "run",
        "Popen",
        "call",
        "check_call",
        "check_output",
        "getoutput",
    ];
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let shells_out = call_path_matches(call, &SHELL_RUNNERS, &[], &[]);
        let forces_shell = is_call_method(call, "getoutput")
            || (SUBPROCESS_LAUNCHERS.contains(&called_name(&call.func).unwrap_or_default())
                && keyword_value(&call.arguments, "shell").is_some_and(is_true_literal));
        if shells_out || forces_shell {
            issues.push(issue_at(
                "python:S4721",
                "Remove this use of a shell interpreter.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
