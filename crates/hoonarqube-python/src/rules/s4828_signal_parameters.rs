use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::int_literal_value;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S4828 — OS process signal parameters validated ----------------------

pub(crate) fn check_s4828_signal_parameters(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let raw_signal = match called_name(&call.func) {
            Some("signal") => call.arguments.args.first().and_then(int_literal_value),
            Some("kill") => call.arguments.args.get(1).and_then(int_literal_value),
            _ => None,
        }
        .is_some();
        if raw_signal {
            issues.push(issue_at(
                "python:S4828",
                "Validate this signal parameter against the symbolic SIG constants.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
