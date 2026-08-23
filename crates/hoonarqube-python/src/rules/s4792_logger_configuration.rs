use crate::support::call_path_matches;
use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::is_call_method;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S4792 — configuring loggers is security-sensitive ----------------

pub(crate) fn check_s4792_logger_configuration(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const LOGGER_CONFIG_APIS: [&str; 3] = [
        "logging.config.dictConfig",
        "logging.config.fileConfig",
        "logging.config.listen",
    ];
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let configured = call_path_matches(call, &LOGGER_CONFIG_APIS, &[], &[])
            || (is_call_method(call, "basicConfig") && has_keyword(&call.arguments, "handlers"));
        if configured {
            issues.push(issue_at(
                "python:S4792",
                "Make sure that configuring loggers is safe here.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
