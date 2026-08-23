use crate::support::PUBLIC_TEMP_PREFIXES;
use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s5443_public_temp_files(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let public_temp = called_name(&call.func) == Some("open")
            && call
                .arguments
                .args
                .first()
                .and_then(string_literal_text)
                .is_some_and(|path| {
                    PUBLIC_TEMP_PREFIXES
                        .iter()
                        .any(|prefix| path.starts_with(prefix))
                });
        if public_temp {
            issues.push(issue_at(
                "python:S5443",
                "Create this temporary file in a directory with restricted permissions.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
