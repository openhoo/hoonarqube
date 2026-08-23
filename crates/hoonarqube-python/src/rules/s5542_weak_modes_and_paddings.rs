use crate::support::WEAK_MODE_OR_PADDING_NAMES;
use crate::support::for_each_attr_load;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s5542_weak_modes_and_paddings(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for name in WEAK_MODE_OR_PADDING_NAMES {
        for_each_attr_load(parsed.syntax().body.as_slice(), name, |attr| {
            issues.push(issue_at(
                "python:S5542",
                "Replace this weak cipher mode or padding scheme.",
                attr.range(),
                index,
                source,
            ));
        });
    }
    issues
}
