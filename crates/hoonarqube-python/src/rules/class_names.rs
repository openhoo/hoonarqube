use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::matches_class_name;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// Class names at any nesting depth are python:S101.
pub(crate) fn check_class_names(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::ClassDef(class) = stmt else {
            return;
        };
        if !matches_class_name(class.name.as_str()) {
            issues.push(issue_at(
                "python:S101",
                "Rename this class to match the regular expression \
                     '^_?([A-Z_][a-zA-Z0-9]*|[a-z_][a-z0-9_]*)$'.",
                class.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}
