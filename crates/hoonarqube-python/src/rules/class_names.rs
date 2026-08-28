use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::matches_class_name;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// Class names at any nesting depth are python:S101.
pub(crate) fn check_class_names(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::ClassDef(class) = stmt else {
            continue;
        };
        if !matches_class_name(class.name.as_str()) {
            issues.push(issue_at(
                "python:S101",
                &format!(
                    "Rename class \"{}\" to match the regular expression \
                     ^_?([A-Z_][a-zA-Z0-9]*|[a-z_][a-z0-9_]*)$.",
                    class.name
                ),
                class.name.range(),
                index,
                source,
            ));
        }
    }
    issues
}
