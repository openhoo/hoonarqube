use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::StmtClassDef;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1722 — old-style class declarations --------------------------------

pub(crate) fn check_old_style_classes(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut visit = |stmt: &ruff_python_ast::Stmt| {
        if let ruff_python_ast::Stmt::ClassDef(class) = stmt {
            flag_empty_bases(class, &mut issues, index, source);
        }
    };
    for_each_stmt(parsed.syntax().body.as_slice(), &mut visit);
    issues
}

/// A class with an empty base list and no keywords resolves to the legacy
/// `object`-less form; inheriting explicitly documents the new-style choice.
fn flag_empty_bases(
    class: &StmtClassDef,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let bases_empty = match class.arguments.as_deref() {
        None => true,
        Some(arguments) => arguments.args.is_empty() && arguments.keywords.is_empty(),
    };
    if bases_empty {
        issues.push(issue_at(
            "python:S1722",
            "Define this class as a new-style class by inheriting from 'object'.",
            class.name.range(),
            index,
            source,
        ));
    }
}
