use crate::engine::calls::concrete_hint;
use crate::engine::calls::hint_accepts_literal;
use crate::support::expr_normalized_text;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::typed_literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5890 — assigned values should match their annotations -----------

/// python:S5890 — flags `x: T = <literal>` assignments whose literal kind
/// provably contradicts the simple concrete annotation `T`.
pub(crate) fn check_s5890_annotated_assignment_kinds(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::AnnAssign(assign) = stmt else {
            return;
        };
        let Some(value) = assign.value.as_deref() else {
            return;
        };
        let Some(hint) = concrete_hint(&assign.annotation) else {
            return;
        };
        let Some(kind) = typed_literal_kind(value) else {
            return;
        };
        if hint_accepts_literal(hint, kind) {
            return;
        }
        let annotation_text = expr_normalized_text(&assign.annotation, source);
        issues.push(issue_at(
            "python:S5890",
            &format!("This value does not match the '{annotation_text}' annotation."),
            value.range(),
            index,
            source,
        ));
    });
    issues
}
