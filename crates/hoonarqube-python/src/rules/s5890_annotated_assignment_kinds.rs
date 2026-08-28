use crate::engine::calls::concrete_hint;
use crate::engine::calls::hint_accepts_literal;
use crate::engine::file_context::FileContext;
use crate::support::expr_normalized_text;
use crate::support::issue_at;
use crate::support::typed_literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5890 — assigned values should match their annotations -----------

/// python:S5890 — flags `x: T = <literal>` assignments whose literal kind
/// provably contradicts the simple concrete annotation `T`.
pub(crate) fn check_s5890_annotated_assignment_kinds(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::AnnAssign(assign) = stmt else {
            continue;
        };
        let Some(value) = assign.value.as_deref() else {
            continue;
        };
        let Some(hint) = concrete_hint(&assign.annotation) else {
            continue;
        };
        let Some(kind) = typed_literal_kind(value) else {
            continue;
        };
        if hint_accepts_literal(hint, kind) {
            continue;
        }
        let annotation_text = expr_normalized_text(&assign.annotation, source);
        let target_text = expr_normalized_text(&assign.target, source);
        let actual_type = match kind {
            "string" => "str",
            "boolean" => "bool",
            "none" => "None",
            other => other,
        };
        issues.push(issue_at(
            "python:S5890",
            &format!(
                "Assign to \"{target_text}\" a value of type \"{annotation_text}\" instead of \"{actual_type}\" or update its type hint."
            ),
            value.range(),
            index,
            source,
        ));
    }
    issues
}
