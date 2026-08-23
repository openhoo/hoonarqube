use crate::engine::calls::concrete_hint;
use crate::engine::calls::hint_accepts_literal;
use crate::support::expr_normalized_text;
use crate::support::for_each_return_in_scope;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::typed_literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5886 — return types should be consistent with the hint ----------

/// python:S5886 — flags `return <literal>` statements whose literal kind
/// provably contradicts the file-local function's simple concrete `-> T` hint.
pub(crate) fn check_s5886_return_hint_mismatches(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::FunctionDef(function) = stmt else {
            return;
        };
        let Some(annotation) = function.returns.as_deref() else {
            return;
        };
        let Some(hint) = concrete_hint(annotation) else {
            return;
        };
        let annotation_text = expr_normalized_text(annotation, source);
        for_each_return_in_scope(&function.body, &mut |returned| {
            let Some(value) = returned.value.as_deref() else {
                return;
            };
            let Some(kind) = typed_literal_kind(value) else {
                return;
            };
            if hint_accepts_literal(hint, kind) {
                return;
            }
            issues.push(issue_at(
                "python:S5886",
                &format!(
                    "This return value does not match the '{annotation_text}' \
                     return type."
                ),
                value.range(),
                index,
                source,
            ));
        });
    });
    issues
}
