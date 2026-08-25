// --- python:S930 — call arguments should match parameters

use crate::engine::calls::concrete_hint;
use crate::engine::calls::hint_accepts_literal;
use crate::support::{expr_normalized_text, issue_at, typed_literal_kind};
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// Positional parameter entries of a signature, optionally skipping the
/// leading bound parameter (`self`/`cls`).
pub(crate) fn parameter_entries(
    parameters: &ruff_python_ast::Parameters,
    skip_receiver: bool,
) -> Vec<&ruff_python_ast::ParameterWithDefault> {
    let all: Vec<&ruff_python_ast::ParameterWithDefault> = parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .collect();
    if skip_receiver && !all.is_empty() {
        all.into_iter().skip(1).collect()
    } else {
        all
    }
}

/// Flags one literal argument whose kind contradicts the parameter's simple
/// concrete annotation.
pub(crate) fn s5655_check_argument(
    entry: &ruff_python_ast::ParameterWithDefault,
    argument: &Expr,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let Some(annotation) = entry.parameter.annotation.as_deref() else {
        return;
    };
    let Some(hint) = concrete_hint(annotation) else {
        return;
    };
    let Some(kind) = typed_literal_kind(argument) else {
        return;
    };
    if hint_accepts_literal(hint, kind) {
        return;
    }
    let annotation_text = expr_normalized_text(annotation, source);
    issues.push(issue_at(
        "python:S5655",
        &format!("This argument does not match the '{annotation_text}' parameter type."),
        argument.range(),
        index,
        source,
    ));
}
