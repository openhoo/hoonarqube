use crate::engine::file_context::FileContext;
use crate::support::exprs_textually_equal;
use crate::support::is_assignable_shape;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1656 — self-assignment ------------------------------------------

pub(crate) fn check_self_assignment(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        match stmt {
            Stmt::Assign(assign) => {
                if assign.targets.iter().any(|target| {
                    is_assignable_shape(target)
                        && exprs_textually_equal(target, &assign.value, source)
                }) {
                    let operator_start = assign
                        .targets
                        .last()
                        .map_or(assign.start(), ruff_text_size::Ranged::end);
                    let between = &source
                        [ruff_text_size::TextRange::new(operator_start, assign.value.start())];
                    let relative = between.find('=').expect("assignment operator");
                    let equals = operator_start
                        + ruff_text_size::TextSize::from(crate::support::to_u32(relative));
                    issues.push(issue_at(
                        "python:S1656",
                        "Remove or correct this useless self-assignment.",
                        ruff_text_size::TextRange::new(
                            equals,
                            equals + ruff_text_size::TextSize::new(1),
                        ),
                        index,
                        source,
                    ));
                }
            }
            Stmt::AnnAssign(annotated) => {
                if let Some(value) = annotated.value.as_deref()
                    && is_assignable_shape(&annotated.target)
                    && exprs_textually_equal(&annotated.target, value, source)
                {
                    issues.push(issue_at(
                        "python:S1656",
                        "Remove or correct this useless self-assignment.",
                        annotated.range(),
                        index,
                        source,
                    ));
                }
            }
            _ => {}
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s1656_flags_self_assignment() {
        assert_eq!(findings(&scan("x = x\n"), "python:S1656").len(), 1);
        assert_eq!(findings(&scan("x.y = x.y\n"), "python:S1656").len(), 1);
        assert!(findings(&scan("x = y\n"), "python:S1656").is_empty());
    }
}
