use crate::support::for_each_stmt;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

/// python:S2757 — `x =+ 1` / `x =- 1` non-existent operators.
///
/// The reference only inspects assignment statements (`x =- y`), never
/// parameter defaults or annotations. It reports when `=` is immediately
/// followed by the unary sign, except for the idiomatic `x=-1` shape where
/// `=` is glued to the variable AND the sign is glued to its operand.
pub(crate) fn check_assign_plus_minus(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::Assign(assign) = stmt else {
            return;
        };
        let Some(Expr::UnaryOp(unary)) = Some(assign.value.as_ref()) else {
            return;
        };
        if !matches!(
            unary.op,
            ruff_python_ast::UnaryOp::UAdd | ruff_python_ast::UnaryOp::USub
        ) {
            return;
        }
        let Some(first_target) = assign.targets.first() else {
            return;
        };
        // The gap between the target and the unary sign must contain exactly
        // one `=` (chained `x = y =- 1` is exempt in the reference).
        let gap = &source[TextRange::new(first_target.end(), unary.start())];
        if gap.matches('=').count() != 1 {
            return;
        }
        let sign = if matches!(unary.op, ruff_python_ast::UnaryOp::UAdd) {
            '+'
        } else {
            '-'
        };
        // `x=-1`: `=` glued to the variable and `-` glued to the operand is
        // the conventional tight form and stays clean.
        let glued_to_variable =
            gap.trim_end() == "=" && gap.ends_with('=') && gap.len() == gap.trim_end().len();
        let sign_glued_to_operand = unary.operand.start() == unary.start() + TextSize::new(1);
        if glued_to_variable && sign_glued_to_operand {
            return;
        }
        // Only `=-`/`=+` glued together is reported.
        let Some(eq_pos) = gap.find('=') else {
            return;
        };
        let after_eq = &gap[eq_pos + 1..];
        if !after_eq.is_empty() {
            return;
        }
        issues.push(Issue {
            rule_key: "python:S2757".to_string(),
            message: format!("Was {sign}= meant instead?"),
            range: to_range(
                TextRange::new(
                    unary.start() - TextSize::new(1),
                    unary.start() + TextSize::new(1),
                ),
                index,
                source,
            ),
            fix: None,
            flows: Vec::new(),
            alternatives: Vec::new(),
        });
    });
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s2757_flags_reversed_compound_assignment_tokens() {
        let bad = scan("value =+ 1\nvalue =- 1\n");
        assert_eq!(findings(&bad, "python:S2757").len(), 2);

        let good = scan("value += 1\nvalue -= 1\n");
        assert!(findings(&good, "python:S2757").is_empty());
    }
}
