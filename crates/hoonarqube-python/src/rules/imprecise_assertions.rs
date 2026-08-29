use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::is_false_literal;
use crate::support::is_none_literal;
use crate::support::is_true_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_imprecise_assertions(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if let Some(better) = preferred_assertion(call) {
            issues.push(issue_at(
                "python:S5906",
                &format!("Use '{better}' for this assertion."),
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S5906 / python:S5914 — imprecise and unconditional asserts ---------------

fn preferred_assertion(call: &ruff_python_ast::ExprCall) -> Option<&'static str> {
    let args = &call.arguments.args;
    match called_name(&call.func) {
        Some("assertEqual" | "assertNotEqual") if args.len() == 2 => {
            preferred_equality_assertion(args, called_name(&call.func) == Some("assertNotEqual"))
        }
        Some("assertTrue") if args.len() == 1 => preferred_true_assertion(&args[0]),
        Some("assertFalse") if args.len() == 1 => preferred_false_assertion(&args[0]),
        _ => None,
    }
}

fn preferred_equality_assertion(args: &[Expr], negated: bool) -> Option<&'static str> {
    [&args[1], &args[0]]
        .into_iter()
        .find_map(|other| literal_assertion(other, negated))
}

fn literal_assertion(other: &Expr, negated: bool) -> Option<&'static str> {
    match (
        negated,
        is_true_literal(other),
        is_false_literal(other),
        is_none_literal(other),
    ) {
        (false, true, _, _) | (true, _, true, _) => Some("assertTrue"),
        (true, true, _, _) | (false, _, true, _) => Some("assertFalse"),
        (false, _, _, true) => Some("assertIsNone"),
        (true, _, _, true) => Some("assertIsNotNone"),
        _ => None,
    }
}

fn preferred_true_assertion(expression: &Expr) -> Option<&'static str> {
    let Expr::Compare(compare) = expression else {
        return None;
    };
    let [operator] = compare.ops.as_ref() else {
        return None;
    };
    match operator {
        ruff_python_ast::CmpOp::Eq => Some("assertEqual"),
        ruff_python_ast::CmpOp::NotEq => Some("assertNotEqual"),
        ruff_python_ast::CmpOp::Is => Some("assertIs"),
        ruff_python_ast::CmpOp::IsNot => Some("assertIsNot"),
        ruff_python_ast::CmpOp::In => Some("assertIn"),
        ruff_python_ast::CmpOp::NotIn => Some("assertNotIn"),
        _ => None,
    }
}

fn preferred_false_assertion(expression: &Expr) -> Option<&'static str> {
    let Expr::Compare(compare) = expression else {
        return None;
    };
    matches!(compare.ops.as_ref(), [ruff_python_ast::CmpOp::In]).then_some("assertNotIn")
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5906_suggests_specific_assertions() {
        let flagged = scan(concat!(
            "case.assertEqual(x, True)\n",
            "case.assertTrue(x == y)\n",
            "case.assertFalse(a in b)\n",
            "case.assertEqual(x, y)\n"
        ));
        let flagged_findings = findings(&flagged, "python:S5906");
        assert_eq!(flagged_findings.len(), 3);
        assert!(
            flagged_findings
                .iter()
                .any(|issue| issue.message == "Use 'assertTrue' for this assertion.")
        );
    }
}
