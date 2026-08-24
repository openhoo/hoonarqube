use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::is_false_literal;
use crate::support::is_none_literal;
use crate::support::is_true_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_imprecise_assertions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if let Some(better) = preferred_assertion(call) {
            issues.push(issue_at(
                "python:S5906",
                &format!("Use {better} for this assertion."),
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- migrated from support/mod.rs (S5906) ---
// --- python:S5906 / python:S5914 — imprecise and unconditional asserts ---------------

pub(crate) fn preferred_assertion(call: &ruff_python_ast::ExprCall) -> Option<&'static str> {
    let args = &call.arguments.args;
    match called_name(&call.func) {
        Some("assertEqual" | "assertNotEqual") if args.len() == 2 => {
            let negated = called_name(&call.func) == Some("assertNotEqual");
            for pair in [(0, 1), (1, 0)] {
                let other = &args[pair.1];
                if is_true_literal(other) {
                    return Some(if negated { "assertFalse" } else { "assertTrue" });
                }
                if is_false_literal(other) {
                    return Some(if negated { "assertTrue" } else { "assertFalse" });
                }
                if is_none_literal(other) {
                    return Some(if negated {
                        "assertIsNotNone"
                    } else {
                        "assertIsNone"
                    });
                }
            }
            None
        }
        Some("assertTrue") if args.len() == 1 => match &args[0] {
            Expr::Compare(compare) if compare.ops.len() == 1 => match compare.ops[0] {
                ruff_python_ast::CmpOp::Eq => Some("assertEqual"),
                ruff_python_ast::CmpOp::NotEq => Some("assertNotEqual"),
                ruff_python_ast::CmpOp::Is => Some("assertIs"),
                ruff_python_ast::CmpOp::IsNot => Some("assertIsNot"),
                ruff_python_ast::CmpOp::In => Some("assertIn"),
                ruff_python_ast::CmpOp::NotIn => Some("assertNotIn"),
                _ => None,
            },
            _ => None,
        },
        Some("assertFalse") if args.len() == 1 => match &args[0] {
            Expr::Compare(compare)
                if compare.ops.len() == 1 && compare.ops[0] == ruff_python_ast::CmpOp::In =>
            {
                Some("assertNotIn")
            }
            _ => None,
        },
        _ => None,
    }
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
        assert_eq!(findings(&flagged, "python:S5906").len(), 3);
    }
}
