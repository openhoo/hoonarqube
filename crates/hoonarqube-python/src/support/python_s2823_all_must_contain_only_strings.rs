// --- python:S2823 — `__all__` must contain only strings

use crate::support::{
    called_name, child_bodies, is_zero_literal, issue_at, ranges_textually_equal, suite_span,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn is_dunder_all_target(expr: &Expr) -> bool {
    matches!(expr, Expr::Name(name) if name.id.as_str() == "__all__")
}

pub(crate) fn flag_trailing_continue(
    body: &[Stmt],
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if let Some(Stmt::Continue(last)) = body.last() {
        issues.push(issue_at(
            "python:S3626",
            "Remove this redundant jump statement.",
            last.range(),
            index,
            source,
        ));
    }
}

pub(crate) fn len_zero_verdict(left: &Expr, comparator: &Expr, op: ruff_python_ast::CmpOp) -> bool {
    is_len_call(left)
        && is_zero_literal(comparator)
        && matches!(
            op,
            ruff_python_ast::CmpOp::GtE | ruff_python_ast::CmpOp::Lt | ruff_python_ast::CmpOp::LtE
        )
}

pub(crate) fn len_zero_verdict_swapped(
    left: &Expr,
    comparator: &Expr,
    op: ruff_python_ast::CmpOp,
) -> bool {
    is_len_call(comparator)
        && is_zero_literal(left)
        && matches!(
            op,
            ruff_python_ast::CmpOp::LtE | ruff_python_ast::CmpOp::Gt | ruff_python_ast::CmpOp::GtE
        )
}

fn is_len_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(call) if called_name(&call.func) == Some("len") && call.arguments.args.len() == 1)
}

pub(crate) fn is_jump_terminator(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Return(_) | Stmt::Raise(_) | Stmt::Break(_) | Stmt::Continue(_)
    )
}

/// RSPEC exempts trivially true identities over the `0`/`1` literals.
pub(crate) fn excluded_identical_pair(left: &Expr, right: &Expr) -> bool {
    is_small_int_literal(left) && is_small_int_literal(right)
}

fn is_small_int_literal(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::NumberLiteral(number)
            if matches!(&number.value, ruff_python_ast::Number::Int(value) if matches!(value.as_u8(), Some(0 | 1)))
    )
}

pub(crate) fn flag_duplicate_branches(
    branches: &[&[Stmt]],
    rule_key: &str,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for (later_index, later) in branches.iter().enumerate() {
        for earlier in &branches[..later_index] {
            if ranges_textually_equal(suite_span(later), suite_span(earlier), source) {
                issues.push(issue_at(
                    rule_key,
                    "This branch duplicates an earlier one; merge them or change one implementation.",
                    suite_span(later),
                    index,
                    source,
                ));
                break;
            }
        }
    }
}

pub(crate) fn is_assignable_shape(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Name(_) | Expr::Attribute(_) | Expr::Subscript(_)
    )
}

pub(crate) fn flag_comprehension_walrus(
    element: &Expr,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if matches!(element, Expr::Named(_)) {
        issues.push(issue_at(
            "python:S5685",
            "Move this walrus operator to a clearer location.",
            element.range(),
            index,
            source,
        ));
    }
}

pub(crate) fn is_freshly_created(expr: &Expr) -> bool {
    match expr {
        Expr::List(_)
        | Expr::Set(_)
        | Expr::Tuple(_)
        | Expr::Dict(_)
        | Expr::ListComp(_)
        | Expr::SetComp(_)
        | Expr::DictComp(_)
        | Expr::Generator(_) => true,
        Expr::Call(call) => matches!(
            called_name(&call.func),
            Some("list" | "dict" | "set" | "tuple" | "frozenset")
        ),
        _ => false,
    }
}

pub(crate) fn is_type_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(call)
        if called_name(&call.func) == Some("type")
            && call.arguments.args.len() == 1
            && call.arguments.keywords.is_empty())
}

pub(crate) fn is_boundary_slice(expr: &Expr) -> bool {
    let Expr::Subscript(subscript) = expr else {
        return false;
    };
    let Expr::Slice(slice) = subscript.slice.as_ref() else {
        return false;
    };
    if slice.step.is_some() {
        return false;
    }
    match (&slice.lower, &slice.upper) {
        (None, Some(_)) => true,
        (Some(bound), None) => {
            matches!(bound.as_ref(), Expr::UnaryOp(unary)
                if unary.op == ruff_python_ast::UnaryOp::USub
                    && matches!(unary.operand.as_ref(), Expr::NumberLiteral(_)))
        }
        _ => false,
    }
}

pub(crate) fn visit_suites_for_no_effect(
    suite: &[Stmt],
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for (position, stmt) in suite.iter().enumerate() {
        if let Stmt::Expr(value) = stmt
            && !(position == 0 && matches!(value.value.as_ref(), Expr::StringLiteral(_)))
            && statement_has_no_effect(&value.value)
        {
            issues.push(issue_at(
                "python:S905",
                "Remove this statement; it has no effect.",
                stmt.range(),
                index,
                source,
            ));
        }
        for body in child_bodies(stmt) {
            visit_suites_for_no_effect(body, issues, index, source);
        }
    }
}

fn statement_has_no_effect(expr: &Expr) -> bool {
    match expr {
        Expr::NoneLiteral(_)
        | Expr::BooleanLiteral(_)
        | Expr::NumberLiteral(_)
        | Expr::StringLiteral(_)
        | Expr::BytesLiteral(_)
        | Expr::EllipsisLiteral(_)
        | Expr::Name(_) => true,
        Expr::Tuple(tuple) => tuple.elts.iter().all(statement_has_no_effect),
        Expr::List(list) => list.elts.iter().all(statement_has_no_effect),
        Expr::Set(set) => set.elts.iter().all(statement_has_no_effect),
        Expr::Dict(dict) => dict.items.iter().all(|item| {
            item.key.as_ref().is_none_or(statement_has_no_effect)
                && statement_has_no_effect(&item.value)
        }),
        Expr::UnaryOp(unary) => statement_has_no_effect(&unary.operand),
        Expr::BinOp(binary) => {
            statement_has_no_effect(&binary.left) && statement_has_no_effect(&binary.right)
        }
        Expr::BoolOp(boolean) => boolean.values.iter().all(statement_has_no_effect),
        Expr::Compare(compare) => {
            statement_has_no_effect(&compare.left)
                && compare.comparators.iter().all(statement_has_no_effect)
        }
        _ => false,
    }
}

/// Names caught by an except type expression (`Name`, attribute tail, or any
/// element of a tuple).
pub(crate) fn exception_type_names(type_expr: Option<&Expr>) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(expr) = type_expr {
        collect_exception_names(expr, &mut names);
    }
    names
}

fn collect_exception_names(expr: &Expr, names: &mut Vec<String>) {
    match expr {
        Expr::Name(name) => names.push(name.id.to_string()),
        Expr::Attribute(attribute) => names.push(attribute.attr.to_string()),
        Expr::Tuple(tuple) => {
            for element in &tuple.elts {
                collect_exception_names(element, names);
            }
        }
        _ => {}
    }
}
