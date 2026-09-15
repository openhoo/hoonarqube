// Rule module s7759_prefer_date_now (generated).
//
// `javascript:S7759` + `typescript:S7759` — `Date.now()` should be used
// instead of creating Date objects to get the current timestamp.
// Reference semantics: eslint-plugin-unicorn `prefer-date-now` at the
// version pinned by SonarJS 13.x (v65.0.1, wrapped by SonarJS S7759 with
// the polyfill decorator):
//
// - `new Date().getTime()` / `new Date().valueOf()` report the method
//   property with "Prefer `Date.now()` over `Date#<method>()`.";
// - `Number(new Date())` reports the call with "Prefer `Date.now()` over
//   `Number(new Date())`."; `BigInt(new Date())` reports the `new Date()`
//   argument with "Prefer `Date.now()` over `new Date()`.";
// - `+new Date()` reports the unary expression and `-new Date()` reports
//   the `new Date()` operand with the default message;
// - `new Date()` as an operand of `-=`, `*=`, `/=`, `%=`, `**=` or of a
//   `-`, `*`, `/`, `%`, `**` binary expression reports the `new Date()`;
// - the SonarJS decorator suppresses reports inside `Date.now` polyfill
//   fallbacks: the right side of `Date.now || …`, the alternate of
//   `Date.now ? … : …`, and the consequent of `if (!Date.now) { Date.now =
//   … }`.
//
// `new Date(args)` with arguments and `Date().getTime()` stay silent; the
// reference is fixable but no auto-fix is offered here.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    AssignmentOperator, AssignmentTarget, BinaryOperator, CallExpression, Expression,
    LogicalOperator, Statement, UnaryOperator,
};
use oxc_semantic::{AstNode, Semantic};
use oxc_span::{GetSpan, Span};

/// Entry point: `javascript:S7759` + `typescript:S7759` prefer-date-now
/// check over the parsed program.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    let Some(semantic) = ctx.semantic else {
        return sink.issues;
    };
    for node in semantic.nodes().iter() {
        match node.kind() {
            AstKind::CallExpression(call) => check_call(&mut sink, semantic, node, call),
            AstKind::UnaryExpression(unary) => check_unary(&mut sink, semantic, node, unary),
            AstKind::AssignmentExpression(assignment) => {
                check_assignment(&mut sink, semantic, node, assignment);
            }
            AstKind::BinaryExpression(binary) => {
                check_binary(&mut sink, semantic, node, binary);
            }
            _ => {}
        }
    }
    sink.issues
}

/// `new Date()` with no arguments (the reference `isNewDate`).
fn is_new_date(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::NewExpression(new) => {
            new.arguments.is_empty()
                && matches!(unparenthesized(&new.callee), Expression::Identifier(callee) if callee.name == "Date")
        }
        _ => false,
    }
}

fn emit(sink: &mut IssueSink<'_>, span: Span, message: &str) {
    sink.emit_span(RuleScope::Both, "S7759", message, span);
}

fn check_call(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    call: &CallExpression<'_>,
) {
    // `new Date().{getTime,valueOf}()`
    if !call.optional
        && let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee)
        && !member.optional
        && matches!(member.property.name.as_str(), "getTime" | "valueOf")
        && call.arguments.is_empty()
        && is_new_date(&member.object)
        && !inside_polyfill(semantic, node)
    {
        let method = member.property.name.as_str();
        let message = match method {
            "getTime" => "Prefer `Date.now()` over `Date#getTime()`.",
            _ => "Prefer `Date.now()` over `Date#valueOf()`.",
        };
        emit(sink, member.property.span(), message);
        return;
    }
    // `{Number,BigInt}(new Date())`
    if call.optional || call.arguments.len() != 1 {
        return;
    }
    let Some(argument) = call.arguments[0].as_expression() else {
        return;
    };
    if !is_new_date(argument) {
        return;
    }
    let Some(name) = (match unparenthesized(&call.callee) {
        Expression::Identifier(identifier) => Some(identifier.name.as_str()),
        _ => None,
    }) else {
        return;
    };
    match name {
        "Number" if !inside_polyfill(semantic, node) => emit(
            sink,
            call.span(),
            "Prefer `Date.now()` over `Number(new Date())`.",
        ),
        "BigInt" if !inside_polyfill(semantic, node) => emit(
            sink,
            argument.span(),
            "Prefer `Date.now()` over `new Date()`.",
        ),
        _ => {}
    }
}

fn check_unary(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    unary: &oxc_ast::ast::UnaryExpression<'_>,
) {
    if !matches!(
        unary.operator,
        UnaryOperator::UnaryPlus | UnaryOperator::UnaryNegation
    ) || !is_new_date(&unary.argument)
        || inside_polyfill(semantic, node)
    {
        return;
    }
    // `+new Date()` reports the unary; `-new Date()` reports the operand.
    let span = if unary.operator == UnaryOperator::UnaryNegation {
        unary.argument.span()
    } else {
        unary.span()
    };
    emit(sink, span, "Prefer `Date.now()` over `new Date()`.");
}

fn check_assignment(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    assignment: &oxc_ast::ast::AssignmentExpression<'_>,
) {
    if !matches!(
        assignment.operator,
        AssignmentOperator::Subtraction
            | AssignmentOperator::Multiplication
            | AssignmentOperator::Division
            | AssignmentOperator::Remainder
            | AssignmentOperator::Exponential
    ) || !is_new_date(&assignment.right)
        || inside_polyfill(semantic, node)
    {
        return;
    }
    emit(
        sink,
        assignment.right.span(),
        "Prefer `Date.now()` over `new Date()`.",
    );
}

fn check_binary(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    binary: &oxc_ast::ast::BinaryExpression<'_>,
) {
    if !matches!(
        binary.operator,
        BinaryOperator::Subtraction
            | BinaryOperator::Multiplication
            | BinaryOperator::Division
            | BinaryOperator::Remainder
            | BinaryOperator::Exponential
    ) || inside_polyfill(semantic, node)
    {
        return;
    }
    for operand in [&binary.left, &binary.right] {
        if is_new_date(operand) {
            emit(
                sink,
                operand.span(),
                "Prefer `Date.now()` over `new Date()`.",
            );
        }
    }
}

fn inside_polyfill(semantic: &Semantic<'_>, node: &AstNode<'_>) -> bool {
    let nodes = semantic.nodes();
    let mut current = node.id();
    loop {
        let parent = nodes.parent_node(current);
        if parent.id() == current {
            return false;
        }
        if is_polyfill_ancestor(nodes, node, parent) {
            return true;
        }
        current = parent.id();
    }
}

/// One ancestor's polyfill shape: `Date.now || <node>`,
/// `Date.now ? … : <node>`, or `if (!Date.now) { Date.now = <node…> }`.
fn is_polyfill_ancestor(
    _nodes: &oxc_semantic::AstNodes<'_>,
    node: &AstNode<'_>,
    ancestor: &AstNode<'_>,
) -> bool {
    match ancestor.kind() {
        AstKind::LogicalExpression(logical) => {
            logical.operator == LogicalOperator::Or
                && is_date_now_member(&logical.left)
                && inside_span(node, logical.right.span())
        }
        AstKind::ConditionalExpression(conditional) => {
            is_date_now_member(&conditional.test) && inside_span(node, conditional.alternate.span())
        }
        AstKind::IfStatement(statement) => {
            is_negated_date_now(&statement.test)
                && contains_date_now_assignment(&statement.consequent)
                && inside_span(node, statement.consequent.span())
        }
        _ => false,
    }
}

/// Whether `node`'s span lies inside `span` (descendant-or-self).
fn inside_span(node: &AstNode<'_>, span: Span) -> bool {
    let node_span = node.kind().span();
    node_span.start >= span.start && node_span.end <= span.end
}

/// `Date.now` as a member expression.
fn is_date_now_member(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::StaticMemberExpression(member) => {
            member.property.name == "now"
                && matches!(unparenthesized(&member.object), Expression::Identifier(object) if object.name == "Date")
        }
        _ => false,
    }
}

/// `!Date.now`.
fn is_negated_date_now(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::UnaryExpression(unary) => {
            unary.operator == UnaryOperator::LogicalNot && is_date_now_member(&unary.argument)
        }
        _ => false,
    }
}

/// Whether a statement (or block) contains an assignment to `Date.now`.
fn contains_date_now_assignment(statement: &Statement<'_>) -> bool {
    match statement {
        Statement::ExpressionStatement(expression) => {
            match unparenthesized(&expression.expression) {
                Expression::AssignmentExpression(assignment) => {
                    date_now_assignment_target(&assignment.left)
                }
                _ => false,
            }
        }
        Statement::BlockStatement(block) => block.body.iter().any(contains_date_now_assignment),
        _ => false,
    }
}

fn date_now_assignment_target(target: &AssignmentTarget<'_>) -> bool {
    match target {
        AssignmentTarget::StaticMemberExpression(member) => {
            member.property.name == "now"
                && matches!(&member.object, Expression::Identifier(object) if object.name == "Date")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7759_flags_new_date_timestamp_forms() {
        let source = "\
const a = new Date().getTime();
const b = new Date().valueOf();
const c = +new Date();
const d = -new Date();
const e = Number(new Date());
const f = BigInt(new Date());
let g = 0;
g -= new Date();
const h = 5 - new Date();
const i = new Date() * 2;
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7759"), 9);
    }

    #[test]
    fn s7759_flags_typescript_too() {
        let source = "const stamp: number = new Date().getTime();\n";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7759"), 1);
    }

    #[test]
    fn s7759_suppresses_date_now_polyfills() {
        let source = "\
const now = Date.now || function() { return new Date().getTime(); };
const stamp = Date.now ? Date.now() : +(new Date());
if (!Date.now) {
  Date.now = function() {
    return new Date().getTime();
  };
}
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7759"), 0);
    }

    #[test]
    fn s7759_ignores_other_date_forms() {
        let source = "\
const a = Date.now();
const b = new Date(2020, 1, 1).getTime();
const c = new Date().toISOString();
const d = new Date();
const e = Number('42');
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7759"), 0);
    }
}
