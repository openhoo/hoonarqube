// Rule module s7775_prefer_regexp_test (generated).
//
// `javascript:S7775` + `typescript:S7775` — `RegExp.test()` should be
// used instead of `String.match()` or `RegExp.exec()` when only checking
// for pattern existence. Reference semantics: eslint-plugin-unicorn
// `prefer-regexp-test` at the version pinned by SonarJS 13.x (v65.0.1,
// wrapped by SonarJS S7775): a one-argument, non-optional `x.exec(str)`
// or `str.match(re)` call is reported when the result is used only as a
// boolean — directly as a control-flow test (`if`/`while`/`do`/`for`/
// ternary), inside `!`/`Boolean(...)` coercion, inside a `&&`/`||` chain
// feeding one of those, or through a `.length` read used the same way
// (including `.length > 0`). `x.exec` reports the `exec` property with
// "Prefer `.test(…)` over `.exec(…)`."; `x.match` reports the whole call
// with "Prefer `RegExp#test(…)` over `String#match(…)`.".
//
// A non-regex string literal argument (`str.match('text')`) stays silent,
// and `slice.actions.x.match(re)` (the Redux Toolkit action-matcher
// shape) stays silent when the argument is not a known regex. A `.length`
// chain that is itself negated (`!x.match(re).length`) stays silent.
// Static-value resolution of regex variables is outside the single-file
// subset; the fix/suggestion split is irrelevant because no auto-fix is
// offered.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{CallExpression, Expression, LogicalOperator, UnaryOperator};
use oxc_semantic::{AstNode, Semantic};
use oxc_span::GetSpan;

/// Entry point: `javascript:S7775` + `typescript:S7775`
/// prefer-regexp-test check over the parsed program. Requires the
/// semantic model for parent links, so recoverable-parse files stay
/// silent.
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
        check_call(&mut sink, semantic, node);
    }
    sink.issues
}

/// Per-call check: boolean-context `exec`/`match` calls are reported.
fn check_call(sink: &mut IssueSink<'_>, semantic: &Semantic<'_>, node: &AstNode<'_>) {
    let AstKind::CallExpression(call) = node.kind() else {
        return;
    };
    if get_length_check(semantic, node).is_none()
        && !(is_boolean_expression(semantic, node) || is_control_flow_test(semantic, node))
    {
        return;
    }
    let Some(member) = method_member(call) else {
        return;
    };
    if call.optional || call.arguments.len() != 1 {
        return;
    }
    let Some(argument) = call.arguments[0].as_expression() else {
        return;
    };
    match member.property.name.as_str() {
        "exec" => {
            if is_non_regex_literal(&member.object) {
                return;
            }
            sink.emit_span(
                RuleScope::Both,
                "S7775",
                "Prefer `.test(…)` over `.exec(…)`.",
                member.property.span(),
            );
        }
        "match" => {
            if is_non_regex_literal(argument) {
                return;
            }
            if !is_known_regexp(argument) && is_redux_action_matcher(&member.object) {
                return;
            }
            sink.emit_span(
                RuleScope::Both,
                "S7775",
                "Prefer `RegExp#test(…)` over `String#match(…)`.",
                call.span(),
            );
        }
        _ => {}
    }
}

/// The callee's non-optional static member (`obj.method(...)`).
fn method_member<'a, 'b>(
    call: &'b CallExpression<'a>,
) -> Option<&'b oxc_ast::ast::StaticMemberExpression<'a>> {
    match unparenthesized(&call.callee) {
        Expression::StaticMemberExpression(member) if !member.optional => Some(member),
        _ => None,
    }
}

/// A literal that is not a regex (the reference's `Literal && !regex`
/// guard on the regexp operand).
fn is_non_regex_literal(expression: &Expression<'_>) -> bool {
    matches!(
        unparenthesized(expression),
        Expression::StringLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::BigIntLiteral(_)
    )
}

/// `isRegExpNode`: a regex literal or `new RegExp(...)`.
fn is_known_regexp(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::RegExpLiteral(_) => true,
        Expression::NewExpression(new) => {
            matches!(unparenthesized(&new.callee), Expression::Identifier(callee) if callee.name == "RegExp")
        }
        _ => false,
    }
}

/// `isReduxToolkitSliceActionMatcher`: `*.actions.*` member shape on the
/// `match` receiver.
fn is_redux_action_matcher(expression: &Expression<'_>) -> bool {
    let Expression::StaticMemberExpression(outer) = unparenthesized(expression) else {
        return false;
    };
    if outer.optional {
        return false;
    }
    let Expression::StaticMemberExpression(inner) = unparenthesized(&outer.object) else {
        return false;
    };
    !inner.optional && inner.property.name == "actions"
}

/// The nearest ancestor that is not a parenthesized expression, mirroring
/// the parent links of the paren-free reference AST.
fn significant_parent<'a, 'b>(
    semantic: &'a Semantic<'b>,
    node: &AstNode<'b>,
) -> Option<&'a AstNode<'b>> {
    let mut current = semantic.nodes().parent_node(node.id());
    while let AstKind::ParenthesizedExpression(_) = current.kind() {
        let parent = semantic.nodes().parent_node(current.id());
        if parent.id() == current.id() {
            return None;
        }
        current = parent;
    }
    Some(current)
}

/// `Boolean(x)` with one argument.
fn is_boolean_call(call: &CallExpression<'_>) -> bool {
    call.arguments.len() == 1
        && matches!(unparenthesized(&call.callee), Expression::Identifier(callee) if callee.name == "Boolean")
}

/// `!x` where `x` is the direct argument.
fn is_negated_argument(semantic: &Semantic<'_>, node: &AstNode<'_>) -> bool {
    let span = node.kind().span();
    let Some(parent) = significant_parent(semantic, node) else {
        return false;
    };
    match parent.kind() {
        AstKind::UnaryExpression(unary) => {
            unary.operator == UnaryOperator::LogicalNot && unary.argument.span() == span
        }
        _ => false,
    }
}

/// `getBooleanExpressionAncestor`: climb `&&`/`||` parents and
/// `Boolean(...)` wrappers.
fn boolean_expression_ancestor<'a, 'b>(
    semantic: &'a Semantic<'b>,
    node: &'a AstNode<'b>,
) -> &'a AstNode<'b> {
    let mut current = node;
    loop {
        let Some(parent) = significant_parent(semantic, current) else {
            return current;
        };
        match parent.kind() {
            AstKind::LogicalExpression(logical)
                if matches!(logical.operator, LogicalOperator::And | LogicalOperator::Or) =>
            {
                current = parent;
            }
            AstKind::CallExpression(call)
                if is_boolean_call(call) && call.arguments[0].span() == current.kind().span() =>
            {
                current = parent;
            }
            _ => return current,
        }
    }
}

/// `isNegatedBooleanValue`: the boolean-cast ancestor is `!`-negated.
fn is_negated_boolean_value(semantic: &Semantic<'_>, node: &AstNode<'_>) -> bool {
    is_negated_argument(semantic, boolean_expression_ancestor(semantic, node))
}

/// `isBooleanExpression`: `!`, `Boolean(...)`, or a `&&`/`||` chain whose
/// parent is itself a boolean context.
fn is_boolean_expression(semantic: &Semantic<'_>, node: &AstNode<'_>) -> bool {
    let span = node.kind().span();
    let Some(parent) = significant_parent(semantic, node) else {
        return false;
    };
    match parent.kind() {
        AstKind::UnaryExpression(unary) => {
            unary.operator == UnaryOperator::LogicalNot && unary.argument.span() == span
        }
        AstKind::CallExpression(call) => is_boolean_call(call) && call.arguments[0].span() == span,
        AstKind::LogicalExpression(logical)
            if matches!(logical.operator, LogicalOperator::And | LogicalOperator::Or) =>
        {
            is_boolean_expression(semantic, parent)
        }
        _ => false,
    }
}

/// `isControlFlowTest`: an `if`/`while`/`do`/`for`/ternary test, possibly
/// reached through a `&&`/`||` chain.
fn is_control_flow_test(semantic: &Semantic<'_>, node: &AstNode<'_>) -> bool {
    let span = node.kind().span();
    let Some(parent) = significant_parent(semantic, node) else {
        return false;
    };
    match parent.kind() {
        AstKind::IfStatement(statement) => statement.test.span() == span,
        AstKind::ConditionalExpression(statement) => statement.test.span() == span,
        AstKind::WhileStatement(statement) => statement.test.span() == span,
        AstKind::DoWhileStatement(statement) => statement.test.span() == span,
        AstKind::ForStatement(statement) => statement
            .test
            .as_ref()
            .is_some_and(|test| test.span() == span),
        AstKind::LogicalExpression(logical)
            if matches!(logical.operator, LogicalOperator::And | LogicalOperator::Or) =>
        {
            is_control_flow_test(semantic, parent)
        }
        _ => false,
    }
}

/// `getLengthCheck`: the call's result is read through `.length` used as
/// a boolean or compared `> 0` in a boolean context.
fn get_length_check(semantic: &Semantic<'_>, node: &AstNode<'_>) -> Option<()> {
    let call_span = node.kind().span();
    let length_node = significant_parent(semantic, node)?;
    let length_node = match length_node.kind() {
        AstKind::ChainExpression(_) => significant_parent(semantic, length_node)?,
        _ => length_node,
    };
    let AstKind::StaticMemberExpression(length_member) = length_node.kind() else {
        return None;
    };
    if length_member.property.name != "length" || length_member.object.span() != call_span {
        return None;
    }
    let length_check_node = match significant_parent(semantic, length_node) {
        Some(parent) if matches!(parent.kind(), AstKind::ChainExpression(_)) => parent,
        _ => length_node,
    };
    if is_negated_boolean_value(semantic, length_check_node) {
        return None;
    }
    if is_boolean_expression(semantic, length_check_node)
        || is_control_flow_test(semantic, length_check_node)
    {
        return Some(());
    }
    // `.length > 0` in a boolean context.
    let check_span = length_check_node.kind().span();
    let parent = significant_parent(semantic, length_check_node)?;
    let AstKind::BinaryExpression(binary) = parent.kind() else {
        return None;
    };
    if binary.operator != oxc_ast::ast::BinaryOperator::GreaterThan
        || binary.left.span() != check_span
        || !matches!(unparenthesized(&binary.right), Expression::NumericLiteral(literal) if literal.value == 0.0)
        || is_negated_boolean_value(semantic, parent)
    {
        return None;
    }
    (is_boolean_expression(semantic, parent) || is_control_flow_test(semantic, parent))
        .then_some(())
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7775_flags_boolean_match_and_exec() {
        let source = "\
if (string.match(/unicorn/)) {
  run();
}
while (/x/.exec(text)) {
  run();
}
const found = Boolean(string.match(pattern));
const negated = !re.exec(input);
const chained = flag && string.match(/y/);
";
        let keys = js_keys(source);
        // `flag && match` in a declarator is not a boolean context, so the
        // chained call stays silent: 4 findings.
        assert_eq!(count_key(&keys, "javascript:S7775"), 4);
    }

    #[test]
    fn s7775_flags_length_boolean_forms() {
        let source = "\
if (string.match(/a/).length) {
  run();
}
const has = string.match(/b/).length > 0 ? 1 : 2;
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7775"), 2);
    }

    #[test]
    fn s7775_flags_typescript_too() {
        let source = "if (text.match(/a/)) { go(); }\n";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7775"), 1);
    }

    #[test]
    fn s7775_ignores_non_boolean_and_non_regex_uses() {
        let source = "\
const parts = string.match(/a/);
const first = string.match(/a/)[0];
const text = string.match('plain');
const negatedLength = !string.match(/a/).length;
const result = re.exec(input).index;
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7775"), 0);
    }
}
