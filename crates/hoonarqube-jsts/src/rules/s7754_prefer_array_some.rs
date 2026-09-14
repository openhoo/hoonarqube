// Rule module s7754_prefer_array_some (generated).
//
// `javascript:S7754` + `typescript:S7754` — Use ".some()" instead of
// ".filter().length" checks or ".find()" for existence testing. Reference
// semantics: eslint-plugin-unicorn `prefer-array-some` at the version pinned
// by SonarJS 13.x (v65.0.1, wrapped by SonarJS S7754):
//
// - `.find(cb)`/`.findLast(cb)` (1-2 arguments, non-optional call and member,
//   no explicit type arguments) whose result is immediately booleanized:
//   `!!`, `!`, `Boolean(...)`, a `&&`/`||` chain used as a boolean or a
//   control-flow test, or a comparison with `undefined` (`===`, `!==`, `==`,
//   `!=`) or a loose comparison with `null`, always with the call on the
//   left of the comparison;
// - a `const`-declared single identifier initialized by such a `.find()`
//   call, without a type annotation and not directly exported, whose reads
//   are all boolean expressions or control-flow tests;
// - `.findIndex(cb)`/`.findLastIndex(cb)` compared against `-1` (`!==`, `!=`,
//   `>`, `===`, `==`) or `0` (`>=`, `<`);
// - `.filter(cb).length > 0` and `.filter(cb).length !== 0`, with a
//   non-function first `.filter()` argument and `$`-prefixed receivers kept
//   silent.
//
// Each report is anchored on the method property, with the reference message
// "Prefer `.some(…)` over `.{method}(…)`." and, for the filter-length form,
// "Prefer `.some(…)` over non-zero length check from `.filter(…)`.". Find
// results consumed as values (returned, stored, indexed) stay silent. No
// auto-fix is offered: the reference suggestion rewrites the callback
// position only, and found-element substitution is rejected per the issue
// guard.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    Argument, BinaryOperator, BindingPattern, CallExpression, Expression, StaticMemberExpression,
    UnaryOperator, VariableDeclarationKind,
};
use oxc_semantic::{AstNode, Semantic};
use oxc_span::{GetSpan, Span};

/// Entry point: `javascript:S7754` + `typescript:S7754` prefer-array-some
/// check over the parsed program. Requires the semantic model for the
/// find-result-variable guard, so recoverable-parse files stay silent.
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
            AstKind::CallExpression(call) => check_find_call(&mut sink, semantic, node, call),
            AstKind::BinaryExpression(binary) => {
                check_find_index_comparison(&mut sink, binary);
                check_filter_length_comparison(&mut sink, binary);
            }
            _ => {}
        }
    }
    sink.issues
}

fn emit_method(sink: &mut IssueSink<'_>, span: Span, method: &str) {
    sink.emit_span(
        RuleScope::Both,
        "S7754",
        &format!("Prefer `.some(…)` over `.{method}(…)`."),
        span,
    );
}

/// The static member whose non-computed, non-optional property is `method`,
/// with a non-optional call (the reference `isMethodCall` shape).
fn required_method_member<'a, 'b>(
    call: &'b CallExpression<'a>,
    methods: &[&str],
) -> Option<&'b StaticMemberExpression<'a>> {
    if call.optional {
        return None;
    }
    let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
        return None;
    };
    if member.optional || !methods.contains(&member.property.name.as_str()) {
        return None;
    }
    Some(member)
}

fn check_find_call(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    call: &CallExpression<'_>,
) {
    let Some(member) = required_method_member(call, &["find", "findLast"]) else {
        return;
    };
    if call.arguments.is_empty() || call.arguments.len() > 2 || call.type_arguments.is_some() {
        return;
    }
    if arguments_include_spread(&call.arguments) {
        return;
    }
    let method = member.property.name.as_str();
    if is_boolean_expression(semantic, node)
        || is_control_flow_test(semantic, node)
        || is_undefined_or_null_comparison(semantic, node, call.span())
        || find_result_variable_used_only_as_boolean(semantic, node, call)
    {
        emit_method(sink, member.property.span(), method);
    }
}

fn arguments_include_spread(arguments: &[Argument<'_>]) -> bool {
    arguments
        .iter()
        .any(|argument| matches!(argument, Argument::SpreadElement(_)))
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

fn is_boolean_call(call: &CallExpression<'_>) -> bool {
    matches!(unparenthesized(&call.callee), Expression::Identifier(identifier) if identifier.name == "Boolean")
}

/// The reference `isBooleanExpression`: `!`, `Boolean(...)`, or a `&&`/`||`
/// chain whose parent is itself a boolean context.
fn is_boolean_expression(semantic: &Semantic<'_>, node: &AstNode<'_>) -> bool {
    let span = node.kind().span();
    let Some(parent) = significant_parent(semantic, node) else {
        return false;
    };
    match parent.kind() {
        AstKind::UnaryExpression(unary) => {
            unary.operator == UnaryOperator::LogicalNot && unary.argument.span() == span
        }
        AstKind::CallExpression(call) => {
            is_boolean_call(call) && call.arguments.len() == 1 && call.arguments[0].span() == span
        }
        AstKind::LogicalExpression(logical)
            if matches!(
                logical.operator,
                oxc_ast::ast::LogicalOperator::And | oxc_ast::ast::LogicalOperator::Or
            ) =>
        {
            is_boolean_expression(semantic, parent)
        }
        _ => false,
    }
}

/// The reference `isControlFlowTest`: an `if`/`while`/`do`/`for`/ternary
/// test, possibly reached through a `&&`/`||` chain.
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
        AstKind::LogicalExpression(logical)
            if matches!(
                logical.operator,
                oxc_ast::ast::LogicalOperator::And | oxc_ast::ast::LogicalOperator::Or
            ) =>
        {
            is_control_flow_test(semantic, parent)
        }
        _ => false,
    }
}

/// The reference `isCheckingUndefined`: the call on the left of `===`,
/// `!==`, `==`, or `!=` with an `undefined` right operand, or loosely
/// compared against `null`.
fn is_undefined_or_null_comparison(
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    call_span: Span,
) -> bool {
    let Some(parent) = significant_parent(semantic, node) else {
        return false;
    };
    let AstKind::BinaryExpression(binary) = parent.kind() else {
        return false;
    };
    if binary.left.span() != call_span {
        return false;
    }
    if !binary.operator.is_equality() {
        return false;
    }
    let right = unparenthesized(&binary.right);
    if matches!(right, Expression::Identifier(identifier) if identifier.name == "undefined") {
        return true;
    }
    matches!(
        binary.operator,
        BinaryOperator::Equality | BinaryOperator::Inequality
    ) && matches!(right, Expression::NullLiteral(_))
}

/// The reference `isFindResultVariableUsedOnlyAsBoolean`: a `const`-bound
/// single identifier without a type annotation and not directly exported
/// whose every read stays inside a boolean expression or control-flow test.
fn find_result_variable_used_only_as_boolean(
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    call: &CallExpression<'_>,
) -> bool {
    let Some(parent) = significant_parent(semantic, node) else {
        return false;
    };
    let AstKind::VariableDeclarator(declarator) = parent.kind() else {
        return false;
    };
    if declarator
        .init
        .as_ref()
        .is_none_or(|init| init.span() != call.span())
    {
        return false;
    }
    let BindingPattern::BindingIdentifier(identifier) = &declarator.id else {
        return false;
    };
    if declarator.type_annotation.is_some() {
        return false;
    }
    let declaration_node = semantic.nodes().parent_node(parent.id());
    let AstKind::VariableDeclaration(declaration) = declaration_node.kind() else {
        return false;
    };
    if declaration.kind != VariableDeclarationKind::Const {
        return false;
    }
    if let AstKind::ExportDeclaration(_) =
        semantic.nodes().parent_node(declaration_node.id()).kind()
    {
        return false;
    }
    let Some(symbol) = semantic
        .scoping()
        .find_binding(declaration_node.scope_id(), identifier.name.as_str().into())
    else {
        return false;
    };
    if semantic.scoping().symbol_declarations(symbol).count() != 1 {
        return false;
    }
    let references: Vec<_> = semantic.scoping().get_resolved_references(symbol).collect();
    if references.is_empty() {
        return false;
    }
    references.iter().all(|reference| {
        let identifier = semantic.nodes().get_node(reference.node_id());

        reference.is_read()
            && (is_boolean_expression(semantic, identifier)
                || is_control_flow_test(semantic, identifier))
    })
}

fn check_find_index_comparison(
    sink: &mut IssueSink<'_>,
    binary: &oxc_ast::ast::BinaryExpression<'_>,
) {
    let Expression::CallExpression(call) = unparenthesized(&binary.left) else {
        return;
    };
    let Some(member) = required_method_member(call, &["findIndex", "findLastIndex"]) else {
        return;
    };
    if call.arguments.len() != 1 {
        return;
    }
    let negative_one = match unparenthesized(&binary.right) {
        Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::UnaryNegation => {
            matches!(
                unparenthesized(&unary.argument),
                Expression::NumericLiteral(literal) if same_number(literal.value, 1.0)
            )
        }
        _ => false,
    };
    let zero = matches!(
        unparenthesized(&binary.right),
        Expression::NumericLiteral(literal) if same_number(literal.value, 0.0)
    );
    let matched = match binary.operator {
        BinaryOperator::StrictInequality
        | BinaryOperator::Inequality
        | BinaryOperator::GreaterThan
        | BinaryOperator::StrictEquality
        | BinaryOperator::Equality => negative_one,
        BinaryOperator::GreaterEqualThan | BinaryOperator::LessThan => zero,
        _ => false,
    };
    if matched {
        emit_method(sink, member.property.span(), member.property.name.as_str());
    }
}

fn check_filter_length_comparison(
    sink: &mut IssueSink<'_>,
    binary: &oxc_ast::ast::BinaryExpression<'_>,
) {
    if !matches!(
        binary.operator,
        BinaryOperator::GreaterThan | BinaryOperator::StrictInequality
    ) {
        return;
    }
    let Expression::NumericLiteral(literal) = unparenthesized(&binary.right) else {
        return;
    };
    if literal.raw.as_deref() != Some("0") {
        return;
    }
    let Expression::StaticMemberExpression(length_member) = unparenthesized(&binary.left) else {
        return;
    };
    if length_member.optional || length_member.property.name != "length" {
        return;
    }
    let Expression::CallExpression(filter_call) = unparenthesized(&length_member.object) else {
        return;
    };
    let Some(filter_member) = required_method_member(filter_call, &["filter"]) else {
        return;
    };
    if let Expression::Identifier(receiver) = unparenthesized(&filter_member.object)
        && receiver.name.starts_with('$')
    {
        return;
    }
    let Some(first) = filter_call.arguments.first() else {
        return;
    };
    let Some(expression) = first.as_expression() else {
        return;
    };
    if is_node_value_not_function(expression) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S7754",
        "Prefer `.some(…)` over non-zero length check from `.filter(…)`.",
        filter_member.property.span(),
    );
}

fn is_node_value_not_function(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::ArrayExpression(_)
        | Expression::BinaryExpression(_)
        | Expression::ClassExpression(_)
        | Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::ObjectExpression(_)
        | Expression::TemplateLiteral(_)
        | Expression::UnaryExpression(_)
        | Expression::UpdateExpression(_)
        | Expression::AssignmentExpression(_)
        | Expression::AwaitExpression(_)
        | Expression::NewExpression(_)
        | Expression::TaggedTemplateExpression(_)
        | Expression::ThisExpression(_) => true,
        Expression::Identifier(identifier) => identifier.name == "undefined",
        Expression::CallExpression(call) => {
            call.optional
                || !matches!(
                    unparenthesized(&call.callee),
                    Expression::StaticMemberExpression(member)
                        if !member.optional && member.property.name == "bind"
                )
        }
        _ => false,
    }
}

/// Exact `f64` comparison, matching the reference `Literal.value ===` checks
/// on parser-produced values.
#[allow(clippy::float_cmp)]
fn same_number(left: f64, right: f64) -> bool {
    left == right
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7754_flags_pinned_zod_types_anchor() {
        // Pinned anchor: colinhacks/zod@46da957 packages/zod/src/v3/types.ts:1253
        // `return !!this._def.checks.find((ch) => ch.kind === "datetime");`
        // (same file also carries the line 1257 and 1261 occurrences).
        let source = "\
class Check {
  isDatetime(): boolean {
    return !!this._def.checks.find((ch) => ch.kind === \"datetime\");
  }

  isDate(): boolean {
    return !!this._def.checks.find((ch) => ch.kind === \"date\");
  }

  isTime(): boolean {
    return !!this._def.checks.find((ch) => ch.kind === \"time\");
  }
}
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7754"), 3);
        let mut issues: Vec<(u32, u32, &str)> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "typescript:S7754")
            .map(|issue| {
                (
                    issue.range.start.line,
                    issue.range.start.column,
                    issue.message.as_str(),
                )
            })
            .collect();
        issues.sort_unstable();
        let prefix = "    return !!this._def.checks.";
        assert_eq!(
            issues,
            vec![
                (
                    3,
                    u32::try_from(prefix.len()).unwrap(),
                    "Prefer `.some(…)` over `.find(…)`."
                ),
                (
                    7,
                    u32::try_from(prefix.len()).unwrap(),
                    "Prefer `.some(…)` over `.find(…)`."
                ),
                (
                    11,
                    u32::try_from(prefix.len()).unwrap(),
                    "Prefer `.some(…)` over `.find(…)`."
                ),
            ]
        );
    }

    #[test]
    fn s7754_flags_all_reference_case_families() {
        let source = "\
const list = [];
const a = !!list.find((x) => x.ok);
const b = Boolean(list.find((x) => x.ok));
const c = !list.findLast((x) => x.ok);
if (list.find((x) => x.ok)) { }
while (list.find((x) => x.ok)) { break; }
const d = list.find((x) => x.ok) !== undefined;
const e = list.find((x) => x.ok) == null;
const f = list.findIndex((x) => x) !== -1;
const g = list.findIndex((x) => x) >= 0;
const h = list.findLastIndex((x) => x) === -1;
const i = list.findIndex((x) => x) > -1;
const j = list.findIndex((x) => x) < 0;
const k = list.filter((x) => x.ok).length > 0;
const l = list.filter((x) => x.ok).length !== 0;
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7754"), 14);
        let messages: Vec<&str> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7754")
            .map(|issue| issue.message.as_str())
            .collect();
        assert!(messages.contains(&"Prefer `.some(…)` over `.find(…)`."));
        assert!(messages.contains(&"Prefer `.some(…)` over `.findLast(…)`."));
        assert!(messages.contains(&"Prefer `.some(…)` over `.findIndex(…)`."));
        assert!(messages.contains(&"Prefer `.some(…)` over `.findLastIndex(…)`."));
        assert!(
            messages.contains(&"Prefer `.some(…)` over non-zero length check from `.filter(…)`.")
        );
    }

    #[test]
    fn s7754_flags_const_find_result_used_only_as_boolean() {
        let source = "\
function run(list) {
  const found = list.find((x) => x.ok);
  if (found) { return true; }
  return !found;
}
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7754"), 1);
    }

    #[test]
    fn s7754_find_results_consumed_as_values_stay_silent() {
        let source = "\
function run(list) {
  const first = list.find((x) => x.ok);
  return first[0];
}
function chain(list) {
  return list.find((x) => x.ok).toString();
}
function passed(list) {
  return list.find((x) => x.ok, { threshold: 1 });
}
function leaked(list) {
  const bare = list.find((x) => x.ok);
  return bare;
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7754"), 0);
    }

    #[test]
    fn s7754_reference_guards_stay_silent() {
        let source = "\
export const exported = list.find((x) => x.ok);
if (exported) { }
function run(list) {
  if (list?.find((x) => x.ok)) { return true; }
  if (list.find?.((x) => x.ok)) { return true; }
  if (list.find()) { return true; }
  const yoda = undefined !== list.find((x) => x.ok);
  const positive = list.findIndex((x) => x) === 0;
  const greater = list.findIndex((x) => x) > 0;
  const dollar = $.filter((x) => x.ok).length > 0;
  const noCallback = list.filter().length > 0;
  const notFunction = list.filter(1).length > 0;
  const separate = list.filter((x) => x.ok).length;
  if (separate > 0) { return true; }
  return false;
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7754"), 0);
    }

    #[test]
    fn s7754_type_arguments_stay_silent() {
        let source = "\
function run<T>(list: T[]) {
  if (list.find<T>((x) => !!x)) { return true; }
  return false;
}
";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7754"), 0);
    }

    #[test]
    fn s7754_reports_in_both_languages() {
        let ts_source = "\
declare const list: { ok: boolean }[];
const a = !!list.find((x) => x.ok);
";
        let js_source = "\
const list = [];
const a = !!list.find((x) => x.ok);
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7754"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7754"), 1);
    }
}

#[cfg(test)]
mod scratch_debug {
    use crate::test_support::*;

    #[test]
    fn scratch_s7754() {
        let source = "export const exported = list.find((x) => x.ok);\nif (exported) { }\nfunction run(list) {\n  if (list?.find((x) => x.ok)) { return true; }\n  if (list.find?.((x) => x.ok)) { return true; }\n  if (list.find()) { return true; }\n  const yoda = undefined !== list.find((x) => x.ok);\n  const positive = list.findIndex((x) => x) === 0;\n  const greater = list.findIndex((x) => x) > 0;\n  const dollar = $.filter((x) => x.ok).length > 0;\n  const noCallback = list.filter().length > 0;\n  const notFunction = list.filter(1).length > 0;\n  const separate = list.filter((x) => x.ok).length;\n  if (separate > 0) { return true; }\n  return false;\n}\n";
        let report = js(source);
        for issue in &report.issues {
            if issue.rule_key.ends_with("S7754") {
                let line: Vec<&str> = source.lines().collect();
                println!(
                    "finding {}:{}: {}",
                    issue.range.start.line,
                    issue.range.start.column,
                    line.get((issue.range.start.line - 1) as usize)
                        .unwrap_or(&"")
                );
            }
        }
    }
}
