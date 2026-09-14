// Rule module s7765_prefer_includes (generated).
//
// `javascript:S7765` + `typescript:S7765` — Existence checks should use
// ".includes()" instead of ".indexOf()" or ".lastIndexOf()". Reference
// semantics: eslint-plugin-unicorn `prefer-includes` at the version pinned
// by SonarJS 13.x (v65.0.1, wrapped by SonarJS S7765):
//
// - `x.indexOf(v)`/`x.lastIndexOf(v)` (non-optional member and call) on the
//   left of a comparison whose right side is `-1` with `!==`, `!=`, `>`,
//   `===`, or `==`, or `0` with `>=` or `<`, is reported on the method
//   property with "Use `.includes()`, rather than `.{method}()`, when
//   checking for existence.". Receivers named `_`, `lodash`, or
//   `underscore` stay silent, more than two arguments stay silent, and a
//   literal `0` `fromIndex` is still reported;
// - `.some(cb)` whose single-parameter non-async callback body is exactly
//   `param === value` (expression or single `return`) is reported on the
//   `some` property with "Use `.includes()` instead of `.some()` when
//   checking value existence.", unless the parameter is referenced outside
//   the comparison or the named callback recurses into itself.
//
// Index-value uses, coercion polarity, and non-comparison forms stay silent
// per the issue guard; no auto-fix is offered.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    BinaryOperator, CallExpression, Expression, StaticMemberExpression, UnaryOperator,
};
use oxc_semantic::Semantic;
use oxc_span::GetSpan;

/// Entry point: `javascript:S7765` + `typescript:S7765` prefer-includes
/// check over the parsed program. Requires the semantic model for the
/// some-callback parameter guard, so recoverable-parse files stay silent.
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
            AstKind::BinaryExpression(binary) => check_index_of_comparison(&mut sink, binary),
            AstKind::CallExpression(call) => check_some_callback(&mut sink, semantic, call),
            _ => {}
        }
    }
    sink.issues
}

/// The static member whose non-computed, non-optional property is `method`.
fn method_member<'a, 'b>(
    call: &'b CallExpression<'a>,
    method: &str,
) -> Option<&'b StaticMemberExpression<'a>> {
    let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
        return None;
    };
    if member.optional || member.property.name != method {
        return None;
    }
    Some(member)
}

fn is_negative_one(expression: &Expression<'_>) -> bool {
    let Expression::UnaryExpression(unary) = expression else {
        return false;
    };
    unary.operator == UnaryOperator::UnaryNegation
        && matches!(
            unparenthesized(&unary.argument),
            Expression::NumericLiteral(literal) if same_number(literal.value, 1.0) // eslint Literal value: exact comparison is the reference behavior
        )
}

fn is_literal_zero(expression: &Expression<'_>) -> bool {
    matches!(expression, Expression::NumericLiteral(literal) if same_number(literal.value, 0.0))
}

/// `x.indexOf(v)` / `x.lastIndexOf(v)` compared for existence.
fn check_index_of_comparison(
    sink: &mut IssueSink<'_>,
    binary: &oxc_ast::ast::BinaryExpression<'_>,
) {
    let Expression::CallExpression(call) = unparenthesized(&binary.left) else {
        return;
    };
    if call.optional {
        return;
    }
    let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
        return;
    };
    if member.optional {
        return;
    }
    let method = member.property.name.as_str();
    if method != "indexOf" && method != "lastIndexOf" {
        return;
    }
    if let Expression::Identifier(target) = unparenthesized(&member.object)
        && matches!(target.name.as_str(), "_" | "lodash" | "underscore")
    {
        return;
    }
    if call.arguments.len() > 2 {
        return;
    }
    let right = unparenthesized(&binary.right);
    let matched = match binary.operator {
        BinaryOperator::StrictInequality
        | BinaryOperator::Inequality
        | BinaryOperator::GreaterThan
        | BinaryOperator::StrictEquality
        | BinaryOperator::Equality => is_negative_one(right),
        BinaryOperator::GreaterEqualThan | BinaryOperator::LessThan => is_literal_zero(right),
        _ => false,
    };
    if !matched {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S7765",
        &format!("Use `.includes()`, rather than `.{method}()`, when checking for existence."),
        member.property.span(),
    );
}

/// `.some((item) => item === value)` value-existence wrappers.
fn check_some_callback(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
) {
    let Some(member) = method_member(call, "some") else {
        return;
    };
    if call.optional || call.arguments.len() != 1 {
        return;
    }
    let Some(callback) = call.arguments[0].as_expression() else {
        return;
    };
    if simple_compare_callback(semantic, callback).is_none() {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S7765",
        "Use `.includes()` instead of `.some()` when checking value existence.",
        member.property.span(),
    );
}

/// The `item === value` expression of the reference
/// `isSimpleCompareCallbackFunction`, with its parameter guard applied.
/// Exact `f64` comparison, matching the reference `Literal.value ===` checks
/// on parser-produced values.
#[allow(clippy::float_cmp)]
fn same_number(left: f64, right: f64) -> bool {
    left == right
}

/// The expression of a single-statement `return` body.
fn single_return_expression<'a>(
    body: &'a oxc_ast::ast::FunctionBody<'a>,
) -> Option<&'a Expression<'a>> {
    if body.statements.len() != 1 {
        return None;
    }
    match &body.statements[0] {
        oxc_ast::ast::Statement::ReturnStatement(statement) => statement.argument.as_ref(),
        _ => None,
    }
}

/// The parameter identifier and comparison expression of the reference
/// `isSimpleCompareCallbackFunction` shape, or `None` when the callback does
/// not match.
fn compare_callback_shape<'a>(
    callback: &'a Expression<'a>,
) -> Option<(&'a oxc_ast::ast::FormalParameters<'a>, &'a Expression<'a>)> {
    match callback {
        Expression::ArrowFunctionExpression(arrow) => {
            if arrow.r#async {
                return None;
            }
            let expression = match &arrow.body {
                oxc_ast::ast::ArrowFunctionBody::FunctionBody(body) => {
                    single_return_expression(body)?
                }
                body => body.as_expression()?,
            };
            Some((&arrow.params, expression))
        }
        Expression::FunctionExpression(function) => {
            let body = function.body.as_deref()?;
            if function.r#async || function.generator {
                return None;
            }
            Some((&function.params, single_return_expression(body)?))
        }
        _ => None,
    }
}

fn simple_compare_callback<'a>(
    semantic: &Semantic<'_>,
    callback: &'a Expression<'_>,
) -> Option<&'a oxc_ast::ast::BinaryExpression<'a>> {
    let (parameters, expression) = compare_callback_shape(callback)?;
    if parameters.rest.is_some() || parameters.items.len() != 1 {
        return None;
    }
    let oxc_ast::ast::BindingPattern::BindingIdentifier(parameter) = &parameters.items[0].pattern
    else {
        return None;
    };
    let Expression::BinaryExpression(binary) = unparenthesized(expression) else {
        return None;
    };
    if binary.operator != BinaryOperator::StrictEquality {
        return None;
    }
    // The reference `isSameIdentifier` compares names; the comparison side
    // must additionally resolve to the parameter's binding.
    let parameter_side_span = comparison_parameter_side(semantic, binary, parameter)?;
    let symbol = parameter.symbol_id.get()?;
    let references: Vec<_> = semantic.scoping().get_resolved_references(symbol).collect();
    let only_in_comparison = references.iter().all(|reference| {
        semantic.nodes().get_node(reference.node_id()).kind().span() == parameter_side_span
    });
    if !only_in_comparison {
        return None;
    }
    if let Expression::FunctionExpression(function) = callback
        && let Some(name) = &function.id
        && let Some(symbol) = name.symbol_id.get()
        && semantic
            .scoping()
            .get_resolved_references(symbol)
            .any(|reference| {
                let span = semantic.nodes().get_node(reference.node_id()).kind().span();
                span.start >= callback.span().start && span.end <= callback.span().end
            })
    {
        return None;
    }
    Some(binary)
}

/// The span of the comparison operand that resolves to the callback
/// parameter, or `None` when neither side does.
fn comparison_parameter_side<'a, 'b>(
    semantic: &Semantic<'b>,
    binary: &'a oxc_ast::ast::BinaryExpression<'b>,
    parameter: &oxc_ast::ast::BindingIdentifier<'b>,
) -> Option<oxc_span::Span> {
    let resolves_to_parameter = |expression: &Expression<'b>| {
        let Expression::Identifier(reference) = unparenthesized(expression) else {
            return false;
        };
        if reference.name != parameter.name.as_str() {
            return false;
        }
        reference
            .reference_id
            .get()
            .and_then(|reference_id| semantic.scoping().get_reference(reference_id).symbol_id())
            == parameter.symbol_id.get()
    };
    if resolves_to_parameter(&binary.left) {
        Some(binary.left.span())
    } else if resolves_to_parameter(&binary.right) {
        Some(binary.right.span())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7765_flags_pinned_axios_anchors() {
        // Pinned anchors: axios/axios@18e7dfed lib/core/dispatchRequest.js:48,
        // lib/defaults/index.js:47 and :82.
        let source = "\
function dispatch(config, contentType) {
  if (['post', 'put', 'patch'].indexOf(config.method) !== -1) {
    return 'data';
  }
  const hasJSONContentType = contentType.indexOf('application/json') > -1;
  if (contentType.indexOf('application/x-www-form-urlencoded') > -1) {
    return 'form';
  }
  return hasJSONContentType;
}
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7765"), 3);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S7765")
            .expect("pinned axios indexOf existence check must be reported");
        assert_eq!(
            issue.message,
            "Use `.includes()`, rather than `.indexOf()`, when checking for existence."
        );
        assert_eq!(issue.range.start.line, 2);
        let prefix = "  if (['post', 'put', 'patch'].";
        assert_eq!(
            issue.range.start.column,
            u32::try_from(prefix.len()).unwrap()
        );
        assert_eq!(
            issue.range.end.column,
            u32::try_from(prefix.len() + "indexOf".len()).unwrap()
        );
        let lines: Vec<u32> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7765")
            .map(|issue| issue.range.start.line)
            .collect();
        assert_eq!(lines, vec![2, 5, 6]);
    }

    #[test]
    fn s7765_flags_pinned_zod_and_markdown_it_anchors() {
        // Pinned anchors: colinhacks/zod@46da957 packages/zod/src/v3/types.ts:3249
        // (`bKeys.indexOf(key) !== -1`) and v4/core/util.ts:279
        // (`numericValues.indexOf(+k) === -1`); markdown-it@3c51991 src/ruler.ts:71,
        // src/rules_block/fence.ts:32 (`>= 0`), src/rules_block/table.ts:122
        // (`=== -1`).
        let zod_v3 = "\
function sharedKeys(aKeys, bKeys) {
  return Object.keys(aKeys).filter((key) => bKeys.indexOf(key) !== -1);
}
";
        assert_eq!(count_key(&ts_keys(zod_v3), "typescript:S7765"), 1);

        let javascript = "\
function numericEntries(entries, values) {
  return entries.filter(([k, v]) => values.indexOf(+k) === -1);
}
function rulerChecks(rule, chain, params, marker, lineText) {
  if (rule.enabled && rule.alt.indexOf(chain) >= 0) return true;
  if (params.indexOf(String.fromCharCode(marker)) >= 0) return true;
  if (lineText.indexOf('|') === -1) return false;
  return false;
}
";
        assert_eq!(count_key(&js_keys(javascript), "javascript:S7765"), 4);
    }

    #[test]
    fn s7765_flags_reference_operator_and_method_families() {
        let source = "\
const list = [];
const a = list.lastIndexOf(item) !== -1;
const b = list.indexOf(item, 2) !== -1;
const c = list.indexOf(item, 0) !== -1;
const d = list.lastIndexOf(item) == -1;
const e = list.indexOf(item) < 0;
";
        let report = js(source);
        let messages: Vec<&str> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7765")
            .map(|issue| issue.message.as_str())
            .collect();
        assert_eq!(messages.len(), 5);
        assert!(messages.contains(
            &"Use `.includes()`, rather than `.lastIndexOf()`, when checking for existence."
        ));
        assert_eq!(
            messages
                .iter()
                .filter(|message| {
                    **message
                        == "Use `.includes()`, rather than `.indexOf()`, when checking for existence."
                })
                .count(),
            3
        );
    }

    #[test]
    fn s7765_non_existence_forms_stay_silent() {
        let source = "\
const list = [];
const f = _.indexOf(list, item) !== -1;
const g = lodash.indexOf(list, item) !== -1;
const h = underscore.indexOf(list, item) !== -1;
const i = list?.indexOf(item) !== -1;
const j = -1 !== list.indexOf(item);
const k = list.indexOf(item) > 0;
const l = list.indexOf(item) === 0;
const m = list.indexOf(item, 0, 1) !== -1;
const position = list.indexOf(item);
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7765"), 0);
    }

    #[test]
    fn s7765_flags_some_value_existence_wrappers() {
        let source = "\
const has = list.some((item) => item === target);
const block = list.some((item) => { return item === target; });
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7765"), 2);
        let messages: Vec<&str> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7765")
            .map(|issue| issue.message.as_str())
            .collect();
        assert!(
            messages
                .contains(&"Use `.includes()` instead of `.some()` when checking value existence.")
        );
    }

    #[test]
    fn s7765_non_simple_some_callbacks_stay_silent() {
        let source = "\
const neg = list.some((item) => item !== target);
const multi = list.some((item) => item === target && item !== other);
const asyncCb = list.some(async (item) => item === target);
const twoParams = list.some((item, index) => item === target);
const reused = list.some((item) => item === String(item));
const selfRef = list.some(function self(item) { return item === self(); });
const spread = list.some(...callbacks);
const generator = list.some(function* (item) { return item === target; });
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7765"), 0);
    }

    #[test]
    fn s7765_reports_in_both_languages() {
        let ts_source = "\
declare const list: string[];
const a = list.indexOf(item) !== -1;
";
        let js_source = "\
const list = [];
const a = list.indexOf(item) !== -1;
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7765"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7765"), 1);
    }
}
