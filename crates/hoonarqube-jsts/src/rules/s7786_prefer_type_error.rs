// Rule module s7786_prefer_type_error (generated).
//
// `javascript:S7786` + `typescript:S7786` — Generic `Error` should be
// `TypeError` when thrown after type checking. Reference semantics:
// eslint-plugin-unicorn `prefer-type-error` at the version pinned by
// SonarJS 13.x (v65.0.1, wrapped by SonarJS S7786).
//
// A `throw new Error(...)` is reported when it is the only statement of
// its block, the block directly belongs to an `if`, and the `if` test
// proves a type/operation failure: global `isNaN(...)`/`isFinite(...)`
// calls, member type-check calls (`_.isFunction`, `util.isArray`, ...),
// `typeof` checks (also under `!`), `instanceof` against anything that is
// not an error-constructor-shaped name, and `&&`/`||` combinations of
// those. `instanceof Error`-style checks, plain truthiness/comparison
// tests, multi-statement bodies, and throws outside `if` blocks stay
// silent, preserving custom error intent, subclassing, messages, and
// control flow. The report anchors on the `Error` constructor with the
// reference message "`new Error()` is too unspecific for a type check.
// Use `new TypeError()` instead." No auto-fix is offered.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    BinaryOperator, CallExpression, Expression, StaticMemberExpression, ThrowStatement,
    UnaryOperator,
};
use oxc_semantic::Semantic;
use oxc_syntax::node::NodeId;

/// The reference `typeCheckIdentifiers` for member calls.
const TYPE_CHECK_IDENTIFIERS: [&str; 37] = [
    "isArguments",
    "isArray",
    "isArrayBuffer",
    "isArrayLike",
    "isArrayLikeObject",
    "isBigInt",
    "isBoolean",
    "isBuffer",
    "isDate",
    "isElement",
    "isError",
    "isFinite",
    "isFunction",
    "isInteger",
    "isLength",
    "isMap",
    "isNaN",
    "isNative",
    "isNil",
    "isNull",
    "isNumber",
    "isObject",
    "isObjectLike",
    "isPlainObject",
    "isPrototypeOf",
    "isRegExp",
    "isSafeInteger",
    "isSet",
    "isString",
    "isSymbol",
    "isTypedArray",
    "isUndefined",
    "isView",
    "isWeakMap",
    "isWeakSet",
    "isWindow",
    "isXMLDoc",
];

/// The reference `typeCheckGlobalIdentifiers` for bare calls.
const TYPE_CHECK_GLOBAL_IDENTIFIERS: [&str; 2] = ["isNaN", "isFinite"];

/// Entry point: `javascript:S7786` + `typescript:S7786`
/// prefer-type-error check over the parsed program.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    if let Some(semantic) = ctx.semantic {
        for node in semantic.nodes().iter() {
            if let AstKind::ThrowStatement(throw) = node.kind() {
                check_throw(&mut sink, semantic, node.id(), throw);
            }
        }
    }
    sink.issues
}

/// The reference `ThrowStatement` listener: `throw new Error(...)`, alone
/// in its block, directly under an `if` whose test proves a type check.
fn check_throw(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    throw_node_id: NodeId,
    throw: &ThrowStatement<'_>,
) {
    let argument = &throw.argument;
    let Expression::NewExpression(new_expression) = unparenthesized(argument) else {
        return;
    };
    let Expression::Identifier(callee) = unparenthesized(&new_expression.callee) else {
        return;
    };
    if callee.name != "Error" {
        return;
    }
    let Some(test) = lone_throw_if_test(semantic, throw_node_id) else {
        return;
    };
    if !is_typechecking_expression(test, None) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S7786",
        "`new Error()` is too unspecific for a type check. Use `new TypeError()` instead.",
        callee.span,
    );
}

/// The `if` test when `throw` is the only statement of a block that
/// directly belongs to an `if` (the reference `isLone` + `isTypechecking`).
fn lone_throw_if_test<'a, 'b>(
    semantic: &'a Semantic<'b>,
    throw_node_id: NodeId,
) -> Option<&'a Expression<'b>> {
    let nodes = semantic.nodes();
    let parent = nodes.parent_node(throw_node_id);
    let AstKind::BlockStatement(block) = parent.kind() else {
        return None;
    };
    if block.body.len() != 1 {
        return None;
    }
    let grandparent = nodes.parent_node(parent.id());
    let AstKind::IfStatement(if_statement) = grandparent.kind() else {
        return None;
    };
    Some(&if_statement.test)
}

/// The reference `isTypecheckingExpression`.
fn is_typechecking_expression(
    expression: &Expression<'_>,
    call: Option<&CallExpression<'_>>,
) -> bool {
    match unparenthesized(expression) {
        Expression::Identifier(identifier) => {
            call.is_some_and(|call| !call.arguments.is_empty())
                && TYPE_CHECK_GLOBAL_IDENTIFIERS.contains(&identifier.name.as_str())
        }
        Expression::StaticMemberExpression(member) => is_typechecking_member(member, call),
        Expression::CallExpression(nested_call) => {
            is_typechecking_expression(&nested_call.callee, Some(nested_call))
        }
        Expression::UnaryExpression(unary) => match unary.operator {
            UnaryOperator::Typeof => true,
            UnaryOperator::LogicalNot => is_typechecking_expression(&unary.argument, None),
            _ => false,
        },
        Expression::BinaryExpression(binary) => {
            if binary.operator == BinaryOperator::Instanceof {
                return !is_error_constructor(&binary.right);
            }
            is_typechecking_expression(&binary.left, call)
                || is_typechecking_expression(&binary.right, call)
        }
        Expression::LogicalExpression(logical) => {
            is_typechecking_expression(&logical.left, call)
                && is_typechecking_expression(&logical.right, call)
        }
        _ => false,
    }
}

/// The reference `isTypecheckingMemberExpression`: a member call named
/// like a type check, or a nested member chain (for example `_.util.is`).
fn is_typechecking_member(
    member: &StaticMemberExpression<'_>,
    call: Option<&CallExpression<'_>>,
) -> bool {
    if call.is_some_and(|call| !call.arguments.is_empty())
        && TYPE_CHECK_IDENTIFIERS.contains(&member.property.name.as_str())
    {
        return true;
    }
    match unparenthesized(&member.object) {
        Expression::StaticMemberExpression(object) => is_typechecking_member(object, call),
        _ => false,
    }
}

/// The reference `isErrorConstructor`: anything not shaped like an error
/// constructor name makes `instanceof` a type check.
fn is_error_constructor(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::Identifier(identifier) => is_error_constructor_name(identifier.name.as_str()),
        Expression::StaticMemberExpression(member) => {
            !member.optional && is_error_constructor_name(member.property.name.as_str())
        }
        _ => false,
    }
}

/// The reference `errorNameRegexp` (`^(?:[A-Z][\da-z]*)*Error$`) without a
/// regular-expression engine: the prefix must segment into
/// uppercase-started runs.
fn is_error_constructor_name(name: &str) -> bool {
    let Some(prefix) = name.strip_suffix("Error") else {
        return false;
    };
    let bytes = prefix.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_uppercase() {
            return false;
        }
        index += 1;
        while index < bytes.len()
            && (bytes[index].is_ascii_lowercase() || bytes[index].is_ascii_digit())
        {
            index += 1;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    const MESSAGE: &str = concat!(
        "`new Error()` is too unspecific for a type check. ",
        "Use `new TypeError()` instead."
    );

    #[test]
    fn s7786_flags_pinned_express_anchors() {
        // Pinned anchors: expressjs/express@53d4a0d
        // lib/application.js:296 and lib/view.js:84 - lone throws behind
        // `typeof fn !== 'function'`.
        let source = "\
app.engine = function engine(ext, fn) {
  if (typeof fn !== 'function') {
    throw new Error('callback function required');
  }
};

View.prototype.lookup = function lookup(name) {
  var resolved = require(name).__express;

  if (typeof resolved !== 'function') {
    throw new Error('Module \"' + name + '\" does not provide a view engine.');
  }
};
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7786"), 2);
        for (line, prefix) in [(3u32, "    throw new "), (11, "    throw new ")] {
            let issue = report
                .issues
                .iter()
                .find(|issue| {
                    issue.rule_key == "javascript:S7786" && issue.range.start.line == line
                })
                .expect("each pinned express throw must be reported");
            assert_eq!(issue.message, MESSAGE);
            assert_eq!(
                issue.range.start.column,
                u32::try_from(prefix.len()).unwrap()
            );
            assert_eq!(
                issue.range.end.column,
                u32::try_from(prefix.len()).unwrap() + u32::try_from("Error".len()).unwrap()
            );
        }
    }

    #[test]
    fn s7786_flags_pinned_zod_anchors() {
        // Pinned anchors: colinhacks/zod@46da957
        // packages/zod/src/v3/types.ts:3470/4380/4421.
        let source = "\
class ZodTuple {
  static create(schemas: unknown) {
    if (!Array.isArray(schemas)) {
      throw new Error('You must pass an array of schemas to z.tuple([ ... ])');
    }
    const refined = effect.refinement(acc, checkCtx);
    if (refined instanceof Promise) {
      throw new Error('Async refinement encountered during synchronous parse operation.');
    }
    const result = effect.transform(base.value, checkCtx);
    if (result instanceof Promise) {
      throw new Error(
        `Asynchronous transform encountered during synchronous parse operation.`
      );
    }
  }
}
";
        let keys = ts_keys(source);
        let flagged: Vec<u32> = keys
            .iter()
            .filter(|(key, _)| key == "typescript:S7786")
            .map(|(_, line)| *line)
            .collect();
        assert_eq!(flagged, vec![4, 8, 12]);
    }

    #[test]
    fn s7786_flags_reference_type_check_families() {
        let source = "\
function check(fn, value) {
  if (!isNaN(value)) {
    throw new Error('unexpected NaN');
  }
  if (typeof value === 'string' || typeof value === 'number') {
    throw new Error('primitive not allowed');
  }
  if (_.isPlainObject(value)) {
    throw new Error('plain object not allowed');
  }
  if (util.isArrayLike(value) && !isFinite(value)) {
    throw new Error('unexpected array-like');
  }
  return fn;
}
";
        let keys = js_keys(source);
        let flagged: Vec<u32> = keys
            .iter()
            .filter(|(key, _)| key == "javascript:S7786")
            .map(|(_, line)| *line)
            .collect();
        assert_eq!(flagged, vec![3, 6, 9, 12]);
    }

    #[test]
    fn s7786_controls_stay_silent() {
        let source = "\
function controls(fn, value, Box) {
  if (value instanceof Error) {
    throw new TypeError('already an error');
  }
  if (value instanceof Box) {
    log();
    throw new Error('not a lone throw');
  }
  if (value) {
    throw new Error('no type check');
  }
  if (value !== null) {
    throw new Error('plain comparison');
  }
  if (typeof fn !== 'function') {
    log(fn);
    throw new Error('two statements');
  }
  throw new Error('bare throw');
  function inner() {
    throw new Error('function body');
  }
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7786"), 0);
    }

    #[test]
    fn s7786_reports_in_both_languages() {
        let js_source = "\
function keep(value) {
  if (typeof value !== 'string') {
    throw new Error('string required');
  }
}
";
        let ts_source = "\
function keep(value: unknown) {
  if (typeof value !== 'string') {
    throw new Error('string required');
  }
}
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7786"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7786"), 1);
    }
}
