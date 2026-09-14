// Rule module s7746_useless_promise_resolve_reject (generated).
//
// `javascript:S7746` + `typescript:S7746` — Promise.resolve() and
// Promise.reject() should not be used in async functions or promise
// callbacks. Reference semantics: eslint-plugin-unicorn
// `no-useless-promise-resolve-reject` at the version pinned by SonarJS 13.x
// (v65.0.1, wrapped by SonarJS S7746): a `Promise.resolve(...)` or
// `Promise.reject(...)` call (non-optional member on the `Promise`
// identifier) whose result is returned, yielded, or is an arrow-function
// body is reported on the callee when the nearest enclosing function is
// `async` or a `.then()`/`.catch()`/`.finally()` callback. The wording
// distinguishes `return` from `yield`. Plain functions, awaited results,
// standalone statements, aliases, `new`, optional chains, and unrelated
// callbacks (`.map`) stay silent. No auto-fix is offered: rejection-order
// and microtask semantics must be qualified before any rewrite.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{Argument, CallExpression, Expression};
use oxc_semantic::{AstNode, AstNodes};
use oxc_span::GetSpan;
use oxc_syntax::node::NodeId;

/// Entry point: `javascript:S7746` + `typescript:S7746` useless
/// `Promise.resolve`/`Promise.reject` check over the parsed program.
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
        if let AstKind::CallExpression(call) = node.kind() {
            check_call(&mut sink, semantic.nodes(), node.id(), call);
        }
    }
    sink.issues
}

/// The reference report: a non-optional `Promise.resolve`/`Promise.reject`
/// member call whose result is returned, yielded, or is an arrow body, in
/// an `async` function or a `.then()`/`.catch()`/`.finally()` callback.
/// The finding covers the callee. `await`ed results, plain functions, and
/// unrelated callbacks stay silent.
fn check_call(
    sink: &mut IssueSink<'_>,
    nodes: &AstNodes<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
) {
    let Expression::StaticMemberExpression(member) = &call.callee else {
        return;
    };
    if call.optional || member.optional {
        return;
    }
    let Expression::Identifier(object) = &member.object else {
        return;
    };
    if object.name != "Promise" {
        return;
    }
    let method = member.property.name.as_str();
    if method != "resolve" && method != "reject" {
        return;
    }
    let parent = nodes.parent_node(node_id);
    let parent_kind = parent.kind();
    let is_reported_position = match parent_kind {
        AstKind::ReturnStatement(returned) => returned
            .argument
            .as_ref()
            .map(unparenthesized)
            .is_some_and(|argument| argument.span() == call.span),
        AstKind::YieldExpression(yielded) => {
            !yielded.delegate
                && yielded
                    .argument
                    .as_ref()
                    .map(unparenthesized)
                    .is_some_and(|argument| argument.span() == call.span)
        }
        AstKind::ArrowFunctionExpression(arrow) => arrow
            .body
            .as_expression()
            .map(unparenthesized)
            .is_some_and(|expression| expression.span() == call.span),
        _ => false,
    };
    if !is_reported_position {
        return;
    }
    let type_word = if matches!(parent_kind, AstKind::YieldExpression(_)) {
        "yield"
    } else {
        "return"
    };
    let Some(function) = nearest_function(nodes, parent) else {
        return;
    };
    if !is_async(function) && !is_promise_callback(nodes, function) {
        return;
    }
    let message = if method == "resolve" {
        format!("Prefer `{type_word} value` over `{type_word} Promise.resolve(value)`.")
    } else {
        format!("Prefer `throw error` over `{type_word} Promise.reject(error)`.")
    };
    sink.emit_span(RuleScope::Both, "S7746", &message, member.span());
}

/// The nearest enclosing function node, starting at `start` itself.
fn nearest_function<'a, 'b>(
    nodes: &'b AstNodes<'a>,
    start: &'b AstNode<'a>,
) -> Option<&'b AstNode<'a>> {
    std::iter::once(start)
        .chain(nodes.ancestors(start.id()))
        .find(|node| {
            matches!(
                node.kind(),
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
            )
        })
}

fn is_async(function: &AstNode<'_>) -> bool {
    match function.kind() {
        AstKind::Function(function) => function.r#async,
        AstKind::ArrowFunctionExpression(arrow) => arrow.r#async,
        _ => false,
    }
}

/// Whether the function is used as a `.then()`/`.catch()`/`.finally()`
/// callback: single-argument calls for all three names, or the second
/// argument of a two-argument `.then()`.
fn is_promise_callback(nodes: &AstNodes<'_>, function: &AstNode<'_>) -> bool {
    let parent = nodes.parent_node(function.id());
    let AstKind::CallExpression(call) = parent.kind() else {
        return false;
    };
    let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
        return false;
    };
    if member.property.name != "then"
        && member.property.name != "catch"
        && member.property.name != "finally"
    {
        return false;
    }
    let arguments = &call.arguments;
    if arguments.len() == 1 {
        return argument_is_function(arguments.first(), function);
    }
    if arguments.len() == 2 && member.property.name == "then" {
        return argument_is_function(arguments.first(), function)
            || (!matches!(arguments.first(), Some(Argument::SpreadElement(_)))
                && argument_is_function(arguments.get(1), function));
    }
    false
}

fn argument_is_function(argument: Option<&Argument<'_>>, function: &AstNode<'_>) -> bool {
    let span = function.span();
    argument
        .and_then(Argument::as_expression)
        .map(unparenthesized)
        .is_some_and(|expression| expression.span() == span)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7746_flags_pinned_axios_on_adapter_rejection_anchor() {
        // Pinned anchor: axios/axios@18e7dfed lib/core/dispatchRequest.js:92
        // `return Promise.reject(reason);` inside `onAdapterRejection`, the
        // second `.then(onAdapterResolution, onAdapterRejection)` callback.
        let source = "\
function dispatch(config) {
  return adapter(config).then(
    function onAdapterResolution(response) {
      return transform(response);
    },
    function onAdapterRejection(reason) {
      if (reason && reason.response) {
        reason.response.headers = parse(reason.response.headers);
      }
      return Promise.reject(reason);
    }
  );
}
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7746"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S7746")
            .expect("pinned axios onAdapterRejection must be reported");
        assert_eq!(
            issue.message,
            "Prefer `throw error` over `return Promise.reject(error)`."
        );
        assert_eq!(issue.range.start.line, 10);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("      return ".len()).unwrap()
        );
        assert_eq!(issue.range.end.line, 10);
        assert_eq!(
            issue.range.end.column,
            u32::try_from("      return Promise.reject".len()).unwrap()
        );
    }

    #[test]
    fn s7746_flags_async_and_callback_forms() {
        let source = "\
async function load(check) {
  if (check) {
    return Promise.resolve(fallback());
  }
  return Promise.reject(new Error(\"no\"));
}
function viaThen() {
  return fetchIt().then((result) => Promise.resolve(result));
}
function viaThenRejection() {
  return fetchIt().then((result) => result, (error) => Promise.reject(error));
}
function viaCatch() {
  return fetchIt().catch((error) => Promise.reject(error));
}
async function* viaYield() {
  yield Promise.resolve(1);
}
function viaFinally() {
  return fetchIt().finally(() => Promise.resolve());
}
";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7746"), 7);
    }

    #[test]
    fn s7746_messages_match_reference_wording() {
        let source = "\
async function resolveValue() {
  return Promise.resolve(1);
}
async function* yieldValue() {
  yield Promise.resolve(2);
}
function rejectError() {
  return fetchIt().then(function () {}, function (error) {
    return Promise.reject(error);
  });
}
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7746"), 3);
        let messages: Vec<&str> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "typescript:S7746")
            .map(|issue| issue.message.as_str())
            .collect();
        assert!(messages.contains(&"Prefer `return value` over `return Promise.resolve(value)`."));
        assert!(messages.contains(&"Prefer `yield value` over `yield Promise.resolve(value)`."));
        assert!(messages.contains(&"Prefer `throw error` over `return Promise.reject(error)`."));
    }

    #[test]
    fn s7746_plain_functions_awaits_and_other_contexts_stay_silent() {
        let silent = "\
function plain() {
  return Promise.resolve(1);
}
async function awaited() {
  return await Promise.resolve(1);
}
function mapped(list) {
  return list.map((x) => Promise.resolve(x));
}
function aliased() {
  const P = Promise;
  return P.resolve(1);
}
function standalone() {
  Promise.resolve(1);
}
function constructed() {
  return new Promise.resolve(1);
}
function chained(lib) {
  return lib.Promise.resolve(1);
}
function optionalized() {
  return Promise?.resolve(1);
}
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7746"), 0);
    }

    #[test]
    fn s7746_reports_in_both_languages() {
        let source = "\
async function both(value) {
  return Promise.resolve(value);
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7746"), 1);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7746"), 1);
    }
}
