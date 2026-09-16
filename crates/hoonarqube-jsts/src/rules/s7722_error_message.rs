// Rule module s7722_error_message (generated).
//
// `typescript:S7722` — Built-in error objects should have meaningful
// messages. Reference semantics: eslint-plugin-unicorn `error-message`
// wrapped by SonarJS S7722 (which suppresses stack-trace-capture patterns):
// constructing or calling a built-in error constructor (`Error`,
// `EvalError`, `RangeError`, `ReferenceError`, `SyntaxError`, `TypeError`,
// `URIError`, `AggregateError`, `SuppressedError`) without a message
// argument is reported on the expression; a message argument that is
// statically known to be a non-string or the empty string is reported on
// the argument; statically unknown arguments stay silent. `AggregateError`
// carries its message at index 1 and `SuppressedError` at index 2; spread
// arguments at or before the message index stay silent; shadowed
// constructors stay silent. Direct `.stack` reads of a fresh error and
// variables used exclusively for such reads are deliberate stack-capture
// code and stay silent.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{Argument, BindingPattern, Expression, VariableDeclarator};
use oxc_semantic::{Scoping, Semantic};
use oxc_span::{GetSpan, Span};

/// The built-in error constructors tracked by the reference rule.
const BUILTIN_ERRORS: [&str; 9] = [
    "Error",
    "EvalError",
    "RangeError",
    "ReferenceError",
    "SyntaxError",
    "TypeError",
    "URIError",
    "AggregateError",
    "SuppressedError",
];

/// Entry point: `typescript:S7722` built-in error message check. Requires
/// the semantic model for shadowing and stack-capture resolution, so
/// recoverable-parse files stay silent.
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
            AstKind::CallExpression(call) => check_error_expression(
                &mut sink,
                semantic,
                node.id(),
                call.span,
                &call.callee,
                &call.arguments,
                call.optional,
            ),
            AstKind::NewExpression(new) => check_error_expression(
                &mut sink,
                semantic,
                node.id(),
                new.span,
                &new.callee,
                &new.arguments,
                false,
            ),
            _ => {}
        }
    }
    sink.issues
}

/// Reports one built-in error construction or call according to the
/// reference message/argument contract.
fn check_error_expression(
    sink: &mut IssueSink,
    semantic: &Semantic<'_>,
    node_id: oxc_syntax::node::NodeId,
    span: Span,
    callee: &Expression<'_>,
    arguments: &[Argument<'_>],
    optional: bool,
) {
    if optional {
        return;
    }
    let Some(name) = global_error_name(callee, semantic) else {
        return;
    };
    let message_index = message_argument_index(name);
    if arguments.iter().take(message_index + 1).any(is_spread) {
        return;
    }
    let Some(message_argument) = arguments.get(message_index) else {
        if !stack_capture_suppressed(semantic, node_id) {
            sink.emit_span(
                RuleScope::TsOnly,
                "S7722",
                &format!("Pass a message to the `{name}` constructor."),
                span,
            );
        }
        return;
    };
    let Some(expression) = message_argument.as_expression() else {
        return;
    };
    let Some(message) = static_message_report(unparenthesized(expression)) else {
        return;
    };
    sink.emit_span(RuleScope::TsOnly, "S7722", message, expression.span());
}

/// The constructor name when the callee is a non-shadowed built-in error.
fn global_error_name<'a>(callee: &Expression<'a>, semantic: &Semantic<'_>) -> Option<&'a str> {
    let Expression::Identifier(identifier) = callee else {
        return None;
    };
    let name = identifier.name.as_str();
    (BUILTIN_ERRORS.contains(&name) && semantic.is_reference_to_global_variable(identifier))
        .then_some(name)
}

fn message_argument_index(name: &str) -> usize {
    match name {
        "AggregateError" => 1,
        "SuppressedError" => 2,
        _ => 0,
    }
}

fn is_spread(argument: &Argument<'_>) -> bool {
    matches!(argument, Argument::SpreadElement(_))
}

/// The reference report for a statically decidable message argument:
/// `None` when the value is unknown (silent), otherwise the wording.
fn static_message_report(expression: &Expression<'_>) -> Option<&'static str> {
    match expression {
        Expression::StringLiteral(literal) => literal
            .value
            .is_empty()
            .then_some("Error message should not be an empty string."),
        Expression::TemplateLiteral(template) => {
            // A template is empty only when it has no expressions and every
            // quasi cooks to the empty string; a `${...}`-leading template
            // has an empty first quasi but a non-empty message.
            if !template.expressions.is_empty() {
                return None;
            }
            template
                .quasis
                .iter()
                .all(|quasi| quasi.value.cooked.as_deref().is_some_and(str::is_empty))
                .then_some("Error message should not be an empty string.")
        }
        Expression::ArrayExpression(_)
        | Expression::ObjectExpression(_)
        | Expression::NumericLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_) => Some("Error message should be a string."),
        Expression::Identifier(identifier) => {
            (identifier.name == "undefined").then_some("Error message should be a string.")
        }
        _ => None,
    }
}

/// The `SonarJS` S7722 decorator's stack-trace-capture exemptions: a direct
/// `.stack` read of the fresh error, or a variable initialized with it and
/// used exclusively for such reads.
fn stack_capture_suppressed(
    semantic: &Semantic<'_>,
    error_node_id: oxc_syntax::node::NodeId,
) -> bool {
    let nodes = semantic.nodes();
    let parent = nodes.parent_node(error_node_id);
    match parent.kind() {
        AstKind::StaticMemberExpression(member) => {
            member.property.name == "stack" && stack_read_context(nodes, parent.id())
        }
        AstKind::ComputedMemberExpression(member) => {
            matches!(
                unparenthesized(&member.expression),
                Expression::StringLiteral(literal) if literal.value == "stack"
            ) && stack_read_context(nodes, parent.id())
        }
        AstKind::VariableDeclarator(declarator) => {
            declarator_exclusive_stack_reads(semantic, declarator)
        }
        _ => false,
    }
}

/// Whether the `.stack` member access at `member_node_id` sits in one of the
/// reference decorator's stack-capture contexts.
fn stack_read_context(
    nodes: &oxc_semantic::AstNodes<'_>,
    member_node_id: oxc_syntax::node::NodeId,
) -> bool {
    let member_span = nodes.get_node(member_node_id).kind().span();
    let parent = nodes.parent_node(member_node_id);
    match parent.kind() {
        AstKind::ExpressionStatement(_) => true,
        AstKind::AssignmentExpression(assignment) => assignment.right.span() == member_span,
        AstKind::VariableDeclarator(declarator) => declarator
            .init
            .as_ref()
            .is_some_and(|init| init.span() == member_span),
        AstKind::ReturnStatement(returned) => returned
            .argument
            .as_ref()
            .is_some_and(|argument| argument.span() == member_span),
        // Side-effect statement calls (logging) and awaited statement calls
        // count as reads without argument-membership checks, mirroring the
        // reference decorator.
        AstKind::CallExpression(_) | AstKind::AwaitExpression(_) => {
            matches!(
                nodes.parent_kind(parent.id()),
                AstKind::ExpressionStatement(_)
            )
        }
        AstKind::ObjectProperty(property) => property.value.span() == member_span,
        _ => false,
    }
}

/// Whether the variable initialized by `declarator` is only ever read
/// through `.stack` member accesses and never reassigned.
fn declarator_exclusive_stack_reads(
    semantic: &Semantic<'_>,
    declarator: &VariableDeclarator<'_>,
) -> bool {
    let BindingPattern::BindingIdentifier(identifier) = &declarator.id else {
        return false;
    };
    let Some(symbol_id) = identifier.symbol_id.get() else {
        return false;
    };
    exclusive_stack_reads(semantic.scoping(), semantic, symbol_id)
}

fn exclusive_stack_reads(
    scoping: &Scoping,
    semantic: &Semantic<'_>,
    symbol_id: oxc_syntax::symbol::SymbolId,
) -> bool {
    let reference_ids = scoping.get_resolved_reference_ids(symbol_id);
    let mut reads = 0;
    for &reference_id in reference_ids {
        let reference = scoping.get_reference(reference_id);
        if reference.is_write() || !reference.is_read() {
            return false;
        }
        if !stack_read_reference(semantic, reference.node_id()) {
            return false;
        }
        reads += 1;
    }
    reads > 0
}

/// Whether one read reference is a `.stack` member access in a stack-capture
/// context.
fn stack_read_reference(
    semantic: &Semantic<'_>,
    reference_node_id: oxc_syntax::node::NodeId,
) -> bool {
    let nodes = semantic.nodes();
    let parent = nodes.parent_node(reference_node_id);
    match parent.kind() {
        AstKind::StaticMemberExpression(member) => {
            member.property.name == "stack" && stack_read_context(nodes, parent.id())
        }
        AstKind::ComputedMemberExpression(member) => {
            matches!(
                unparenthesized(&member.expression),
                Expression::StringLiteral(literal) if literal.value == "stack"
            ) && stack_read_context(nodes, parent.id())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7722_flags_pinned_zod_assert_never_anchor() {
        // Pinned anchor: colinhacks/zod@46da957
        // packages/zod/src/v3/helpers/util.ts:8 `throw new Error();`
        let source = "export function assertNever(_x: never): never {\n\
                      throw new Error();\n\
                      }\n";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7722"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7722")
            .expect("pinned zod assertNever empty error must be reported");
        assert_eq!(issue.message, "Pass a message to the `Error` constructor.");
        assert_eq!(issue.range.start.line, 2);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("throw ".len()).unwrap()
        );
        assert_eq!(issue.range.end.line, 2);
        assert_eq!(
            issue.range.end.column,
            u32::try_from("throw new Error()".len()).unwrap()
        );
    }

    #[test]
    fn s7722_flags_every_builtin_error_constructor_and_call_form() {
        let source = "\
new EvalError();
new RangeError();
new ReferenceError();
new SyntaxError();
new TypeError();
new URIError();
new AggregateError();
new SuppressedError();
Error();
TypeError('meaningful');
";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7722"), 9);
    }

    #[test]
    fn s7722_aggregate_and_suppressed_message_indices_match_reference() {
        let source = "\
new AggregateError();
new AggregateError(entries);
new AggregateError(entries, 'many failures');
new SuppressedError();
new SuppressedError(cause);
new SuppressedError(cause, 'after');
";
        // `AggregateError(entries)` still lacks the message at index 1, and
        // both two-argument `SuppressedError` forms lack the message at
        // index 2, exactly like the reference rule.
        let keys = ts_keys(source);
        assert_eq!(count_key(&keys, "typescript:S7722"), 5);
    }

    #[test]
    fn s7722_reports_non_string_and_empty_message_arguments() {
        let source = "\
new Error(42);
new Error(true);
new Error(null);
new Error(undefined);
new Error([]);
new Error({});
new Error('');
new Error('boom');
new Error(someVariable);
new Error(`ok`);
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7722"), 7);
        let messages: Vec<&str> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "typescript:S7722")
            .map(|issue| issue.message.as_str())
            .collect();
        assert_eq!(
            messages
                .iter()
                .filter(|message| **message == "Error message should be a string.")
                .count(),
            6
        );
        assert_eq!(
            messages
                .iter()
                .filter(|message| **message == "Error message should not be an empty string.")
                .count(),
            1
        );
        let numeric = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7722" && issue.range.start.line == 1)
            .expect("the numeric message argument must be reported");
        assert_eq!(numeric.message, "Error message should be a string.");
        assert_eq!(
            numeric.range.start.column,
            u32::try_from("new Error(".len()).unwrap()
        );
    }

    #[test]
    fn s7722_suppresses_reference_stack_capture_patterns() {
        let silent = "\
const stack = new Error().stack;
new Error().stack;
const computed = new Error()['stack'];
let err = new Error();
console.log(err.stack);
const recorded = new Error().stack;
log(recorded);
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7722"), 0);
    }

    #[test]
    fn s7722_still_reports_when_variable_escapes_stack_reads() {
        let reported = "\
let err = new Error();
console.log(err.message);
let reassigned = new Error();
reassigned = new Error('later');
console.log(reassigned.stack);
let thrown = new Error();
throw thrown;
";
        assert_eq!(count_key(&ts_keys(reported), "typescript:S7722"), 3);
    }

    #[test]
    fn s7722_shadowed_constructors_and_spread_arguments_stay_silent() {
        let silent = "\
function wrap(Error) {
  return new Error();
}
const spread = new Error(...parts);
const aggregated = new AggregateError(...list);
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7722"), 0);
    }

    #[test]
    fn s7722_template_with_expressions_or_nonempty_quasis_stays_silent() {
        // Regression of #511: a template whose first quasi is empty still
        // carries a non-empty message when it contains expressions.
        let silent = "\
throw new Error(`${method} returned null symbol for ${source.id}`);
throw new Error(`prefix ${method}`);
throw new Error(`${method}`);
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7722"), 0);

        let flagged = "throw new Error(``);\nthrow new Error('');\n";
        assert_eq!(count_key(&ts_keys(flagged), "typescript:S7722"), 2);
    }

    #[test]
    fn s7722_stays_silent_in_javascript_files() {
        let source = "throw new Error();\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7722"), 0);
    }
}
