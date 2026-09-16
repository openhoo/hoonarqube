// Rule module s7755_prefer_at (generated).
//
// `javascript:S7755` + `typescript:S7755` — Complex index access patterns
// should be replaced with ".at()" method. Reference semantics:
// eslint-plugin-unicorn `prefer-at` at the version pinned by SonarJS 13.x
// (v65.0.1, wrapped by SonarJS S7755, default options
// `checkAllIndexAccess: false`, no extra `getLastElementFunctions`):
//
// - computed member access `foo[foo.length - N]` (a positive numeric literal
//   N, including nested `length - N - 1` chains that resolve to the same
//   receiver reference) is reported on the index expression with the
//   reference message "Prefer `.at(…)` over `[….length - index]`.";
// - `foo.charAt(foo.length - N)` is reported on the index argument with
//   "Prefer `String#at(…)` over `String#charAt(….length - index)`.";
// - first-element `.slice(-N)` reads — `slice(-1)[0]`, `slice(-1).shift()`,
//   `slice(-1).pop()`, and the wider `slice(-N, -N-1)`/suggested forms — are
//   reported on the `slice` property with "Prefer `.at(…)` over the first
//   element from `.slice(…)`.";
// - `_.last(x)`, `lodash.last(x)`, and `underscore.last(x)` are reported on
//   the callee with "Prefer `.at(-1)` over `_.last(…)` to get the last
//   element.".
//
// Assignment targets, the `arguments` object, positive-index access, and
// receivers with a different reference than the `length` receiver stay
// silent. Receiver element semantics and the ES2022 `.at()` target remain
// caller-qualified per the issue guard: no auto-fix is offered.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    BinaryOperator, CallExpression, ComputedMemberExpression, Expression, StaticMemberExpression,
    UnaryOperator,
};
use oxc_semantic::{AstNode, Semantic};
use oxc_span::{GetSpan, Span};

/// Entry point: `javascript:S7755` + `typescript:S7755` prefer-at check over
/// the parsed program. Requires the semantic model for assignment-target
/// detection, so recoverable-parse files stay silent.
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
            AstKind::ComputedMemberExpression(member) => {
                check_computed_member(&mut sink, semantic, node, member);
            }
            AstKind::CallExpression(call) => {
                check_char_at(&mut sink, semantic, call);
                check_slice(&mut sink, semantic, node, call);
                check_get_last_function(&mut sink, call);
            }
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

fn is_arguments_object(expression: &Expression<'_>) -> bool {
    matches!(
        unparenthesized(expression),
        Expression::Identifier(identifier) if identifier.name == "arguments"
    )
}

fn is_literal_positive_number(expression: &Expression<'_>) -> bool {
    matches!(expression, Expression::NumericLiteral(literal) if literal.value > 0.0)
}

fn length_member_of<'a>(expression: &'a Expression<'a>) -> Option<&'a StaticMemberExpression<'a>> {
    match expression {
        Expression::StaticMemberExpression(member)
            if !member.optional && member.property.name == "length" =>
        {
            Some(member)
        }
        _ => None,
    }
}

/// The reference `getNegativeIndexLengthNode`: a `length` subtraction that
/// resolves against the same receiver, directly or through nesting.
fn get_negative_index_length_node<'a>(
    node: &'a Expression<'a>,
    object: &'a Expression<'a>,
) -> Option<&'a Expression<'a>> {
    let Expression::BinaryExpression(binary) = node else {
        return None;
    };
    if binary.operator != BinaryOperator::Subtraction || !is_literal_positive_number(&binary.right)
    {
        return None;
    }
    if let Some(length_member) = length_member_of(&binary.left)
        && is_same_reference(&length_member.object, object)
    {
        return Some(&binary.left);
    }
    get_negative_index_length_node(&binary.left, object)
}

fn unwrap_ts<'a, 'b>(expression: &'a Expression<'b>) -> &'a Expression<'b> {
    let mut current = expression;
    loop {
        match current {
            Expression::TSAsExpression(inner) => current = &inner.expression,
            Expression::TSSatisfiesExpression(inner) => current = &inner.expression,
            Expression::TSNonNullExpression(inner) => current = &inner.expression,
            Expression::TSTypeAssertion(inner) => current = &inner.expression,
            _ => return current,
        }
    }
}

/// The reference `isSameReference` subset: two expressions that reference
/// the same value.
fn is_same_reference(left: &Expression<'_>, right: &Expression<'_>) -> bool {
    let left = unwrap_ts(left);
    let right = unwrap_ts(right);
    match (left, right) {
        (Expression::ThisExpression(_), Expression::ThisExpression(_)) => true,
        (Expression::Identifier(a), Expression::Identifier(b)) => a.name == b.name,
        (Expression::StringLiteral(a), Expression::StringLiteral(b)) => a.value == b.value,
        (Expression::NumericLiteral(a), Expression::NumericLiteral(b)) => {
            same_number(a.value, b.value)
        }
        (Expression::StaticMemberExpression(a), Expression::StaticMemberExpression(b)) => {
            a.property.name == b.property.name && is_same_reference(&a.object, &b.object)
        }
        (Expression::ComputedMemberExpression(a), Expression::ComputedMemberExpression(b)) => {
            a.optional == b.optional
                && is_same_reference(&a.object, &b.object)
                && is_same_reference(&a.expression, &b.expression)
        }
        _ => false,
    }
}

/// The reference `isLeftHandSide`: assignment targets, update arguments, and
/// `delete` targets stay silent.
fn is_left_hand_side(semantic: &Semantic<'_>, node: &AstNode<'_>) -> bool {
    let span = node.kind().span();
    let parent = semantic.nodes().parent_node(node.id());
    match parent.kind() {
        AstKind::AssignmentExpression(assignment) => assignment.left.span() == span,
        AstKind::UpdateExpression(update) => update.argument.span() == span,
        AstKind::UnaryExpression(unary) => {
            unary.operator == UnaryOperator::Delete && unary.argument.span() == span
        }
        AstKind::ObjectProperty(property) => {
            property.value.span() == span
                && matches!(
                    semantic.nodes().parent_node(parent.id()).kind(),
                    AstKind::ObjectPattern(_)
                )
        }
        _ => false,
    }
}
/// The `SonarJS` decorator gates every report on `typeHasMethod(node, 'at',
/// services)` — without type information the reference stays silent. hq is
/// syntactic, so the approximation flags only receivers that are
/// self-evidently array/string *expressions* (array/string/template
/// literals, `new Array(…)`, `.split(…)` results) or `const` bindings
/// initialized to one; bare identifiers, member chains, and annotated
/// parameters stay silent, matching Sonar's silence on unresolved types.
fn is_self_evident_at_receiver(semantic: &Semantic<'_>, expression: &Expression<'_>) -> bool {
    match unwrap_ts(unparenthesized(expression)) {
        Expression::ArrayExpression(_)
        | Expression::StringLiteral(_)
        | Expression::TemplateLiteral(_) => true,
        Expression::NewExpression(new_expression) => matches!(
            unparenthesized(&new_expression.callee),
            Expression::Identifier(callee) if callee.name == "Array"
        ),
        Expression::CallExpression(call) => method_member(call, "split").is_some(),
        Expression::Identifier(identifier) => const_initializer(semantic, identifier)
            .is_some_and(|init| is_self_evident_at_receiver(semantic, init)),
        _ => false,
    }
}

/// The `const` initializer of a single-declaration identifier binding —
/// the reference's `getConstVariableInitializer` subset.
fn const_initializer<'a>(
    semantic: &Semantic<'a>,
    identifier: &oxc_ast::ast::IdentifierReference<'a>,
) -> Option<&'a Expression<'a>> {
    let symbol = identifier
        .reference_id
        .get()
        .and_then(|id| semantic.scoping().get_reference(id).symbol_id())?;
    if semantic.scoping().symbol_declarations(symbol).count() != 1 {
        return None;
    }
    let declaration = semantic.symbol_declaration(symbol);
    let AstKind::VariableDeclarator(declarator) = semantic.nodes().kind(declaration.id()) else {
        return None;
    };
    let AstKind::VariableDeclaration(kind) = semantic.nodes().parent_kind(declaration.id()) else {
        return None;
    };
    if kind.kind != oxc_ast::ast::VariableDeclarationKind::Const {
        return None;
    }
    declarator.init.as_ref()
}

fn check_computed_member(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    member: &ComputedMemberExpression<'_>,
) {
    if is_left_hand_side(semantic, node) || is_arguments_object(&member.object) {
        return;
    }
    if get_negative_index_length_node(&member.expression, &member.object).is_some()
        && is_self_evident_at_receiver(semantic, &member.object)
    {
        sink.emit_span(
            RuleScope::Both,
            "S7755",
            "Prefer `.at(…)` over `[….length - index]`.",
            member.expression.span(),
        );
    }
}

fn check_char_at(sink: &mut IssueSink<'_>, semantic: &Semantic<'_>, call: &CallExpression<'_>) {
    let Some(member) = method_member(call, "charAt") else {
        return;
    };
    if call.optional || call.arguments.len() != 1 {
        return;
    }
    let Some(index) = call.arguments[0].as_expression() else {
        return;
    };
    if get_negative_index_length_node(index, &member.object).is_none()
        || !is_self_evident_at_receiver(semantic, &member.object)
    {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S7755",
        "Prefer `String#at(…)` over `String#charAt(….length - index)`.",
        index.span(),
    );
}

fn literal_negative_integer(argument: &oxc_ast::ast::Argument<'_>) -> Option<f64> {
    let Expression::UnaryExpression(unary) = argument.as_expression()? else {
        return None;
    };
    if unary.operator != UnaryOperator::UnaryNegation {
        return None;
    }
    let Expression::NumericLiteral(literal) = unparenthesized(&unary.argument) else {
        return None;
    };
    let value = literal.value;
    (value.is_finite() && value.fract() == 0.0 && value > 0.0).then_some(value)
}

fn is_zero_literal(expression: &Expression<'_>) -> bool {
    matches!(
        unparenthesized(expression),
        Expression::NumericLiteral(literal) if literal.value == 0.0
    )
}

fn check_slice(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    call: &CallExpression<'_>,
) {
    let Some(member) = method_member(call, "slice") else {
        return;
    };
    if call.optional || call.arguments.is_empty() || call.arguments.len() > 2 {
        return;
    }
    let Some(start_value) = literal_negative_integer(&call.arguments[0]) else {
        return;
    };
    let call_span = call.span();
    let parent = semantic.nodes().parent_node(node.id());
    let mut first_element_get_method: &str = "";
    let _ = first_element_get_method;
    match parent.kind() {
        AstKind::ComputedMemberExpression(access)
            if access.object.span() == call_span
                && !access.optional
                && is_zero_literal(&access.expression) =>
        {
            if is_left_hand_side(semantic, parent) {
                return;
            }
            first_element_get_method = "zero-index";
        }
        AstKind::StaticMemberExpression(wrapper_member)
            if wrapper_member.object.span() == call_span =>
        {
            let method = wrapper_member.property.name.as_str();
            if method != "shift" && method != "pop" {
                return;
            }
            let grandparent = semantic.nodes().parent_node(parent.id());
            match grandparent.kind() {
                AstKind::CallExpression(wrapper)
                    if !wrapper.optional
                        && wrapper.arguments.is_empty()
                        && wrapper.callee.span() == parent.kind().span() => {}
                _ => return,
            }
            first_element_get_method = if method == "shift" { "shift" } else { "pop" };
        }
        _ => return,
    }
    let start_index = -start_value;
    if call.arguments.len() == 1 {
        if same_number(start_value, 1.0) {
            emit_slice(sink, member.property.span());
        }
        return;
    }
    if let Some(end_value) = literal_negative_integer(&call.arguments[1])
        && same_number(-end_value, start_index + 1.0)
    {
        emit_slice(sink, member.property.span());
        return;
    }
    if first_element_get_method == "pop" {
        return;
    }
    emit_slice(sink, member.property.span());
}

fn emit_slice(sink: &mut IssueSink<'_>, span: Span) {
    sink.emit_span(
        RuleScope::Both,
        "S7755",
        "Prefer `.at(…)` over the first element from `.slice(…)`.",
        span,
    );
}

const LAST_FUNCTIONS: [&str; 3] = ["_.last", "lodash.last", "underscore.last"];

fn check_get_last_function(sink: &mut IssueSink<'_>, call: &CallExpression<'_>) {
    if call.optional || call.arguments.len() != 1 {
        return;
    }
    let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
        return;
    };
    let Expression::Identifier(object) = unparenthesized(&member.object) else {
        return;
    };
    let name = format!("{}.{}", object.name.as_str(), member.property.name.as_str());
    if !LAST_FUNCTIONS.contains(&name.as_str()) {
        return;
    }
    let Some(argument) = call.arguments[0].as_expression() else {
        return;
    };
    if is_arguments_object(argument) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S7755",
        &format!("Prefer `.at(-1)` over `{name}(…)` to get the last element."),
        call.callee.span(),
    );
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
    fn s7755_flags_pinned_axios_to_form_data_anchor() {
        // Pinned anchor: axios/axios@18e7dfed lib/helpers/toFormData.js:173
        // `while (ancestors.length && ancestors[ancestors.length - 1] !== this) {`
        // The receiver is a `const` array binding so the self-evident
        // receiver gate admits it.
        let source = "\
const ancestors = [];
function walk() {
  while (ancestors.length && ancestors[ancestors.length - 1] !== this) {
    ancestors.pop();
  }
}
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7755"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S7755")
            .expect("pinned axios ancestors access must be reported");
        assert_eq!(issue.message, "Prefer `.at(…)` over `[….length - index]`.");
        assert_eq!(issue.range.start.line, 3);
        let prefix = "  while (ancestors.length && ancestors[";
        assert_eq!(
            issue.range.start.column,
            u32::try_from(prefix.len()).unwrap()
        );
        let index = "ancestors.length - 1";
        assert_eq!(
            issue.range.end.column,
            u32::try_from(prefix.len() + index.len()).unwrap()
        );
    }

    #[test]
    fn s7755_flags_pinned_markdown_it_table_anchor() {
        // Pinned anchor: markdown-it/markdown-it@3c51991 src/rules_block/table.ts:126+188
        // `if (columns.length && columns[columns.length - 1] === '') columns.pop()`
        // The receiver is a `const` array binding so the self-evident
        // receiver gate admits it.
        let source = "\
const columns = [''];
function table() {
  if (columns.length && columns[columns.length - 1] === '') columns.pop();
  if (columns.length && columns[columns.length - 1] === '') columns.pop();
}
";
        let keys = ts_keys(source);
        assert_eq!(count_key(&keys, "typescript:S7755"), 2);
        let findings: Vec<u32> = ts_keys(source)
            .iter()
            .filter(|(key, _)| key == "typescript:S7755")
            .map(|(_, line)| *line)
            .collect();
        assert_eq!(findings, vec![3, 4]);
    }

    #[test]
    fn s7755_flags_all_reference_case_families() {
        let source = "\
const list = [];
const first = list[list.length - 1];
const second = list[list.length - 2];
const nested = list[list.length - 1 - 1];
const half = list[list.length - 1.5];
const char = 'abc'.charAt('abc'.length - 1);
const charAt = 'abc'.charAt('abc'.length - 2);
const sl = list.slice(-1)[0];
const sh = list.slice(-1).shift();
const pop = list.slice(-1).pop();
const two = list.slice(-2, -1)[0];
const weird = list.slice(-1, -2)[0];
const lo = _.last(list);
const lo2 = lodash.last(list);
const lo3 = underscore.last(list);
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7755"), 14);
        let messages: Vec<&str> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7755")
            .map(|issue| issue.message.as_str())
            .collect();
        assert_eq!(
            messages
                .iter()
                .filter(|message| **message == "Prefer `.at(…)` over `[….length - index]`.")
                .count(),
            4
        );
        assert_eq!(
            messages
                .iter()
                .filter(|message| {
                    **message == "Prefer `String#at(…)` over `String#charAt(….length - index)`."
                })
                .count(),
            2
        );
        assert_eq!(
            messages
                .iter()
                .filter(|message| {
                    **message == "Prefer `.at(…)` over the first element from `.slice(…)`."
                })
                .count(),
            5
        );
        assert!(messages.contains(&"Prefer `.at(-1)` over `_.last(…)` to get the last element."));
        assert!(
            messages.contains(&"Prefer `.at(-1)` over `lodash.last(…)` to get the last element.")
        );
        assert!(
            messages
                .contains(&"Prefer `.at(-1)` over `underscore.last(…)` to get the last element.")
        );
    }

    #[test]
    fn s7755_non_matching_forms_stay_silent() {
        let source = "\
const list = [];
const zero = list[0];
const bareLength = list[list.length];
const other = list[missing.length - 1];
list[list.length - 1] = 1;
function args() {
  return arguments[arguments.length - 1];
}
const bareSlice = list.slice(-1);
const deepSlice = list.slice(-2);
const positiveSlice = list.slice(1)[0];
const farEnd = list.slice(-2)[0];
const notFirst = list.slice(-1)[1];
const bareLast = last(list);
const extraLast = _.last(list, 2);
const firstOf = _.first(list);
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7755"), 0);
    }

    #[test]
    fn s7755_member_receiver_negative_access_stays_silent() {
        // The receiver-type gate: a member chain is not a self-evident
        // array/string expression, so the reference stays silent without
        // type information.
        let source = "class Queue {
  last() {
    return this.items[this.items.length - 1];
  }
}
";
        let report = js(source);
        assert_eq!(count_key(&report_keys(&report), "javascript:S7755"), 0);
    }

    #[test]
    fn s7755_reports_in_both_languages() {
        let ts_source = "\
const list: string[] = [];
const first = list[list.length - 1];
";
        let js_source = "\
const list = [];
const first = list[list.length - 1];
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7755"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7755"), 1);
    }
}
