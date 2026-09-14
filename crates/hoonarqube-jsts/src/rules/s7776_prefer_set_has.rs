// Rule module s7776_prefer_set_has (generated).
//
// `javascript:S7776` + `typescript:S7776` — Arrays used only for existence
// checks should be Sets. Reference semantics: eslint-plugin-unicorn
// `prefer-set-has` at the version pinned by SonarJS 13.x (v65.0.1, wrapped
// by SonarJS S7776).
//
// A non-exported `const` declarator initialized with an array-shaped
// expression (array literal, `Array()`/`new Array()`, `Array.from()`/
// `Array.of()`, the array-returning method list, or `slice`/`concat` on a
// non-string receiver) is reported when every remaining reference is an
// existence check (`includes(...)` with one argument), a `length` read, or
// one of the Set-compatible extra uses (`for-of` iteration, argument/array
// spread, single-callback `forEach`). Extras additionally require a known
// unique literal array; a single `includes` use must be called repeatedly
// (inside a loop or function between the call and the declaration).
// Reassignment, indexing, mutation, optional access, and exported identity
// stay silent. The report anchors on the declarator identifier with the
// reference message "`NAME` should be a `Set`, and use `NAME.has()` to
// check existence or non-existence." No auto-fix is offered.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    ArrayExpressionElement, BindingPattern, CallExpression, Expression, FormalParameters,
    StaticMemberExpression, VariableDeclarationKind, VariableDeclarator,
};
use oxc_semantic::{Semantic, SymbolId};
use oxc_span::GetSpan;
use oxc_syntax::node::NodeId;

/// The reference `methodsReturnsArray` (plus the `Array` constructor and
/// `Array.from`/`Array.of` initializers).
const ARRAY_RETURNING_METHODS: [&str; 15] = [
    "copyWithin",
    "fill",
    "filter",
    "flat",
    "flatMap",
    "map",
    "reverse",
    "sort",
    "splice",
    "toReversed",
    "toSorted",
    "toSpliced",
    "with",
    "split",
    "toArray",
];

/// How one non-declaration reference to the candidate array is used.
enum ReferenceClass {
    /// `NAME.includes(x)` — the includes call node.
    Includes(NodeId),
    /// `NAME.length` — counted as a Set-compatible extra use.
    Length,
    /// `for-of` iteration, spread, or single-callback `forEach`.
    Extra,
}

struct ReferenceGroups {
    includes: Vec<NodeId>,
    extra: usize,
}

/// Entry point: `javascript:S7776` + `typescript:S7776`
/// prefer-set-has check over the parsed program.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    if let Some(semantic) = ctx.semantic {
        for node in semantic.nodes().iter() {
            if let AstKind::VariableDeclarator(declarator) = node.kind() {
                check_declarator(&mut sink, semantic, node.id(), declarator);
            }
        }
    }
    sink.issues
}

/// The reference `Identifier` listener: a non-exported `const` declarator
/// initialized with an array-shaped expression whose references are only
/// existence checks, length reads, and Set-compatible extras.
fn check_declarator(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    declarator_node_id: NodeId,
    declarator: &VariableDeclarator<'_>,
) {
    let BindingPattern::BindingIdentifier(identifier) = &declarator.id else {
        return;
    };
    let Some(init) = declarator.init.as_ref() else {
        return;
    };
    if !is_const_declaration(semantic, declarator_node_id)
        || is_exported_declaration(semantic, declarator_node_id)
        || !is_array_shaped_init(init)
    {
        return;
    }
    let Some(symbol_id) = identifier.symbol_id.get() else {
        return;
    };
    let Some(groups) = classify_references(semantic, symbol_id) else {
        return;
    };
    if groups.includes.is_empty() {
        return;
    }
    if groups.extra > 0 && !is_known_unique_array_expression(init) {
        return;
    }
    if groups.includes.len() == 1
        && !is_multiple_call(semantic, groups.includes[0], declarator_node_id)
    {
        return;
    }
    let name = identifier.name.as_str();
    sink.emit_span(
        RuleScope::Both,
        "S7776",
        &format!(
            "`{name}` should be a `Set`, and use `{name}.has()` to check existence or non-existence."
        ),
        identifier.span,
    );
}

/// Whether the declarator's parent declaration is a `const`.
fn is_const_declaration(semantic: &Semantic<'_>, declarator_node_id: NodeId) -> bool {
    match semantic.nodes().parent_node(declarator_node_id).kind() {
        AstKind::VariableDeclaration(declaration) => {
            declaration.kind == VariableDeclarationKind::Const
        }
        _ => false,
    }
}

/// The reference export exclusion: `export const foo = [...]` keeps its
/// public array identity.
fn is_exported_declaration(semantic: &Semantic<'_>, declarator_node_id: NodeId) -> bool {
    let declaration = semantic.nodes().parent_node(declarator_node_id);
    matches!(
        semantic.nodes().parent_node(declaration.id()).kind(),
        AstKind::ExportDeclaration(_)
    )
}

/// The reference `isArrayMethodCall` (minus the alias-tracking
/// `slice`/`concat` identifier branch, which stays conservatively silent).
fn is_array_shaped_init(init: &Expression<'_>) -> bool {
    match unparenthesized(init) {
        Expression::ArrayExpression(_) => true,
        Expression::CallExpression(call) => is_array_call(call),
        Expression::NewExpression(new_expression) => {
            matches!(
                unparenthesized(&new_expression.callee),
                Expression::Identifier(callee) if callee.name == "Array"
            )
        }
        _ => false,
    }
}

/// `Array(...)`, `Array.from()`, `Array.of()`, the array-returning method
/// list, and `slice`/`concat` on a non-string receiver.
fn is_array_call(call: &CallExpression<'_>) -> bool {
    if call.optional {
        return false;
    }
    match unparenthesized(&call.callee) {
        Expression::Identifier(callee) => callee.name == "Array",
        Expression::StaticMemberExpression(member) => {
            if member.optional {
                return false;
            }
            let name = member.property.name.as_str();
            match unparenthesized(&member.object) {
                Expression::Identifier(object) if object.name == "Array" => {
                    name == "from" || name == "of"
                }
                object => {
                    ARRAY_RETURNING_METHODS.contains(&name)
                        || ((name == "slice" || name == "concat") && !is_string_literal(object))
                }
            }
        }
        _ => false,
    }
}

/// The reference `isStringLiteral`: a string literal or an expression-free
/// template literal.
fn is_string_literal(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::StringLiteral(_) => true,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        _ => false,
    }
}

/// Walk every resolved reference of the symbol into the reference classes;
/// any unclassified use rejects the candidate.
fn classify_references(semantic: &Semantic<'_>, symbol_id: SymbolId) -> Option<ReferenceGroups> {
    let scoping = semantic.scoping();
    let mut groups = ReferenceGroups {
        includes: Vec::new(),
        extra: 0,
    };
    for &reference_id in scoping.get_resolved_reference_ids(symbol_id) {
        match classify_reference(semantic, scoping.get_reference(reference_id).node_id())? {
            ReferenceClass::Includes(call_node_id) => groups.includes.push(call_node_id),
            ReferenceClass::Length | ReferenceClass::Extra => groups.extra += 1,
        }
    }
    Some(groups)
}

/// Classify one identifier reference by its surrounding shape.
fn classify_reference(
    semantic: &Semantic<'_>,
    reference_node_id: NodeId,
) -> Option<ReferenceClass> {
    let nodes = semantic.nodes();
    let AstKind::IdentifierReference(identifier) = nodes.get_node(reference_node_id).kind() else {
        return None;
    };
    let parent = nodes.parent_node(reference_node_id);
    match parent.kind() {
        AstKind::StaticMemberExpression(member) if member.object.span() == identifier.span() => {
            classify_member_reference(semantic, parent.id(), member)
        }
        AstKind::ForOfStatement(for_of) if for_of.right.span() == identifier.span() => {
            Some(ReferenceClass::Extra)
        }
        AstKind::SpreadElement(spread) if spread.argument.span() == identifier.span() => {
            classify_spread_reference(semantic, parent.id())
        }
        _ => None,
    }
}

/// `.includes(x)` calls, single-callback `.forEach(...)` uses, and bare
/// `.length` reads; every other member shape rejects the candidate.
fn classify_member_reference(
    semantic: &Semantic<'_>,
    member_node_id: NodeId,
    member: &StaticMemberExpression<'_>,
) -> Option<ReferenceClass> {
    if member.optional {
        return None;
    }
    let nodes = semantic.nodes();
    let grandparent = nodes.parent_node(member_node_id);
    let call = match grandparent.kind() {
        AstKind::CallExpression(call) if call.callee.span() == member.span() => call,
        _ => {
            if member.property.name == "length"
                && !member_is_assignment_target(semantic, member_node_id)
            {
                return Some(ReferenceClass::Length);
            }
            return None;
        }
    };
    if call.optional || call.arguments.len() != 1 {
        return None;
    }
    let argument = call.arguments[0].as_expression();
    match member.property.name.as_str() {
        "includes" if argument.is_some() => Some(ReferenceClass::Includes(grandparent.id())),
        "forEach" if is_one_parameter_arrow(argument) => Some(ReferenceClass::Extra),
        _ => None,
    }
}
/// Spread uses inside an array literal, call, or `new` expression.
fn classify_spread_reference(
    semantic: &Semantic<'_>,
    spread_node_id: NodeId,
) -> Option<ReferenceClass> {
    match semantic.nodes().parent_node(spread_node_id).kind() {
        AstKind::ArrayExpression(_) | AstKind::CallExpression(_) | AstKind::NewExpression(_) => {
            Some(ReferenceClass::Extra)
        }
        _ => None,
    }
}

/// The reference `isAssignmentTarget` above the `.length` member.
fn member_is_assignment_target(semantic: &Semantic<'_>, member_node_id: NodeId) -> bool {
    let nodes = semantic.nodes();
    let mut current = member_node_id;
    loop {
        let current_span = nodes.get_node(current).kind().span();
        match nodes.parent_node(current).kind() {
            AstKind::TSAsExpression(_)
            | AstKind::TSNonNullExpression(_)
            | AstKind::TSTypeAssertion(_) => {
                current = nodes.parent_node(current).id();
            }
            AstKind::AssignmentExpression(assignment) => {
                return assignment.left.span() == current_span;
            }
            AstKind::AssignmentPattern(pattern) => {
                return pattern.left.span() == current_span;
            }
            AstKind::UpdateExpression(update) => {
                return update.argument.span() == current_span;
            }
            AstKind::ForInStatement(for_in) => return for_in.left.span() == current_span,
            AstKind::ForOfStatement(for_of) => return for_of.left.span() == current_span,
            _ => return false,
        }
    }
}

/// The reference `isOneParameterArrowFunction`.
fn is_one_parameter_arrow(expression: Option<&Expression<'_>>) -> bool {
    let Some(Expression::ArrowFunctionExpression(arrow)) = expression.map(unparenthesized) else {
        return false;
    };
    is_single_non_rest_parameter(&arrow.params)
}

fn is_single_non_rest_parameter(parameters: &FormalParameters<'_>) -> bool {
    parameters.rest.is_none() && parameters.items.len() == 1
}

/// The reference `isMultipleCall`: a loop or function between the includes
/// call and the declaration statement means the check runs repeatedly.
fn is_multiple_call(
    semantic: &Semantic<'_>,
    call_node_id: NodeId,
    declarator_node_id: NodeId,
) -> bool {
    let nodes = semantic.nodes();
    let declaration_node_id = nodes.parent_node(declarator_node_id).id();
    let stop_node_id = nodes.parent_node(declaration_node_id).id();
    for ancestor_id in nodes.ancestor_ids(call_node_id) {
        if ancestor_id == stop_node_id {
            return false;
        }
        if is_repeated_context(nodes.get_node(ancestor_id).kind()) {
            return true;
        }
    }
    false
}

fn is_repeated_context(kind: AstKind<'_>) -> bool {
    matches!(
        kind,
        AstKind::ForOfStatement(_)
            | AstKind::ForStatement(_)
            | AstKind::ForInStatement(_)
            | AstKind::WhileStatement(_)
            | AstKind::DoWhileStatement(_)
            | AstKind::Function(_)
            | AstKind::ArrowFunctionExpression(_)
    )
}

/// The reference `isKnownUniqueArrayExpression`: a literal array of static
/// comparable values without holes, spread, or duplicate values.
fn is_known_unique_array_expression(init: &Expression<'_>) -> bool {
    let Expression::ArrayExpression(array) = unparenthesized(init) else {
        return false;
    };
    let mut values: Vec<StaticValue<'_>> = Vec::new();
    for element in &array.elements {
        if element.is_elision() || element.is_spread() {
            return false;
        }
        let Some(value) = static_element_value(element) else {
            return false;
        };
        if values.contains(&value) {
            return false;
        }
        values.push(value);
    }
    true
}

#[derive(PartialEq)]
enum StaticValue<'a> {
    Text(&'a str),
    Number(f64),
    Boolean(bool),
    Null,
}

/// The reference `getStaticValue` + `isComparableStaticValue` subset for
/// literal elements; `-0` is excluded (the reference `Object.is` guard).
fn static_element_value<'a>(element: &ArrayExpressionElement<'a>) -> Option<StaticValue<'a>> {
    match element {
        ArrayExpressionElement::StringLiteral(literal) => {
            Some(StaticValue::Text(literal.value.as_str()))
        }
        ArrayExpressionElement::BooleanLiteral(literal) => {
            Some(StaticValue::Boolean(literal.value))
        }
        ArrayExpressionElement::NullLiteral(_) => Some(StaticValue::Null),
        ArrayExpressionElement::NumericLiteral(literal) => static_number(literal.value),
        ArrayExpressionElement::TemplateLiteral(template) => {
            if !template.expressions.is_empty() {
                return None;
            }
            let quasi = template.quasis.first()?;
            quasi
                .value
                .cooked
                .as_ref()
                .map(|cooked| StaticValue::Text(cooked.as_str()))
        }
        ArrayExpressionElement::UnaryExpression(unary) => {
            let Expression::NumericLiteral(literal) = unparenthesized(&unary.argument) else {
                return None;
            };
            let negated = unary.operator == oxc_ast::ast::UnaryOperator::UnaryNegation;
            static_number(if negated {
                -literal.value
            } else {
                literal.value
            })
        }
        _ => None,
    }
}

fn static_number<'a>(value: f64) -> Option<StaticValue<'a>> {
    if value == 0.0 && value.is_sign_negative() {
        return None;
    }
    Some(StaticValue::Number(value))
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7776_flags_pinned_axios_form_data_anchor() {
        // Pinned anchor: axios/axios@18e7dfe
        // lib/core/setFormDataHeaders.js:3 — Sonar: `FORM_DATA_CONTENT_HEADERS`
        // should be a `Set`, and use `FORM_DATA_CONTENT_HEADERS.has()` ...
        let source = "\
'use strict';

const FORM_DATA_CONTENT_HEADERS = ['content-type', 'content-length'];

export default function setFormDataHeaders(headers, formHeaders, policy) {
  if (policy !== 'content-only') {
    headers.set(formHeaders);
    return;
  }

  Object.entries(formHeaders || {}).forEach(([key, val]) => {
    if (FORM_DATA_CONTENT_HEADERS.includes(key.toLowerCase())) {
      headers.set(key, val);
    }
  });
}
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7776"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S7776")
            .expect("pinned axios existence array must be reported");
        assert_eq!(
            issue.message,
            "`FORM_DATA_CONTENT_HEADERS` should be a `Set`, and use \
             `FORM_DATA_CONTENT_HEADERS.has()` to check existence or non-existence."
        );
        assert_eq!(issue.range.start.line, 3);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("const ".len()).unwrap()
        );
    }

    #[test]
    fn s7776_flags_repeated_includes_uses() {
        let source = "\
const MODES = ['a', 'b'];
const both = MODES.includes('a') || MODES.includes('b');
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7776"), 1);
        assert!(keys.contains(&("javascript:S7776".to_string(), 1)));
    }

    #[test]
    fn s7776_flags_single_looped_include_with_length_reads() {
        let source = "\
const ITEMS = ['a', 'b'];
function total() {
  if (ITEMS.length > 0 && ITEMS.includes('a')) {
    return ITEMS.length;
  }
  return 0;
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7776"), 1);
    }

    #[test]
    fn s7776_flags_for_of_iteration_with_unique_literals() {
        let source = "\
const ROLES = ['admin', 'user'];
for (const role of ROLES) {
  if (ROLES.includes(role)) {
    grant(role);
  }
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7776"), 1);
    }

    #[test]
    fn s7776_flags_array_shaped_initializers() {
        let source = "\
const fromCtor = Array(3);
const a1 = fromCtor.includes(1) || fromCtor.includes(2);
const mapped = ['x'].map((value) => value);
const m1 = mapped.includes('x') || mapped.includes('y');
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7776"), 2);
    }

    #[test]
    fn s7776_controls_stay_silent() {
        let source = "\
let mutable = ['a'];
const once = ['x'];
if (once.includes('x')) {
  hit();
}
const pushed = ['a'];
if (pushed.includes('a') || pushed.includes('b')) {
  pushed.push('c');
}
export const exported = ['a', 'b'];
const e1 = exported.includes('a');
const e2 = exported.includes('b');
const indexed = ['a', 'b'];
const first = indexed.includes('a') && indexed[0] === 'a';
const optionalChained = ['a'];
const o1 = optionalChained.includes('a') || optionalChained?.includes('b');
const dupExtra = ['a', 'a'];
for (const item of dupExtra) {
  if (dupExtra.includes(item)) {
    hit();
  }
}
const reassigned = ['a'];
reassigned = ['b'];
if (reassigned.includes('a')) {
  hit();
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7776"), 0);
    }

    #[test]
    fn s7776_reports_in_both_languages() {
        let js_source = "\
const MODES = ['a', 'b'];
const both = MODES.includes('a') || MODES.includes('b');
";
        let ts_source = "\
const roles: string[] = ['admin', 'user'];
function has(role: string) {
  return roles.includes(role) || roles.length > 0;
}
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7776"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7776"), 1);
    }
}
