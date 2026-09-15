// Rule module s7760_prefer_default_parameters (generated).
//
// `javascript:S7760` + `typescript:S7760` — default parameters should be
// used instead of reassigning parameters with literal fallback values.
// Reference semantics: eslint-plugin-unicorn `prefer-default-parameters`
// at the version pinned by SonarJS 13.x (v65.0.1, wrapped by SonarJS
// S7760): inside a function, an expression statement `param = param ||
// <literal>` / `param = param ?? <literal>` (same identifier on both
// sides) or a first declarator `const x = param || <literal>` /
// `const x = param ?? <literal>` is reported on the whole statement or
// declaration with "Prefer default parameters over reassignment.".
//
// The reference guards, all implemented: the fallback must be a `Literal`
// (string/number/boolean/null/bigint/regex), the parameter must be the
// function's last parameter, no earlier statement in the function body
// may contain a call expression, and the parameter must have no extra
// references (for the assignment form the first reference must be the
// assignment target; for the declaration form the parameter may only be
// referenced once). Non-last parameters, non-literal fallbacks, and
// parameters read before the defaulting statement stay silent. The
// reference offers a suggestion only; no auto-fix is offered here.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{ArrowFunctionBody, AssignmentTarget, Expression, LogicalOperator};
use oxc_semantic::{AstNode, Semantic};
use oxc_span::GetSpan;
use oxc_syntax::symbol::SymbolId;

/// Entry point: `javascript:S7760` + `typescript:S7760`
/// prefer-default-parameters check over the parsed program. Requires the
/// semantic model for parameter/reference resolution, so
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
            AstKind::ExpressionStatement(statement) => {
                check_expression_statement(&mut sink, semantic, node, statement);
            }
            AstKind::VariableDeclaration(declaration) => {
                check_variable_declaration(&mut sink, semantic, node, declaration);
            }
            _ => {}
        }
    }
    sink.issues
}

/// `param = param || <literal>` / `param = param ?? <literal>` as an
/// expression statement.
fn check_expression_statement(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    statement: &oxc_ast::ast::ExpressionStatement<'_>,
) {
    let Expression::AssignmentExpression(assignment) = unparenthesized(&statement.expression)
    else {
        return;
    };
    if assignment.operator != oxc_ast::ast::AssignmentOperator::Assign {
        return;
    }
    let AssignmentTarget::AssignmentTargetIdentifier(left) = &assignment.left else {
        return;
    };
    let Some((parameter_name, _literal)) = default_expression(&assignment.right) else {
        return;
    };
    if left.name != parameter_name {
        return;
    }
    let Some(function_node) = enclosing_function(semantic, node) else {
        return;
    };
    let Some(symbol) = resolve_symbol(semantic, node, parameter_name) else {
        return;
    };
    if !is_last_parameter(semantic, function_node, symbol) {
        return;
    }
    if has_side_effects(semantic, function_node, node) {
        return;
    }
    // Assignment form: the parameter's first reference must be the
    // assignment target itself.
    let mut references = semantic.scoping().get_resolved_references(symbol);
    let Some(first) = references.next() else {
        return;
    };
    if first.node_id() != left.node_id.get() {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S7760",
        "Prefer default parameters over reassignment.",
        statement.span(),
    );
}

/// `const x = param || <literal>` / `const x = param ?? <literal>` as the
/// first declarator of a declaration.
fn check_variable_declaration(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    declaration: &oxc_ast::ast::VariableDeclaration<'_>,
) {
    let Some(declarator) = declaration.declarations.first() else {
        return;
    };
    let Some(init) = declarator.init.as_ref() else {
        return;
    };
    let Some((parameter_name, _literal)) = default_expression(init) else {
        return;
    };
    let Some(function_node) = enclosing_function(semantic, node) else {
        return;
    };
    let Some(symbol) = resolve_symbol(semantic, node, parameter_name) else {
        return;
    };
    if !is_last_parameter(semantic, function_node, symbol) {
        return;
    }
    if has_side_effects(semantic, function_node, node) {
        return;
    }
    // Declaration form: the parameter may only be referenced once (the
    // use inside this initializer).
    if semantic.scoping().get_resolved_reference_ids(symbol).len() != 1 {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S7760",
        "Prefer default parameters over reassignment.",
        declaration.span(),
    );
}

/// `isDefaultExpression`: `<identifier> || <literal>` or
/// `<identifier> ?? <literal>`; returns the identifier name and literal.
fn default_expression<'a>(right: &'a Expression<'a>) -> Option<(&'a str, &'a Expression<'a>)> {
    let Expression::LogicalExpression(logical) = unparenthesized(right) else {
        return None;
    };
    if !matches!(
        logical.operator,
        LogicalOperator::Or | LogicalOperator::Coalesce
    ) {
        return None;
    }
    let Expression::Identifier(identifier) = unparenthesized(&logical.left) else {
        return None;
    };
    let literal = unparenthesized(&logical.right);
    if !is_literal(literal) {
        return None;
    }
    Some((identifier.name.as_str(), literal))
}

/// ESTree `Literal`: string/number/boolean/null/bigint/regex literals.
fn is_literal(expression: &Expression<'_>) -> bool {
    matches!(
        expression,
        Expression::StringLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::RegExpLiteral(_)
    )
}

/// The nearest enclosing `Function`/`ArrowFunctionExpression` ancestor
/// (the reference's innermost function-stack entry).
fn enclosing_function<'a, 'b>(
    semantic: &'a Semantic<'b>,
    node: &AstNode<'b>,
) -> Option<&'a AstNode<'b>> {
    let nodes = semantic.nodes();
    let mut current = node.id();
    loop {
        let parent = nodes.parent_node(current);
        if parent.id() == current {
            return None;
        }
        if matches!(
            parent.kind(),
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        ) {
            return Some(parent);
        }
        current = parent.id();
    }
}

/// `findVariable` for a name referenced inside `node`'s scope.
fn resolve_symbol(semantic: &Semantic<'_>, node: &AstNode<'_>, name: &str) -> Option<SymbolId> {
    semantic
        .scoping()
        .find_binding(node.scope_id(), name.into())
}

/// `isLastParameter`: the resolved symbol must be the last formal
/// parameter of `function_node`.
fn is_last_parameter(
    semantic: &Semantic<'_>,
    function_node: &AstNode<'_>,
    symbol: SymbolId,
) -> bool {
    if semantic.scoping().symbol_declarations(symbol).count() != 1 {
        return false;
    }
    let declaration = semantic.symbol_declaration(symbol);
    let AstKind::FormalParameter(parameter) = semantic.nodes().kind(declaration.id()) else {
        return false;
    };
    let params = match function_node.kind() {
        AstKind::Function(function) => &function.params,
        AstKind::ArrowFunctionExpression(arrow) => &arrow.params,
        _ => return false,
    };
    params
        .items
        .last()
        .is_some_and(|last| last.node_id.get() == parameter.node_id.get())
}

/// `hasSideEffects`: a statement before `node` in the function body
/// contains a call expression.
fn has_side_effects(
    semantic: &Semantic<'_>,
    function_node: &AstNode<'_>,
    node: &AstNode<'_>,
) -> bool {
    let statements = match function_node.kind() {
        AstKind::Function(function) => function
            .body
            .as_ref()
            .map(|body| body.statements.as_slice()),
        AstKind::ArrowFunctionExpression(arrow) => match &arrow.body {
            ArrowFunctionBody::FunctionBody(body) => Some(body.statements.as_slice()),
            _ => None,
        },
        _ => None,
    };
    let Some(statements) = statements else {
        return false;
    };
    let target_span = node.kind().span();
    for statement in statements {
        if statement.span() == target_span {
            break;
        }
        if contains_call_expression(semantic, statement.span()) {
            return true;
        }
    }
    false
}

/// Whether any descendant-or-self node inside `span` is a call
/// expression (the reference's recursive `containsCallExpression`).
fn contains_call_expression(semantic: &Semantic<'_>, span: oxc_span::Span) -> bool {
    semantic.nodes().iter().any(|node| {
        let node_span = node.kind().span();
        node_span.start >= span.start
            && node_span.end <= span.end
            && matches!(node.kind(), AstKind::CallExpression(_))
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7760_flags_parameter_reassignment_and_declaration() {
        let source = "\
function setWidth(width) {
  width = width || 100;
  return width;
}
function setHeight(height) {
  const fallback = height ?? 50;
  return fallback;
}
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7760"), 2);
    }

    #[test]
    fn s7760_flags_typescript_too() {
        let source = "function f(size: number) { size = size || 10; return size; }\n";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7760"), 1);
    }

    #[test]
    fn s7760_ignores_non_last_params_side_effects_and_extra_refs() {
        let source = "\
function two(a, b) {
  a = a || 1;
  return a + b;
}
function calls(x) {
  setup();
  x = x || 2;
  return x;
}
function readFirst(y) {
  log(y);
  y = y || 3;
  return y;
}
function reused(z) {
  const copy = z;
  const fallback = z || 4;
  return copy + fallback;
}
function nonLiteral(w, other) {
  w = w || other;
  return w;
}
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7760"), 0);
    }
}
