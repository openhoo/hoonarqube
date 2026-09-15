// Rule module s3512_template_literal.
//
// `javascript:S3512` + `typescript:S3512` — string concatenations that
// can be rewritten as template literals. Issue #387 restores the
// reference semantics: a `+` chain root is flagged when the chain weighs
// at least three atoms with at least one string-literal operand and at
// least one non-literal operand. Two-operand chains (`'/' + name`),
// all-literal chains (`'a' + 'b' + 'c'`), and chains already containing
// a template literal stay silent, matching the pinned express (89
// findings) and exceljs (0 findings) oracles. A chain root is the `+`
// node whose parent is not itself a `+` binary, so chains nested through
// call arguments or function bodies report independently while the
// sub-binaries of one chain stay unflagged. Requires the semantic model
// for the parent lookup; recoverable-parse files stay silent. No
// auto-fix is offered.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{BinaryOperator, Expression};
use oxc_semantic::Semantic;
use oxc_span::GetSpan;

/// Entry point: `javascript:S3512` + `typescript:S3512`
/// prefer-template-literal check over the parsed program.
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
        let AstKind::BinaryExpression(binary) = node.kind() else {
            continue;
        };
        if binary.operator != BinaryOperator::Addition
            || is_addition_child(semantic, node.id())
            || !is_template_candidate(&binary.left, &binary.right)
        {
            continue;
        }
        sink.emit_span(
            RuleScope::Both,
            "S3512",
            "Replace this string concatenation with a template literal.",
            binary.span(),
        );
    }
    sink.issues
}

/// Whether the node's parent is itself a `+` binary: then this node is a
/// mid-chain sub-binary and only the chain root is reported.
fn is_addition_child(semantic: &Semantic<'_>, node_id: oxc_syntax::node::NodeId) -> bool {
    matches!(
        semantic.nodes().parent_node(node_id).kind(),
        AstKind::BinaryExpression(parent) if parent.operator == BinaryOperator::Addition
    )
}

/// The direct `+` operands of a chain root, in source order.
/// Parenthesized sub-expressions stay single operands.
fn concat_operands<'a, 'b>(
    left: &'b Expression<'a>,
    right: &'b Expression<'a>,
) -> Vec<&'b Expression<'a>> {
    let mut operands = vec![right];
    let mut current = left;
    while let Expression::BinaryExpression(binary) = current
        && binary.operator == BinaryOperator::Addition
    {
        operands.push(&binary.right);
        current = &binary.left;
    }
    operands.push(current);
    operands.reverse();
    operands
}

/// Atom weight of an expression: a binary (parenthesized arithmetic, a
/// sub-chain, ...) weighs by its operands, anything else weighs one, so
/// `'public, max-age=' + (60 * 60 * 24 * 30)` weighs five (`S3512`).
fn chain_weight(expression: &Expression<'_>) -> usize {
    match unparenthesized(expression) {
        Expression::BinaryExpression(binary) => {
            chain_weight(&binary.left) + chain_weight(&binary.right)
        }
        _ => 1,
    }
}

/// Whether a direct `+` operand is a plain string literal; template
/// literals do not count (the pinned exceljs oracle stays silent for
/// template operands).
fn is_string_operand(expression: &Expression<'_>) -> bool {
    matches!(unparenthesized(expression), Expression::StringLiteral(_))
}

/// Whether a `+` chain weighs at least three atoms with at least one
/// string-literal operand and at least one non-literal operand. Chains
/// already containing a template literal stay silent.
fn is_template_candidate(left: &Expression<'_>, right: &Expression<'_>) -> bool {
    let operands = concat_operands(left, right);
    chain_weight(left) + chain_weight(right) >= 3
        && operands.iter().any(|operand| is_string_operand(operand))
        && operands.iter().any(|operand| !is_string_operand(operand))
        && operands
            .iter()
            .all(|operand| !matches!(unparenthesized(operand), Expression::TemplateLiteral(_)))
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s3512_flags_mixed_multi_operand_chains() {
        // Issue #387 pinned site: express examples/auth/index.js:36.
        let flagged = js_keys("res.send('<p class=\"msg error\">' + err + '</p>');\n");
        assert_eq!(count_key(&flagged, "javascript:S3512"), 1);

        let longer = js_keys(
            "req.session.success = 'Authenticated as ' + user.name\n  + ' click to logout. '\n  + ' You may now access it.';\n",
        );
        assert_eq!(count_key(&longer, "javascript:S3512"), 1);

        // Parenthesized arithmetic weighs into the chain: the pinned
        // express test/express.static.js:456 shape.
        let paren_arith =
            js_keys("res.set('cache-control', 'public, max-age=' + (60 * 60 * 24 * 30));\n");
        assert_eq!(count_key(&paren_arith, "javascript:S3512"), 1);

        let ts = ts_keys("const t = '<ul>' + items.join('') + '</ul>';\n");
        assert_eq!(count_key(&ts, "typescript:S3512"), 1);
    }

    #[test]
    fn s3512_keeps_two_operand_all_literal_and_template_chains_silent() {
        let source = "\
const a = '/' + name;
const b = str + '!';
const c = 'Viewing user ' + req.user.name;
const d = 'a' + 'b' + 'c';
const e = x + y;
const f = `<Relationship Id=\"${rId}\"` + tail + more;
";
        assert_eq!(count_key(&js_keys(source), "javascript:S3512"), 0);
    }

    #[test]
    fn s3512_reports_nested_chains_without_double_flagging() {
        // The chain inside the callback is its own root (its parent is the
        // return statement); the enclosing chain root is reported too, and
        // the mid-chain sub-binaries of either chain stay silent.
        let source = "\
res.send('<ul>' + users.map(function (user) {
  return '<li>' + user.name + '</li>';
}).join('') + '</ul>');
";
        assert_eq!(count_key(&js_keys(source), "javascript:S3512"), 2);

        // A parenthesized sub-chain reports on its own root only.
        let grouped = js_keys("const v = a + b + ('x' + c + 'y');\n");
        assert_eq!(count_key(&grouped, "javascript:S3512"), 1);
    }
}
