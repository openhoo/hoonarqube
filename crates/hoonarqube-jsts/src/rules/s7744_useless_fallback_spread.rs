// Rule module s7744_useless_fallback_spread (generated).
//
// `javascript:S7744` + `typescript:S7744` — Unnecessary fallback objects
// should not be used when spreading in object literals. Reference
// semantics: eslint-plugin-unicorn `no-useless-fallback-in-spread` at the
// version pinned by SonarJS 13.x (v65.0.1, wrapped by SonarJS S7744): an
// empty object literal `{}` used as the right-hand side of a `||`/`??`
// logical expression whose whole result is spread into an object literal
// (`{ ...(value ?? {}) }`) is reported on the empty object. Property-value
// fallbacks and array spreads keep their necessary fallbacks and stay
// silent. No auto-fix is offered (comments and parenthesization around the
// fallback make the reference fix unsafe).
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{LogicalOperator, ObjectExpression, ObjectPropertyKind};
use oxc_semantic::AstNodes;
use oxc_span::GetSpan;
use oxc_syntax::node::NodeId;

/// Entry point: `javascript:S7744` + `typescript:S7744` useless fallback
/// spread check over the parsed program.
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
        if let AstKind::ObjectExpression(object) = node.kind() {
            check_empty_object(&mut sink, semantic.nodes(), node.id(), object);
        }
    }
    sink.issues
}

/// The reference report: an empty object literal as the right side of a
/// `||`/`??` expression whose whole result is spread into an object
/// literal. The finding covers the empty object.
fn check_empty_object(
    sink: &mut IssueSink<'_>,
    nodes: &AstNodes<'_>,
    node_id: NodeId,
    object: &ObjectExpression<'_>,
) {
    if !object.properties.is_empty() {
        return;
    }
    let logical_node = nodes.parent_node(node_id);
    let AstKind::LogicalExpression(logical) = logical_node.kind() else {
        return;
    };
    if !matches!(
        logical.operator,
        LogicalOperator::Or | LogicalOperator::Coalesce
    ) {
        return;
    }
    if logical.right.span() != object.span() {
        return;
    }
    // This parser preserves parentheses, so skip the wrappers the
    // reference parser does not materialize.
    let spread_id = skip_parenthesized(nodes, logical_node.id());
    let AstKind::SpreadElement(spread) = nodes.get_node(spread_id).kind() else {
        return;
    };
    if unparenthesized(&spread.argument).span() != logical.span() {
        return;
    }
    let container_id = skip_parenthesized(nodes, spread_id);
    let AstKind::ObjectExpression(container) = nodes.get_node(container_id).kind() else {
        return;
    };
    if !container
        .properties
        .iter()
        .any(|property| matches!(property, ObjectPropertyKind::SpreadProperty(s) if s.span == spread.span))
    {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S7744",
        "The empty object is useless.",
        object.span(),
    );
}

/// Nearest ancestor of `node_id` that is not a parenthesized expression
/// wrapper.
fn skip_parenthesized(nodes: &AstNodes<'_>, node_id: NodeId) -> NodeId {
    let mut parent = nodes.parent_id(node_id);
    while let AstKind::ParenthesizedExpression(_) = nodes.get_node(parent).kind() {
        parent = nodes.parent_id(parent);
    }
    parent
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7744_flags_pinned_zod_registries_anchor() {
        // Pinned anchor: colinhacks/zod@46da957
        // packages/zod/src/v4/core/registries.ts:66
        // `const pm: any = { ...(this.get(p) ?? {}) };`
        let source = "\
declare const registry: { get(p: string): Record<string, unknown> | undefined };
declare const p: string;
if (p) {
  const pm = { ...(registry.get(p) ?? {}) };
  delete pm.id;
}
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7744"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7744")
            .expect("pinned registries spread fallback must be reported");
        assert_eq!(issue.message, "The empty object is useless.");
        assert_eq!(issue.range.start.line, 4);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("  const pm = { ...(registry.get(p) ?? ".len()).unwrap()
        );
        assert_eq!(issue.range.end.line, 4);
        assert_eq!(
            issue.range.end.column,
            u32::try_from("  const pm = { ...(registry.get(p) ?? {}".len()).unwrap()
        );
    }

    #[test]
    fn s7744_flags_pinned_zod_to_json_schema_anchor() {
        // Pinned anchor: colinhacks/zod@46da957
        // packages/zod/src/v4/core/to-json-schema.ts:853
        // `initializeContext({ ...(libraryOptions ?? {}), target, io, processors })`
        let source = "\
declare const libraryOptions: Record<string, unknown> | undefined;
declare const target: string;
declare const io: string;
declare const processors: Record<string, unknown>;
declare function initializeContext(options: Record<string, unknown>): unknown;
const context = initializeContext({ ...(libraryOptions ?? {}), target, io, processors });
";
        let report = ts(source);
        assert_eq!(count_key(&report_keys(&report), "typescript:S7744"), 1);
    }

    #[test]
    fn s7744_property_fallbacks_and_array_spreads_stay_silent() {
        let silent = "\
declare const params: { processors?: Record<string, unknown> };
declare const external: { defs?: Record<string, unknown> } | undefined;
declare const arr: string[] | undefined;
const config = { processors: params.processors ?? {} };
const defs = external?.defs ?? {};
const spread = [...(arr ?? [])];
const logical = params.processors || {};
function direct(arg = {}) {
  return arg;
}
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7744"), 0);
    }

    #[test]
    fn s7744_reports_in_both_languages() {
        let ts_source = "\
declare const source: Record<string, unknown> | undefined;
const merged = { ...(source ?? {}) };
";
        let js_source = "\
const source = read();
const merged = { ...(source ?? {}) };
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7744"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7744"), 1);
    }
}
