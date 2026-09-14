// Rule module s7773_prefer_number_properties (generated).
//
// `javascript:S7773` + `typescript:S7773` — Number static methods and
// properties should be preferred over global equivalents. Reference
// semantics: eslint-plugin-unicorn `prefer-number-properties` at the
// version pinned by SonarJS 13.x (v65.0.1, wrapped by SonarJS S7773).
//
// Issue #222 narrows the request to explicit-radix `parseInt` calls where
// `Number.parseInt` is provably equivalent: the callee must resolve to the
// unshadowed global `parseInt`, and the call must pass exactly two plain
// arguments so the radix is preserved verbatim (lexical lookup, coercion,
// and call evaluation are untouched). The blocked `isNaN`/`parseFloat`
// observations stay rejected: `Number.isNaN`/`Number.isFinite` differ in
// coercion semantics, so those occurrences are not proven. No auto-fix is
// offered.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_semantic::Semantic;
use oxc_span::{GetSpan, Span};
use oxc_syntax::node::NodeId;

/// Entry point: `javascript:S7773` + `typescript:S7773`
/// prefer-number-properties check over the parsed program.
/// Requires the semantic model for the global-binding guard, so
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
        let AstKind::IdentifierReference(identifier) = node.kind() else {
            continue;
        };
        if identifier.name != "parseInt"
            || !semantic.is_reference_to_global_variable(identifier)
            || !is_explicit_radix_call(semantic, node.id(), identifier.span)
        {
            continue;
        }
        sink.emit_span(
            RuleScope::Both,
            "S7773",
            "Prefer `Number.parseInt` over `parseInt`.",
            identifier.span,
        );
    }
    sink.issues
}

/// The issue limit: only a plain, non-optional call on the unshadowed
/// global `parseInt` with exactly two plain arguments (the radix preserved
/// verbatim) is a proven `Number.parseInt` equivalent.
fn is_explicit_radix_call(
    semantic: &Semantic<'_>,
    identifier_node_id: NodeId,
    callee_span: Span,
) -> bool {
    let AstKind::CallExpression(call) = semantic.nodes().parent_node(identifier_node_id).kind()
    else {
        return false;
    };
    call.callee.span() == callee_span
        && !call.optional
        && call.arguments.len() == 2
        && call
            .arguments
            .iter()
            .all(|argument| argument.as_expression().is_some())
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7773_flags_pinned_markdown_it_entity_anchor() {
        // Pinned anchor: markdown-it/markdown-it@3c51991
        // src/rules_inline/entity.ts:24 — Sonar emits two findings, one for
        // each explicit-radix call.
        let source = "\
function scan(state: any, silent: boolean) {
  const match = state.src.slice(pos).match(DIGITAL_RE);
  if (match) {
    if (!silent) {
      const code = match[1][0].toLowerCase() === 'x' ? parseInt(match[1].slice(1), 16) : parseInt(match[1], 10);

      const token = state.push('text_special', '', 0);
      return code;
    }
  }
  return false;
}
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7773"), 2);
        let mut anchors: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "typescript:S7773")
            .map(|issue| (issue.range.start.column, issue.range.end.column))
            .collect();
        anchors.sort_unstable();
        let first_prefix = "      const code = match[1][0].toLowerCase() === 'x' ? ";
        let second_prefix = concat!(
            "      const code = match[1][0].toLowerCase() === 'x' ? ",
            "parseInt(match[1].slice(1), 16) : ",
        );
        let expected: Vec<(u32, u32)> = [first_prefix, second_prefix]
            .iter()
            .map(|prefix| {
                let start = u32::try_from(prefix.len()).unwrap();
                (start, start + u32::try_from("parseInt".len()).unwrap())
            })
            .collect();
        assert_eq!(anchors, expected);
        for issue in report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "typescript:S7773")
        {
            assert_eq!(issue.range.start.line, 5);
            assert_eq!(issue.message, "Prefer `Number.parseInt` over `parseInt`.");
        }
    }

    #[test]
    fn s7773_flags_explicit_radix_calls() {
        let source = "\
const hex = parseInt('7f', 16);
const dec = parseInt('42', 10);
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7773"), 2);
        assert!(keys.contains(&("javascript:S7773".to_string(), 1)));
        assert!(keys.contains(&("javascript:S7773".to_string(), 2)));
    }

    #[test]
    fn s7773_rejects_unproven_and_shadowed_forms() {
        let source = "\
const single = parseInt('42');
const member = Number.parseInt('42', 16);
const spread = parseInt(...parts, 10);
function shadowed() {
  const parseInt = (value, radix) => Number(value);
  return parseInt('42', 16);
}
parseInt = Number.parseInt;
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7773"), 0);
    }

    #[test]
    fn s7773_rejects_global_forms_without_proven_equivalence() {
        // Issue guard: the blocked isNaN/parseFloat observations stay
        // rejected; NaN/Infinity reads are outside the documented limit.
        let source = "\
const n = parseFloat('2.5');
const bad = isNaN(n);
const finite = isFinite(n);
const zero = NaN;
const inf = Infinity;
const neg = -Infinity;
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7773"), 0);
    }

    #[test]
    fn s7773_reports_in_both_languages() {
        let js_source = "const a = parseInt('7', 8);\n";
        let ts_source = "const a = parseInt('7', 8);\n";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7773"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7773"), 1);
    }
}
