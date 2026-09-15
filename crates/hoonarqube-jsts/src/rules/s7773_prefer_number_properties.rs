// Rule module s7773_prefer_number_properties (generated).
//
// `javascript:S7773` + `typescript:S7773` — Number static methods and
// properties should be preferred over global equivalents. Reference
// semantics: eslint-plugin-unicorn `prefer-number-properties` at the
// version pinned by SonarJS 13.x (v65.0.1, wrapped by SonarJS S7773).
//
// Issue #222 originally narrowed the rule to explicit-radix `parseInt`
// calls. Issue #388 restores the documented global set: any plain call on
// the unshadowed global `parseInt`, `parseFloat`, `isNaN`, or `isFinite`
// maps to its `Number.*` static, and unshadowed `NaN` reads map to
// `Number.NaN`. `Infinity`/`-Infinity` reads stay unflagged: the pinned
// campaign oracles (express 12, exceljs 106 findings) count only the five
// mappings above. No auto-fix is offered.
//
// The regression tests below pin the extended mapping at the campaign
// base; they stay green once the detector covers the full global set.

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
        let Some(static_name) = number_static_equivalent(&identifier.name) else {
            continue;
        };
        if !semantic.is_reference_to_global_variable(identifier) {
            continue;
        }
        // Function globals must be called; `NaN` flags on every unshadowed
        // read.
        if static_name != "Number.NaN"
            && !is_plain_global_call(semantic, node.id(), identifier.span)
        {
            continue;
        }
        sink.emit_span(
            RuleScope::Both,
            "S7773",
            &format!("Prefer `{static_name}` over `{}`.", identifier.name),
            identifier.span,
        );
    }
    sink.issues
}

/// The `Number.*` static that replaces an unshadowed global number
/// function or `NaN` reference (`S7773`).
fn number_static_equivalent(name: &str) -> Option<&'static str> {
    match name {
        "parseInt" => Some("Number.parseInt"),
        "parseFloat" => Some("Number.parseFloat"),
        "isNaN" => Some("Number.isNaN"),
        "isFinite" => Some("Number.isFinite"),
        "NaN" => Some("Number.NaN"),
        _ => None,
    }
}

/// The reference must be the direct callee of a plain (non-optional)
/// call; argument shapes are unconstrained.
fn is_plain_global_call(
    semantic: &Semantic<'_>,
    identifier_node_id: NodeId,
    callee_span: Span,
) -> bool {
    let AstKind::CallExpression(call) = semantic.nodes().parent_node(identifier_node_id).kind()
    else {
        return false;
    };
    call.callee.span() == callee_span && !call.optional
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
    fn s7773_flags_full_documented_global_set() {
        // Issue #388: the mapping covers every documented global number
        // function plus `NaN`, regardless of the argument shapes.
        let source = "\
const radix = parseInt('42', 16);
const single = parseInt('42');
const decimal = parseFloat('2.5');
const bad = isNaN(0);
const finite = isFinite(0);
const zero = NaN;
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7773"), 6);
        for line in 1..=6 {
            assert!(keys.contains(&("javascript:S7773".to_string(), line)));
        }
    }

    #[test]
    fn s7773_rejects_infinity_shadowed_and_non_call_forms() {
        let source = "\
const inf = Infinity;
const neg = -Infinity;
const member = Number.parseInt('42', 16);
function shadowed() {
  const parseInt = (value, radix) => Number(value);
  return parseInt('42', 16);
}
parseInt = Number.parseInt;
const alias = parseInt;
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
