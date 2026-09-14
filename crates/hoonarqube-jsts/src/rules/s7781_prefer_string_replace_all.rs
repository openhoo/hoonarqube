// Rule module s7781_prefer_string_replace_all (generated).
//
// `javascript:S7781` + `typescript:S7781` — Strings should use
// `replaceAll()` instead of `replace()` with a global regex. Reference
// semantics: eslint-plugin-unicorn `prefer-string-replace-all` at the
// version pinned by SonarJS 13.x (v65.0.1, wrapped by SonarJS S7781).
//
// A non-optional `.replace(...)`/`.replaceAll(...)` member call with
// exactly two arguments whose pattern is a global-flagged regular
// expression (a `/.../g` literal, or `new RegExp(pattern, flags)` whose
// literal flags contain `g`) is reported on the `replace` property with
// the reference message "Prefer `String#replaceAll()` over
// `String#replace()`." Optional calls, computed access, non-global or
// stateful patterns, and wrong arities stay rejected, and the receiver,
// pattern, and replacement evaluation are untouched. The unicorn
// "pattern can be replaced with a string literal" and
// `split()/join()` directions use different reference messages without
// capture evidence, so they stay out of scope. No auto-fix is offered.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{CallExpression, Expression, RegExpFlags};
use oxc_span::{GetSpan, Span};

/// Entry point: `javascript:S7781` + `typescript:S7781`
/// prefer-string-replace-all check over the parsed program.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    if let Some(semantic) = ctx.semantic {
        for node in semantic.nodes().iter() {
            if let AstKind::CallExpression(call) = node.kind() {
                check_call(&mut sink, call);
            }
        }
    }
    sink.issues
}

/// The reference `create`: a `.replace(pattern, replacement)` call whose
/// pattern is a global-flagged regular expression is reported on the
/// `replace` property.
fn check_call(sink: &mut IssueSink<'_>, call: &CallExpression<'_>) {
    let Some(property_span) = global_regex_replace_property(call) else {
        return;
    };
    sink.emit_span(
        RuleScope::Both,
        "S7781",
        "Prefer `String#replaceAll()` over `String#replace()`.",
        property_span,
    );
}

/// The `replace` property span when the call is a non-optional
/// two-argument member call named `replace` (the reference
/// `isMethodCall`), or `None` otherwise.
fn global_regex_replace_property(call: &CallExpression<'_>) -> Option<Span> {
    if call.optional || call.arguments.len() != 2 {
        return None;
    }
    let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
        return None;
    };
    if member.optional || member.property.name != "replace" {
        // `replaceAll` keeps its regex pattern: the unicorn
        // "pattern can be replaced with a string literal" suggestion is a
        // different reference message without capture evidence.
        return None;
    }
    if !has_global_regex_pattern(&call.arguments) {
        return None;
    }
    Some(member.property.span())
}

/// Whether the pattern argument is a global-flagged regular expression:
/// a `/.../g...` literal or `new RegExp(pattern, "flags")` whose literal
/// flags contain `g` (the reference `isRegExpWithGlobalFlag` minus its
/// opaque static-value branch).
fn has_global_regex_pattern(arguments: &[oxc_ast::ast::Argument<'_>]) -> bool {
    let Some(pattern) = arguments
        .first()
        .and_then(|argument| argument.as_expression())
    else {
        return false;
    };
    match unparenthesized(pattern) {
        Expression::RegExpLiteral(literal) => literal.regex.flags.contains(RegExpFlags::G),
        Expression::NewExpression(new_expression) => {
            let Expression::Identifier(callee) = unparenthesized(&new_expression.callee) else {
                return false;
            };
            callee.name == "RegExp"
                && new_expression
                    .arguments
                    .first()
                    .is_some_and(|argument| argument.as_expression().is_some())
                && matches!(
                    new_expression.arguments.get(1).and_then(|argument| argument.as_expression()),
                    Some(Expression::StringLiteral(flags)) if flags.value.contains('g'),
                )
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7781_flags_pinned_markdown_it_replacements_anchor() {
        // Pinned anchor: markdown-it/markdown-it@3c51991
        // src/rules_core/replacements.ts:65 — `.replace(/\+-/g, '±')`.
        let source = "\
export function replace(content: string) {
  return content
    .replace(/\\+-/g, '±')
    .replace(/\\.{2,}/g, '…').replace(/([?!])…/g, '$1..')
    .replace(/([?!]){4,}/g, '$1$1$1').replace(/,{2,}/g, ',');
}
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7781"), 5);
        let first = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7781" && issue.range.start.line == 3)
            .expect("pinned replacements chain must be reported");
        assert_eq!(
            first.message,
            "Prefer `String#replaceAll()` over `String#replace()`."
        );
        assert_eq!(
            first.range.start.column,
            u32::try_from("    .".len()).unwrap()
        );
        assert_eq!(
            first.range.end.column,
            u32::try_from("    .".len()).unwrap() + u32::try_from("replace".len()).unwrap()
        );
    }

    #[test]
    fn s7781_flags_global_regex_patterns_only() {
        let source = "\
const a = 'x'.replace(/x/g, 'y');
const b = 'x'.replace(new RegExp('x', 'g'), 'y');
const c = 'x'.replace(/x/gu, 'y');
const d = 'x'.replace(/x/i, 'y');
const e = 'x'.replace(/x/, 'y');
const f = 'x'.replace('str', 'y');
const g = 'x'.replace(new RegExp('x'), 'y');
const h = 'x'.replaceAll(/x/g, 'y');
const i = 'x'?.replace(/x/g, 'y');
const j = 'x'['replace'](/x/g, 'y');
const k = 'x'.replace(/x/g);
";
        let keys = js_keys(source);
        let flagged: Vec<u32> = keys
            .iter()
            .filter(|(key, _)| key == "javascript:S7781")
            .map(|(_, line)| *line)
            .collect();
        assert_eq!(flagged, vec![1, 2, 3]);
    }

    #[test]
    fn s7781_reports_in_both_languages() {
        let js_source = "const a = value.replace(/x/g, 'y');\n";
        let ts_source = "const a = value.replace(/x/g, 'y');\n";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7781"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7781"), 1);
    }
}
