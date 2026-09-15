// Rule module s7758_prefer_code_point (generated).
//
// `javascript:S7758` + `typescript:S7758` — Unicode-aware string methods
// should be used for proper character handling. Reference semantics:
// eslint-plugin-unicorn `prefer-code-point` at the version pinned by
// SonarJS 13.x (v65.0.1, wrapped by SonarJS S7758): a non-optional method
// call `x.charCodeAt(...)` is reported on the `charCodeAt` property with
// "Prefer `String#codePointAt()` over `String#charCodeAt()`." and a
// non-computed, non-optional member `String.fromCharCode` is reported on
// the `fromCharCode` property with "Prefer `String.fromCodePoint()` over
// `String.fromCharCode()`." — the member itself is flagged even without a
// call, matching the reference's MemberExpression visitor. Optional-call
// `?.()` forms stay silent; the reference offers suggestions only, so no
// auto-fix is offered here either.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

/// Entry point: `javascript:S7758` + `typescript:S7758` prefer-code-point
/// check over the parsed program.
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
            AstKind::CallExpression(call) => {
                if call.optional {
                    continue;
                }
                let Some(member) = method_member(call) else {
                    continue;
                };
                if member.property.name == "charCodeAt" {
                    sink.emit_span(
                        RuleScope::Both,
                        "S7758",
                        "Prefer `String#codePointAt()` over `String#charCodeAt()`.",
                        member.property.span(),
                    );
                }
            }
            AstKind::StaticMemberExpression(member) => {
                if member.optional || member.property.name != "fromCharCode" {
                    continue;
                }
                if matches!(unparenthesized(&member.object), Expression::Identifier(object) if object.name == "String")
                {
                    sink.emit_span(
                        RuleScope::Both,
                        "S7758",
                        "Prefer `String.fromCodePoint()` over `String.fromCharCode()`.",
                        member.property.span(),
                    );
                }
            }
            _ => {}
        }
    }
    sink.issues
}

/// The callee's non-optional static member (`obj.method(...)`).
fn method_member<'a, 'b>(
    call: &'b oxc_ast::ast::CallExpression<'a>,
) -> Option<&'b oxc_ast::ast::StaticMemberExpression<'a>> {
    match unparenthesized(&call.callee) {
        Expression::StaticMemberExpression(member) if !member.optional => Some(member),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7758_flags_char_code_at_and_from_char_code() {
        let source = "\
const code = '🦄'.charCodeAt(0);
const other = text.charCodeAt(index);
const made = String.fromCharCode(72, 105);
const held = String.fromCharCode;
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7758"), 4);
    }

    #[test]
    fn s7758_flags_typescript_too() {
        let source = "const code: number = value.charCodeAt(0);\n";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7758"), 1);
    }

    #[test]
    fn s7758_ignores_code_point_and_optional_forms() {
        let source = "\
const code = '🦄'.codePointAt(0);
const made = String.fromCodePoint(0x1F984);
const maybe = text?.charCodeAt(0);
const optCall = text.charCodeAt?.(0);
const computed = String['fromCharCode'](65);
const other = text.charCodeAt;
";
        let keys = js_keys(source);
        // `text.charCodeAt` without a call stays silent (call-only rule);
        // `String['fromCharCode']` is computed and stays silent.
        assert_eq!(count_key(&keys, "javascript:S7758"), 0);
    }
}
