// Rule module s1442_plain_calls (generated).
use hoonarqube_ir::{Issue};
use oxc_ast::ast::{CallExpression, Expression, Function, StringLiteral, TemplateLiteral};
use oxc_span::{GetSpan};
use crate::context::{AnalysisContext};
use crate::support::{IssueSink, RuleScope, callee_name, member_rooted_at};
use super::walker::{call_property};


/// Plain-callee rules: `S1442`, `S2427`, `S3533`, `S2817`, `S6958`, and the
/// prototype-mutation calls of `S6643`.
pub(crate) fn check_plain_calls(sink: &mut IssueSink, it: &CallExpression<'_>) {
    if let Some(name) = callee_name(it) {
        if name == "alert" {
            sink.emit_span(
                RuleScope::JsOnly,
                "S1442",
                "Remove this use of \"alert\".",
                it.callee.span(),
            );
        }
        if name == "parseInt" && it.arguments.len() < 2 {
            sink.emit_span(
                RuleScope::Both,
                "S2427",
                "Add the radix parameter to this \"parseInt\".",
                it.callee.span(),
            );
        }
        if name == "require" {
            sink.emit_span(
                RuleScope::JsOnly,
                "S3533",
                "Use ECMAScript module imports instead of \"require\".",
                it.callee.span(),
            );
        }
        if matches!(name, "openDatabase" | "openDatabaseSync") {
            sink.emit_span(
                RuleScope::Both,
                "S2817",
                "Do not use the deprecated WebSQL database API.",
                it.callee.span(),
            );
        }
    } else if let Some((property, member)) = call_property(it)
        && matches!(property, "defineProperty" | "defineProperties")
        && BUILTIN_GLOBALS
            .iter()
            .any(|builtin| member_rooted_at(member, builtin))
    {
        sink.emit_span(
            RuleScope::Both,
            "S6643",
            "Do not extend built-in prototypes.",
            it.callee.span(),
        );
    }
    if matches!(
        &it.callee,
        Expression::StringLiteral(_) | Expression::TemplateLiteral(_)
    ) {
        sink.emit_span(
            RuleScope::Both,
            "S6958",
            "Do not invoke functions through literals.",
            it.callee.span(),
        );
    }
}


/// Built-in globals whose prototypes `S6643` protects and whose surfaces
/// `S2424` treats as read-only.
pub(crate) const BUILTIN_GLOBALS: [&str; 16] = [
    "Array", "Object", "Function", "String", "Number", "Boolean", "Symbol", "BigInt", "Map", "Set",
    "Promise", "Date", "RegExp", "Error", "Math", "JSON",
];

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    const KEYS: &[&str] = &["S1442"];
    let mut issues = super::walker::run(ctx);
    issues.retain(|i| {
        i.rule_key.rsplit(':').next().is_some_and(|k| KEYS.contains(&k))
    });
    issues
}
