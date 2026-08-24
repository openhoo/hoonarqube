// Rule module s1442_plain_calls (generated).
use super::walker::call_property;
use crate::support::{IssueSink, RuleScope, callee_name, member_rooted_at};
use oxc_ast::ast::{CallExpression, Expression};
use oxc_span::GetSpan;

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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s1442_flags_alert_and_radixless_parseint() {
        let findings = js_keys("alert(\"hi\");\nparseInt(s);\n");
        assert_eq!(count_key(&findings, "javascript:S1442"), 1);
        assert_eq!(count_key(&findings, "javascript:S2427"), 1);
    }

    #[test]
    fn s1442_allows_radix_parseint_and_flags_member_style_alert() {
        let radix = js_keys("parseInt(s, 10);\nconsole.log(1);\n");
        assert_eq!(count_key(&radix, "javascript:S1442"), 0);
        assert_eq!(count_key(&radix, "javascript:S2427"), 0);

        let member = js_keys("window.alert(\"hi\");\n");
        assert_eq!(count_key(&member, "javascript:S1442"), 1);
    }

    #[test]
    fn s1442_family_ts_suppresses_js_only_calls_but_keeps_s6958() {
        let ts_findings = ts_keys("alert(\"hi\");\nrequire(\"fs\");\n");
        assert_eq!(count_key(&ts_findings, "typescript:S1442"), 0);
        assert_eq!(count_key(&ts_findings, "typescript:S3533"), 0);

        let literal_call = js_keys("\"foo\"();\n");
        assert_eq!(count_key(&literal_call, "javascript:S6958"), 1);
    }
}
