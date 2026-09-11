// Rule module s1442_plain_calls (generated).
use crate::rules::shared::call_property;
use crate::support::{IssueSink, RuleScope, callee_name, member_object, member_rooted_at};
use oxc_ast::ast::{CallExpression, Expression};
use oxc_semantic::Semantic;
use oxc_span::GetSpan;

/// Plain-callee rules: `S1442`, `S2427`, `S3533`, `S2817`, `S6958`, and the
/// prototype-mutation calls of `S6643`.
pub(crate) fn check_plain_calls(
    sink: &mut IssueSink,
    it: &CallExpression<'_>,
    semantic: Option<&Semantic<'_>>,
) {
    let plain_name = callee_name(it);
    if let Some(name) = plain_name {
        if name == "alert" {
            sink.emit_span(RuleScope::JsOnly, "S1442", "Unexpected alert.", it.span());
        }
        if name == "parseInt" && it.arguments.len() < 2 {
            sink.emit_span(
                RuleScope::Both,
                "S2427",
                "Missing radix parameter.",
                it.span(),
            );
        }
        if name == "require" {
            sink.emit_span(
                RuleScope::Both,
                "S3533",
                "Use a standard \"import\" statement instead of \"require\".",
                it.callee.span(),
            );
        }
    }
    if is_global_open_database(it, semantic) {
        sink.emit_span(
            RuleScope::Both,
            "S2817",
            "Convert this use of a Web SQL database to another technology.",
            it.callee.span(),
        );
    }
    if plain_name.is_none()
        && let Some((property, member)) = call_property(it)
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
fn is_global_open_database(call: &CallExpression<'_>, semantic: Option<&Semantic<'_>>) -> bool {
    if let Expression::Identifier(identifier) = &call.callee {
        return identifier.name == "openDatabase" && is_global_identifier(identifier, semantic);
    }
    let Some((property, member)) = call_property(call) else {
        return false;
    };
    if property != "openDatabase" {
        return false;
    }
    let Expression::Identifier(root) = member_object(member) else {
        return false;
    };
    matches!(root.name.as_str(), "window" | "globalThis") && is_global_identifier(root, semantic)
}

fn is_global_identifier(
    identifier: &oxc_ast::ast::IdentifierReference<'_>,
    semantic: Option<&Semantic<'_>>,
) -> bool {
    semantic.is_some_and(|semantic| semantic.is_reference_to_global_variable(identifier))
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
    fn s1442_family_ts_suppresses_alert_but_flags_commonjs_require() {
        let ts_findings = ts_keys("alert(\"hi\");\nrequire(\"fs\");\n");
        assert_eq!(count_key(&ts_findings, "typescript:S1442"), 0);
        assert_eq!(count_key(&ts_findings, "typescript:S3533"), 1);

        let module_import = ts_keys("import fs from 'fs';\n");
        assert_eq!(count_key(&module_import, "typescript:S3533"), 0);

        let literal_call = js_keys("\"foo\"();\n");
        assert_eq!(count_key(&literal_call, "javascript:S6958"), 1);
    }
    #[test]
    fn s2817_matches_unbound_bare_and_global_browser_members_in_js_and_ts() {
        let javascript_attack = js_keys(
            "const db = window.openDatabase(\"myDb\", \"1.0\", \
             \"Personal secrets stored here\", 2*1024*1024);\n",
        );
        assert_eq!(count_key(&javascript_attack, "javascript:S2817"), 1);

        let typescript_attack = ts_keys(
            "const db = window.openDatabase(\"myDb\", \"1.0\", \
             \"Personal secrets stored here\", 2*1024*1024);\n",
        );
        assert_eq!(count_key(&typescript_attack, "typescript:S2817"), 1);

        let javascript_bare = js_keys("const db = openDatabase(name);\n");
        assert_eq!(count_key(&javascript_bare, "javascript:S2817"), 1);

        let typescript_bare = ts_keys("const db = openDatabase(name);\n");
        assert_eq!(count_key(&typescript_bare, "typescript:S2817"), 1);

        let javascript_global_this = js_keys("globalThis.openDatabase(name);\n");
        assert_eq!(count_key(&javascript_global_this, "javascript:S2817"), 1);

        let typescript_global_this = ts_keys("globalThis.openDatabase(name);\n");
        assert_eq!(count_key(&typescript_global_this, "typescript:S2817"), 1);

        for findings in [
            js_keys(
                "const db = window.indexedDB.open('myDb');\n\
                 const open = window.indexedDB.open;\n\
                 const same = open('myDb');\n",
            ),
            ts_keys(
                "const db = window.indexedDB.open('myDb');\n\
                 const open = window.indexedDB.open;\n\
                 const same = open('myDb');\n",
            ),
        ] {
            assert!(findings.iter().all(|(key, _)| !key.ends_with(":S2817")));
        }

        let javascript_shadowed = js_keys(
            "function use(window, openDatabase) {\n\
             window.openDatabase(name);\n\
             openDatabase(name);\n\
             }\n",
        );
        assert_eq!(count_key(&javascript_shadowed, "javascript:S2817"), 0);

        let typescript_shadowed = ts_keys(
            "function use(window: unknown, openDatabase: () => unknown) {\n\
             window.openDatabase(name);\n\
             openDatabase(name);\n\
             }\n",
        );
        assert_eq!(count_key(&typescript_shadowed, "typescript:S2817"), 0);
    }
}
