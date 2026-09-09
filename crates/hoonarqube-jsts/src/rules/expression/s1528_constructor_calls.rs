// Rule module s1528_constructor_calls (generated).
use crate::support::{IssueSink, RuleScope, constructor_name};
use oxc_ast::ast::{NewExpression, TSType, TSTypeName};
use oxc_span::GetSpan;

/// Constructor-call rules: `S1528`, `S1533`, `S2428`, and `S3834`.
pub(crate) fn check_constructor_calls(sink: &mut IssueSink, it: &NewExpression<'_>) {
    let Some(name) = constructor_name(it) else {
        return;
    };
    if name == "Array" {
        sink.emit_span(
            RuleScope::Both,
            "S1528",
            "Use either a literal or \"Array.from()\" instead of the \"Array\" constructor.",
            it.span(),
        );
    }
    if matches!(name, "Number" | "String" | "Boolean") {
        sink.emit_span(
            RuleScope::Both,
            "S1533",
            &format!("Remove this use of \"{name}\" constructor."),
            it.span(),
        );
    }
    if name == "Object" {
        sink.emit_span(
            RuleScope::JsOnly,
            "S2428",
            "Use an object literal instead of \"new Object()\".",
            it.callee.span(),
        );
    }
    if matches!(name, "Symbol" | "BigInt") {
        sink.emit_span(
            RuleScope::JsOnly,
            "S3834",
            "Remove this \"new\" operator.",
            oxc_span::Span::new(it.span.start, it.span.start + 3),
        );
    }
}

/// TypeScript counterpart of `S1533`: primitive wrapper references are not
/// useful as types and should be replaced by their primitive counterparts.
pub(crate) fn check_type_wrapper(sink: &mut IssueSink, it: &TSType<'_>) {
    let TSType::TSTypeReference(reference) = it else {
        return;
    };
    if reference.type_arguments.is_some() {
        return;
    }
    let TSTypeName::IdentifierReference(identifier) = &reference.type_name else {
        return;
    };
    let name = identifier.name.as_str();
    let primitive = match name {
        "Boolean" => "boolean",
        "Number" => "number",
        "String" => "string",
        _ => return,
    };
    sink.emit_span(
        RuleScope::TsOnly,
        "S1533",
        &format!("Replace this \"{name}\" wrapper object with primitive type \"{primitive}\"."),
        reference.span,
    );
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s1528_flags_array_wrapper_object_and_primitive_constructors() {
        let findings =
            js_keys("new Array(1, 2);\nnew String(\"x\");\nnew Object();\nnew Symbol();\n");
        assert_eq!(count_key(&findings, "javascript:S1528"), 1);
        assert_eq!(count_key(&findings, "javascript:S1533"), 1);
        assert_eq!(count_key(&findings, "javascript:S2428"), 1);
        assert_eq!(count_key(&findings, "javascript:S3834"), 1);
    }

    #[test]
    fn s1528_flags_length_constructor_and_allows_user_classes() {
        let findings = js_keys("new Array(3);\nnew Foo();\n[];\n");
        assert_eq!(count_key(&findings, "javascript:S1528"), 1);
        assert_eq!(count_key(&findings, "javascript:S1533"), 0);
    }

    #[test]
    fn s1528_empty_array_and_bigint_constructor_still_flagged() {
        let findings = js_keys("new Array();\nnew BigInt(1);\n");
        assert_eq!(count_key(&findings, "javascript:S1528"), 1);
        assert_eq!(count_key(&findings, "javascript:S3834"), 1);
    }
}
