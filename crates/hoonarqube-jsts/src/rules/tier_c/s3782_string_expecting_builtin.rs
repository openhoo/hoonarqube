use super::walker::TierCLiteralCollector;
use crate::engine::scope_model::LiteralKind;
use crate::engine::scope_model::kind_is_numeric;
use crate::engine::scope_model::literal_kind;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::RuleScope;
use crate::support::callee_name;
use crate::support::expression_root_name;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl TierCLiteralCollector<'_> {
    /// `S3782`: literal arguments contradicting the built-ins' documented
    /// types: parse functions over composite/`null`/`undefined` text, bad
    /// radixes, and non-numeric `String.fromCharCode` codes.
    pub(crate) fn check_builtin_signature(&mut self, call: &CallExpression<'_>) {
        if let Expression::StaticMemberExpression(member) = &call.callee
            && member.property.name == "fromCharCode"
            && expression_root_name(&member.object) == Some("String")
        {
            for argument in call.arguments.iter().filter_map(argument_expression) {
                if let Some(kind) = literal_kind(argument)
                    && !kind_is_numeric(kind)
                {
                    self.sink.emit_span(
                        RuleScope::JsOnly,
                        "S3782",
                        "String.fromCharCode expects numeric character codes.",
                        argument.span(),
                    );
                }
            }
            return;
        }
        let Some(name) = callee_name(call) else {
            return;
        };
        if matches!(name, "parseInt" | "parseFloat")
            && let Some(radix_kind) = call
                .arguments
                .get(1)
                .and_then(argument_expression)
                .and_then(literal_kind)
            && !kind_is_numeric(radix_kind)
        {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3782",
                "This parse function expects a numeric radix.",
                call.span(),
            );
        }
        if matches!(
            name,
            "parseInt"
                | "parseFloat"
                | "isNaN"
                | "isFinite"
                | "encodeURI"
                | "decodeURI"
                | "encodeURIComponent"
                | "decodeURIComponent"
        ) {
            self.check_string_expecting_builtin(call, name);
        }
    }

    /// Flags first arguments that cannot be stringified meaningfully.
    fn check_string_expecting_builtin(&mut self, call: &CallExpression<'_>, name: &str) {
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        if let Some(kind) = literal_kind(argument)
            && matches!(
                kind,
                LiteralKind::Object
                    | LiteralKind::Array
                    | LiteralKind::Function
                    | LiteralKind::RegExp
                    | LiteralKind::Null
                    | LiteralKind::Undefined
            )
        {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3782",
                &format!("'{name}' expects a string argument."),
                argument.span(),
            );
        }
    }
}
