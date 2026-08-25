use crate::rules::batch5::collectors::RAW_SOCKET_MODULES;
use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::first_string_argument;
use crate::rules::shared::sink_callee_name;
use crate::support::RuleScope;
use crate::support::expression_root_name;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_ast::ast::ImportDeclaration;
use oxc_ast::ast::NewExpression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S4818`: raw-socket module requires.
    pub(crate) fn check_socket_require(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) == Some("require")
            && first_string_argument(call)
                .is_some_and(|module| RAW_SOCKET_MODULES.contains(&module))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4818",
                "Make sure using this raw socket is safe here.",
                call.span(),
            );
        }
    }

    /// `S4818`: raw-socket module imports.
    pub(crate) fn check_socket_module_import(&mut self, declaration: &ImportDeclaration<'_>) {
        if RAW_SOCKET_MODULES.contains(&declaration.source.value.as_str()) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4818",
                "Make sure using these raw sockets is safe here.",
                declaration.span(),
            );
        }
    }

    /// `S4818`: direct socket constructions over `net`/`dgram`.
    pub(crate) fn check_new_raw_socket(&mut self, constructor: &NewExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &constructor.callee else {
            return;
        };
        if matches!(expression_root_name(&member.object), Some("net" | "dgram"))
            && matches!(member.property.name.as_str(), "Socket" | "Server")
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4818",
                "Make sure opening this raw socket is safe here.",
                constructor.span(),
            );
        }
    }
}
