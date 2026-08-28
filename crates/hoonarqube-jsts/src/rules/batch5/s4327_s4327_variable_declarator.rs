use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::Expression;
use oxc_ast::ast::VariableDeclarator;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S4327` logic extracted from `visit_variable_declarator`.
    pub(crate) fn check_s4327_variable_declarator(&mut self, it: &VariableDeclarator<'_>) {
        if let Some(init) = &it.init
            && matches!(unparenthesized(init), Expression::ThisExpression(_))
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4327",
                "Unexpected aliasing of 'this' to local variable.",
                it.id.span(),
            );
        }
    }
}
