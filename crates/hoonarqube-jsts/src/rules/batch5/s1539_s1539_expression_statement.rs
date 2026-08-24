use super::collectors_hotspots::MiscCollector;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::Expression;
use oxc_ast::ast::ExpressionStatement;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl MiscCollector<'_> {
    /// `S1539` logic extracted from `visit_expression_statement`.
    pub(crate) fn check_s1539_expression_statement(&mut self, it: &ExpressionStatement<'_>) {
        // `S1539`: a surviving string-literal `"use strict"` statement is by
        // definition outside a directive prologue (valid ones become
        // directive nodes during parsing).
        if let Expression::StringLiteral(literal) = unparenthesized(&it.expression)
            && literal.value == "use strict"
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S1539",
                "Move this 'use strict' directive to the top of its enclosing scope.",
                it.span(),
            );
        }
    }
}
