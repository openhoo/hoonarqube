use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::TSUnionType;
use oxc_span::GetSpan;

/// `S4622` catalog parameter `threshold` default: maximum union members.
pub(crate) const MAX_UNION_TYPE_MEMBERS: usize = 3;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S4622` logic extracted from `visit_ts_union_type`.
    pub(crate) fn check_s4622_ts_union_type(&mut self, it: &TSUnionType<'_>) {
        self.check_constituent_redundancy(&it.types, "union");

        if it.types.len() > MAX_UNION_TYPE_MEMBERS {
            let message = format!(
                "Reduce this union type; it currently has {} members.",
                it.types.len()
            );
            self.sink
                .emit_span(RuleScope::TsOnly, "S4622", &message, it.span());
        }
    }
}
