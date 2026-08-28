use super::collectors::DuplicationCollector;
use crate::support::RuleScope;
use crate::support::binding_identifier_name;
use oxc_ast::ast::FormalParameters;

// Generated per-rule checks (moved out of traversal overrides).
impl DuplicationCollector<'_> {
    /// `S1536` logic extracted from `visit_formal_parameters`.
    pub(crate) fn check_s1536_formal_parameters(
        &mut self,
        it: &FormalParameters<'_>,
        function_span: oxc_span::Span,
    ) {
        // `S1536`: duplicate parameter names (JavaScript-only).
        let mut seen: Vec<&str> = Vec::new();

        for item in &it.items {
            let Some(name) = binding_identifier_name(&item.pattern) else {
                continue;
            };
            if seen.contains(&name) {
                self.sink.emit_span(
                    RuleScope::JsOnly,
                    "S1536",
                    &format!("Duplicate param '{name}'."),
                    function_span,
                );
            } else {
                seen.push(name);
            }
        }
    }
}
