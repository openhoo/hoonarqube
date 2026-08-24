use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::TSSignature;
use oxc_span::Span;

impl TsTypeCollector<'_, '_> {
    /// `S6598`: an interface or object type holding exactly one call
    /// signature should be declared as a function type instead.
    pub(crate) fn check_single_call_signature(&mut self, members: &[TSSignature<'_>], span: Span) {
        if let [TSSignature::TSCallSignatureDeclaration(_)] = members {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S6598",
                "Declare this type as a function type instead of wrapping a call signature.",
                span,
            );
        }
    }
}
