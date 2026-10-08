use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::TSSignature;
use oxc_span::GetSpan;

impl TsTypeCollector<'_, '_> {
    /// `S6598`: an interface or object type holding exactly one call
    /// signature should be declared as a function type instead.
    pub(crate) fn check_single_call_signature(
        &mut self,
        members: &[TSSignature<'_>],
        interface: bool,
    ) {
        let [
            signature @ (TSSignature::TSCallSignatureDeclaration(_)
            | TSSignature::TSConstructSignatureDeclaration(_)),
        ] = members
        else {
            return;
        };
        self.sink.emit_span(
            RuleScope::TsOnly,
            "S6598",
            if interface {
                "Interface has only a call signature, you should use a function type instead."
            } else {
                "Type literal has only a call signature, you should use a function type instead."
            },
            signature.span(),
        );
    }
}
