use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::FormalParameters;
use oxc_ast::ast::TSType;
use oxc_ast::ast::TSTypeAnnotation;
use oxc_ast::ast::TSTypeName;
use oxc_span::GetSpan;

impl TsTypeCollector<'_, '_> {
    /// `S4322`, `S4324`, and `S6565` over one function return type.
    pub(crate) fn check_return_type_annotations(
        &mut self,
        params: &FormalParameters<'_>,
        return_type: Option<&TSTypeAnnotation<'_>>,
    ) {
        let Some(return_type) = return_type else {
            return;
        };
        if matches!(return_type.type_annotation, TSType::TSBooleanKeyword(_))
            && let Some(param_name) = single_reference_parameter(params)
        {
            let message = format!(
                "Use a type predicate ('{param_name} is T') instead of this boolean return type."
            );
            self.sink
                .emit_span(RuleScope::TsOnly, "S4322", &message, return_type.span());
        }
        if let TSType::TSTypeReference(reference) = &return_type.type_annotation {
            if let TSTypeName::IdentifierReference(identifier) = &reference.type_name
                && WRAPPER_TYPE_NAMES.contains(&identifier.name.as_str())
            {
                self.sink.emit_span(
                    RuleScope::TsOnly,
                    "S4324",
                    "Use the primitive type keyword instead of this wrapper object type.",
                    reference.span(),
                );
            }
            let enclosing_class = self.class_stack.last();
            if let (Some(class_name), TSTypeName::IdentifierReference(identifier)) =
                (enclosing_class, &reference.type_name)
                && class_name.as_str() == identifier.name.as_str()
            {
                self.sink.emit_span(
                    RuleScope::TsOnly,
                    "S6565",
                    "Return 'this' instead of the class name type.",
                    reference.span(),
                );
            }
        }
    }
}

/// `S4324`: wrapper object type names that must not appear in return types.
const WRAPPER_TYPE_NAMES: [&str; 5] = ["String", "Number", "Boolean", "Symbol", "BigInt"];

/// `S4322` helper: name of the single reference-typed parameter, if any.
fn single_reference_parameter<'a>(params: &FormalParameters<'a>) -> Option<&'a str> {
    if params.items.len() != 1 {
        return None;
    }
    let annotation = params.items[0].type_annotation.as_ref()?;
    match &annotation.type_annotation {
        TSType::TSTypeReference(reference) => match &reference.type_name {
            TSTypeName::IdentifierReference(identifier) => Some(identifier.name.as_str()),
            _ => None,
        },
        _ => None,
    }
}
