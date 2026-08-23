// Rule module s2376_class_getter_pairing (generated).
use crate::support::{IssueSink, RuleScope, property_key_name};
use oxc_ast::ast::{ClassElement, MethodDefinitionKind};
use oxc_span::{GetSpan, Span};

/// Whether any class element is a getter whose name has no matching setter;
/// flags each unmatched getter (`S2376`, `getWithoutSet=false` mode).
pub(crate) fn check_class_getter_pairing(sink: &mut IssueSink<'_>, elements: &[ClassElement<'_>]) {
    let getter_names: Vec<(Option<&str>, Span)> = elements
        .iter()
        .filter_map(|element| match element {
            ClassElement::MethodDefinition(method) if method.kind == MethodDefinitionKind::Get => {
                Some((property_key_name(&method.key), method.key.span()))
            }
            _ => None,
        })
        .collect();
    let setter_names: Vec<Option<&str>> = elements
        .iter()
        .filter_map(|element| match element {
            ClassElement::MethodDefinition(method) if method.kind == MethodDefinitionKind::Set => {
                Some(property_key_name(&method.key))
            }
            _ => None,
        })
        .collect();
    for (name, span) in getter_names {
        if !setter_names.contains(&name) {
            sink.emit_span(
                RuleScope::Both,
                "S2376",
                "Add a setter matching this getter.",
                span,
            );
        }
    }
}
