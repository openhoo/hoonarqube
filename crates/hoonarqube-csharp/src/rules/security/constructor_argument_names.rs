use super::support::attributed_declaration;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, parameters_of, range_of};
use crate::rules::declaration_contracts::attribute_applications;
use crate::rules::expressions::enclosing_type;
use crate::rules::literals::literal_inner_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4260 — `[ConstructorArgument]` names must exist as parameters
/// of a constructor of the same class.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, args, attribute) in attribute_applications(root, source) {
        if !matches!(name, "ConstructorArgument" | "ConstructorArgumentAttribute") {
            continue;
        }
        let Some(args) = args else { continue };
        let literals = collect_kinds(args, &["string_literal"]);
        let Some(literal) = literals.first() else {
            continue;
        };
        let wanted = literal_inner_text(*literal, source);
        let Some(member) = attributed_declaration(attribute) else {
            continue;
        };
        if !matches!(member.kind(), "property_declaration" | "field_declaration") {
            continue;
        }
        let supplied = enclosing_type(member).is_some_and(|ty| {
            collect_kinds(ty, &["constructor_declaration"])
                .iter()
                .any(|ctor| {
                    parameters_of(*ctor).iter().any(|param| {
                        param
                            .child_by_field_name("name")
                            .is_some_and(|param_name| node_text(param_name, source) == wanted)
                    })
                })
        });
        if !supplied {
            issues.push(issue(
                language,
                "S4260",
                "Match this '[ConstructorArgument]' name with a declared constructor parameter.",
                range_of(attribute, source),
            ));
        }
    }
    issues
}
