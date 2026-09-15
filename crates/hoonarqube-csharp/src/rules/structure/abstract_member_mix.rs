use super::support::{accessors_of, body_of, name_anchor};
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, range_of,
};
use crate::project_index::ProjectTypeIndex;
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::support::type_members;
use crate::rules::tier_c::support::local_type_table;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use std::collections::HashMap;
use tree_sitter::Node;

/// csharpsquid:S1694 — an abstract class or non-positional record whose
/// declared shape already is an interface: no base class, no fields, and
/// every declared method abstract (at least one). Constructors, destructors,
/// operators, and conversions are methods in the reference symbol model and
/// can never be abstract, so any of them keeps the rule silent; properties
/// and custom-accessor events do not, though an auto-property's implicit
/// backing field is state. Only a resolvable class base moves the reference
/// rule's `BaseType` off `System.Object`; an unresolvable base binds to an
/// error type there, which is never `System.Object`, so it stays silent too.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let project = options.project_type_index.as_deref();
    let types = local_type_table(root, source);
    let mut issues = Vec::new();
    for declaration in collect_kinds(root, &["class_declaration", "record_declaration"]) {
        if is_error_tainted(declaration)
            || !has_modifier(&modifiers_of(declaration, source), "abstract")
            || is_positional_record(declaration)
            || declares_state(declaration, source)
            || declares_non_method_callable(declaration)
        {
            continue;
        }
        let methods: Vec<Node<'_>> = type_members(declaration)
            .into_iter()
            .filter(|member| member.kind() == "method_declaration")
            .collect();
        if methods.is_empty()
            || !methods
                .iter()
                .all(|method| has_modifier(&modifiers_of(*method, source), "abstract"))
            || declares_base_class(declaration, source, project, &types)
        {
            continue;
        }
        let kind_word = if declaration.kind() == "record_declaration" {
            "record"
        } else {
            "class"
        };
        issues.push(issue(
            language,
            "S1694",
            format!("Convert this 'abstract' {kind_word} to an interface."),
            range_of(name_anchor(declaration), source),
        ));
    }
    issues
}

/// Whether a record declares positional parameters. The reference rule
/// exempts only records whose parameter list is non-empty; a class's own
/// primary constructor does not exempt it because the implicit constructor
/// is excluded from the all-methods-abstract check.
fn is_positional_record(declaration: Node<'_>) -> bool {
    if declaration.kind() != "record_declaration" {
        return false;
    }
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .filter(|child| child.kind() == "parameter_list")
        .any(|list| !collect_kinds(list, &["parameter"]).is_empty())
}

/// Fields of any kind are state the interface shape cannot carry: instance
/// and static fields, constants, field-like event backing fields, and the
/// implicit backing fields of auto-properties.
fn declares_state(declaration: Node<'_>, source: &str) -> bool {
    type_members(declaration).into_iter().any(|member| {
        matches!(
            member.kind(),
            "field_declaration" | "event_field_declaration"
        ) || declares_backing_field(member, source)
    })
}

/// Whether a property is an auto-property: a bodiless accessor (`{ get; }`)
/// synthesizes an implicit backing field, which is an `IFieldSymbol` in the
/// reference symbol model. Abstract and extern properties have no
/// implementation and no backing field.
fn declares_backing_field(member: Node<'_>, source: &str) -> bool {
    if member.kind() != "property_declaration" {
        return false;
    }
    let modifiers = modifiers_of(member, source);
    if has_modifier(&modifiers, "abstract") || has_modifier(&modifiers, "extern") {
        return false;
    }
    accessors_of(member)
        .into_iter()
        .any(|accessor| body_of(accessor).is_none())
}

/// Whether the type declares a constructor, destructor, or operator: these
/// are `IMethodSymbol` members in the reference symbol model that can never
/// carry the `abstract` modifier.
fn declares_non_method_callable(declaration: Node<'_>) -> bool {
    type_members(declaration).into_iter().any(|member| {
        matches!(
            member.kind(),
            "constructor_declaration"
                | "destructor_declaration"
                | "operator_declaration"
                | "conversion_operator_declaration"
        )
    })
}

/// Whether the first base resolves to a class declaration. C# requires the
/// base class to lead the base list, so the first entry decides. Interface
/// bases keep the `System.Object` base the reference rule requires; an
/// unresolvable base binds to an error type there, which is never
/// `System.Object`, so it is treated as a class base and stays silent.
fn declares_base_class<'a>(
    declaration: Node<'_>,
    source: &'a str,
    project: Option<&ProjectTypeIndex>,
    types: &HashMap<&'a str, Node<'a>>,
) -> bool {
    let Some(first_base) = base_simple_names(declaration, source).first().copied() else {
        return false;
    };
    if let Some(base) = types.get(first_base) {
        return base.kind() != "interface_declaration";
    }
    if let Some(project) = project {
        let resolutions: Vec<_> = project.type_declarations(first_base).collect();
        if !resolutions.is_empty() {
            return resolutions.iter().any(|indexed| !indexed.is_interface);
        }
    }
    !matches!(first_base, "object" | "Object")
}
