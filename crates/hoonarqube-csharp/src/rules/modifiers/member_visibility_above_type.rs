use super::support::has_modifier;
use crate::AnalyzerOptions;
use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of,
};
use crate::project_index::ProjectTypeIndex;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::structure::name_anchor;
use crate::semantic::is_test_scope_file;
use hoonarqube_ir::Issue;
use std::collections::{BTreeSet, VecDeque};
use std::path::Path;
use tree_sitter::Node;

/// Member declaration kinds the reference rule inspects for a forced
/// `public` visibility, including nested type declarations.
const MEMBER_KINDS: [&str; 15] = [
    "class_declaration",
    "struct_declaration",
    "record_declaration",
    "enum_declaration",
    "interface_declaration",
    "delegate_declaration",
    "method_declaration",
    "property_declaration",
    "event_declaration",
    "event_field_declaration",
    "field_declaration",
    "indexer_declaration",
    "operator_declaration",
    "conversion_operator_declaration",
    "constructor_declaration",
];

/// Member kinds an interface can declare; only these can be interface
/// implementations in the reference rule's semantic model.
const INTERFACE_MEMBER_KINDS: [&str; 4] = [
    "method_declaration",
    "property_declaration",
    "event_declaration",
    "indexer_declaration",
];

/// csharpsquid:S3059 — the reference rule reports top-level types declared
/// with an explicit `internal` modifier that carry members declared `public`
/// and not forced to that visibility: `override` members keep their base
/// declaration's visibility, operators must be public, and interface
/// implementations must match the interface member's visibility. Interfaces
/// resolve through the project index with an in-file fallback. The catalog
/// scope is MAIN, so test/benchmark projects are never reported.
pub(crate) fn check(
    root: Node<'_>,
    path: &Path,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    if is_test_scope_file(path) {
        return Vec::new();
    }
    let declarations = TypeDeclarations::new(root, source, options.project_type_index.as_deref());
    let mut issues = Vec::new();
    for type_node in collect_kinds(
        root,
        &[
            "class_declaration",
            "struct_declaration",
            "record_declaration",
            "enum_declaration",
        ],
    ) {
        if is_error_tainted(type_node)
            || has_type_ancestor(type_node)
            || !has_modifier(&modifiers_of(type_node, source), "internal")
        {
            continue;
        }
        let interface_members =
            implemented_interface_member_names(type_node, source, &declarations);
        let offends = descendant_public_members(type_node, source)
            .iter()
            .any(|member| !member_is_forced_public(*member, source, &interface_members));
        if offends {
            issues.push(issue(
                language,
                "S3059",
                "Types should not have members with visibility set higher than the type's visibility",
                range_of(name_anchor(type_node), source),
            ));
        }
    }
    issues
}

/// Whether the declaration is nested inside another type declaration; only
/// top-level types are reported by the reference rule.
fn has_type_ancestor(type_node: Node<'_>) -> bool {
    std::iter::successors(type_node.parent(), Node::parent)
        .any(|ancestor| TYPE_DECLARATION_KINDS.contains(&ancestor.kind()))
}

/// Every member declaration below the type, including members of nested
/// types — the reference rule aggregates the whole declaration subtree.
fn descendant_public_members<'a>(type_node: Node<'a>, source: &str) -> Vec<Node<'a>> {
    collect_kinds(type_node, &MEMBER_KINDS)
        .into_iter()
        .filter(|member| member.id() != type_node.id())
        .filter(|member| has_modifier(&modifiers_of(*member, source), "public"))
        .collect()
}

/// Whether the member's `public` visibility is forced by its contract:
/// overrides, operators, and interface implementations cannot be lowered.
fn member_is_forced_public(
    member: Node<'_>,
    source: &str,
    interface_members: &BTreeSet<String>,
) -> bool {
    let modifiers = modifiers_of(member, source);
    if has_modifier(&modifiers, "override")
        || matches!(
            member.kind(),
            "operator_declaration" | "conversion_operator_declaration"
        )
    {
        return true;
    }
    if !INTERFACE_MEMBER_KINDS.contains(&member.kind()) {
        return false;
    }
    member
        .child_by_field_name("name")
        .map(|name| node_text(name, source))
        .is_some_and(|name| interface_members.contains(name))
}

/// Names of every member declared by the interfaces the type implements,
/// transitively through its base list (interfaces of base classes included).
fn implemented_interface_member_names(
    type_node: Node<'_>,
    source: &str,
    declarations: &TypeDeclarations<'_>,
) -> BTreeSet<String> {
    let mut member_names = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut queue: VecDeque<String> = base_simple_names(type_node, source)
        .into_iter()
        .map(str::to_string)
        .collect();
    while let Some(name) = queue.pop_front() {
        if !seen.insert(name.clone()) {
            continue;
        }
        for candidate in declarations.lookup(&name) {
            if candidate.is_interface {
                member_names.extend(candidate.member_names);
            }
            queue.extend(candidate.bases.iter().cloned());
        }
    }
    member_names
}

/// Type declarations visible for base resolution: the project index when a
/// scan supplies one, otherwise the declarations of the analyzed file alone.
enum TypeDeclarations<'a> {
    Project(&'a ProjectTypeIndex),
    Local(Vec<(&'a str, bool, BTreeSet<&'a str>, Vec<&'a str>)>),
}

impl<'a> TypeDeclarations<'a> {
    fn new(root: Node<'a>, source: &'a str, project: Option<&'a ProjectTypeIndex>) -> Self {
        if let Some(index) = project {
            Self::Project(index)
        } else {
            let mut declarations = Vec::new();
            for declaration in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
                let Some(name) = declaration.child_by_field_name("name") else {
                    continue;
                };
                let mut member_names = BTreeSet::new();
                for member in collect_kinds(declaration, &INTERFACE_MEMBER_KINDS) {
                    if let Some(member_name) = member.child_by_field_name("name") {
                        member_names.insert(node_text(member_name, source));
                    }
                }
                declarations.push((
                    node_text(name, source),
                    declaration.kind() == "interface_declaration",
                    member_names,
                    base_simple_names(declaration, source),
                ));
            }
            Self::Local(declarations)
        }
    }

    /// Every declaration of the simple name: interface flag, declared
    /// interface-member names, and base simple names.
    fn lookup(&self, name: &str) -> Vec<TypeLookup> {
        match self {
            Self::Project(index) => index
                .type_declarations(name)
                .map(|indexed| TypeLookup {
                    is_interface: indexed.is_interface,
                    member_names: indexed
                        .methods
                        .keys()
                        .cloned()
                        .chain(indexed.members.iter().map(|member| member.name.clone()))
                        .collect(),
                    bases: indexed.bases.clone(),
                })
                .collect(),
            Self::Local(declarations) => declarations
                .iter()
                .filter(|(candidate, ..)| *candidate == name)
                .map(|(_, is_interface, member_names, bases)| TypeLookup {
                    is_interface: *is_interface,
                    member_names: member_names
                        .iter()
                        .map(|name| (*name).to_string())
                        .collect(),
                    bases: bases.iter().map(|base| (*base).to_string()).collect(),
                })
                .collect(),
        }
    }
}

struct TypeLookup {
    is_interface: bool,
    member_names: Vec<String>,
    bases: Vec<String>,
}
