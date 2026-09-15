use super::support::name_anchor;
use crate::AnalyzerOptions;
use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of,
};
use crate::project_index::ProjectTypeIndex;
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::declaration_kind_word;
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Base classes whose empty derivatives carry meaning in the reference rule
/// (`System.Attribute`, `System.Exception`, ASP.NET `PageModel`).
const IGNORED_BASE_CLASSES: [&str; 3] = ["Attribute", "Exception", "PageModel"];

/// Names the reference rule ignores outright (`DefaultDocumentation` holders).
const IGNORED_NAMES: [&str; 2] = ["AssemblyDoc", "NamespaceDoc"];

/// Name suffixes the reference rule ignores (messaging-style markers).
const IGNORED_SUFFIXES: [&str; 4] = ["Command", "Event", "Message", "Query"];

/// csharpsquid:S2094 — classes and records carry members. The reference rule
/// exempts attributed types, conditionally compiled declarations, documented
/// marker names, and empty types whose base contract gives them meaning
/// (attributes, exceptions, interfaces, abstract or generic bases, primary
/// constructors); comments never count as members.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    const KINDS: [&str; 2] = ["class_declaration", "record_declaration"];
    let project = options.project_type_index.as_deref();
    let mut issues = Vec::new();
    for type_declaration in collect_kinds(root, &KINDS) {
        let modifiers = modifiers_of(type_declaration, source);
        let positional = positional_parameters(type_declaration).is_some();
        if is_error_tainted(type_declaration)
            || has_modifier(&modifiers, "partial")
            || positional
            || has_any_attribute(type_declaration)
            || has_conditional_compilation(type_declaration, source)
        {
            continue;
        }
        let name = name_of(type_declaration, source);
        if is_ignored_name(name) || is_exempt_base_type(type_declaration, source, project) {
            continue;
        }
        if type_has_no_members(type_declaration) {
            issues.push(issue(
                language,
                "S2094",
                format!(
                    "Remove this empty {}, write its code or make it an \"interface\".",
                    declaration_kind_word(type_declaration.kind())
                ),
                range_of(name_anchor(type_declaration), source),
            ));
        }
    }
    issues
}

fn name_of<'a>(type_declaration: Node<'a>, source: &'a str) -> &'a str {
    type_declaration
        .child_by_field_name("name")
        .map(|name| node_text(name, source))
        .unwrap_or_default()
}

fn is_ignored_name(name: &str) -> bool {
    IGNORED_NAMES.contains(&name) || IGNORED_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

/// A primary constructor on the declaration or base type arguments bind the
/// type to constructed state, so it is not an empty shell.
fn positional_parameters(type_declaration: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = type_declaration.walk();
    type_declaration
        .children(&mut cursor)
        .find(|child| child.kind() == "parameter_list")
        .or_else(|| {
            let mut cursor = type_declaration.walk();
            type_declaration
                .children(&mut cursor)
                .find(|child| child.kind() == "base_list")
                .and_then(|base_list| {
                    let mut base_cursor = base_list.walk();
                    base_list
                        .children(&mut base_cursor)
                        .find(|base| base.kind() == "primary_constructor_base_type")
                        .and_then(|base| {
                            let mut argument_cursor = base.walk();
                            base.children(&mut argument_cursor)
                                .find(|child| child.kind() == "argument_list")
                        })
                })
        })
        .filter(|arguments| arguments.named_child_count() > 0)
}

fn has_any_attribute(type_declaration: Node<'_>) -> bool {
    let mut cursor = type_declaration.walk();
    type_declaration
        .children(&mut cursor)
        .any(|child| child.kind() == "attribute_list")
}

/// Conditional compilation wraps the declaration in the reference tree: a
/// directive inside the declaration body, or the directive region attached
/// immediately before it, means the compiler may never see an empty type.
fn has_conditional_compilation(type_declaration: Node<'_>, source: &str) -> bool {
    let mut cursor = type_declaration.walk();
    if type_declaration
        .children(&mut cursor)
        .any(|child| child.kind().starts_with("preproc_"))
    {
        return true;
    }
    let Some(parent) = type_declaration.parent() else {
        return false;
    };
    if !matches!(
        parent.kind(),
        "preproc_if" | "preproc_ifdef" | "preproc_else" | "preproc_elif"
    ) {
        return false;
    }
    let prefix = &source[parent.start_byte()..type_declaration.start_byte()];
    prefix
        .lines()
        .all(|line| line.trim().is_empty() || line.trim_start().starts_with('#'))
}

/// Whether the declared bases give the empty type its meaning: several bases
/// (at least one is an interface), a generic base, a known marker base, or a
/// project-resolvable interface or abstract base class.
fn is_exempt_base_type(
    type_declaration: Node<'_>,
    source: &str,
    project: Option<&ProjectTypeIndex>,
) -> bool {
    let bases = base_simple_names(type_declaration, source);
    if bases.is_empty() {
        return false;
    }
    let mut cursor = type_declaration.walk();
    let generic_base = type_declaration
        .children(&mut cursor)
        .filter(|child| child.kind() == "base_list")
        .any(|base_list| {
            let mut base_cursor = base_list.walk();
            base_list
                .children(&mut base_cursor)
                .filter(|base| {
                    base.kind() == "generic_name" || base.kind() == "primary_constructor_base_type"
                })
                .any(|base| node_text(base, source).contains('<'))
        });
    generic_base
        || bases.len() > 1
        || bases.iter().any(|base| IGNORED_BASE_CLASSES.contains(base))
        || bases.iter().any(|base| {
            project.is_some_and(|index| {
                index
                    .type_declarations(base)
                    .any(|indexed| indexed.is_interface || indexed.is_abstract)
            })
        })
}

/// Whether a type's declaration list carries no member declarations;
/// comments are not members.
fn type_has_no_members(type_node: Node<'_>) -> bool {
    type_members(type_node)
        .into_iter()
        .filter(|member| member.kind() != "comment")
        .all(|member| !member.is_named())
}
