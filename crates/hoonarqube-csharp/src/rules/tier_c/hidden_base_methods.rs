use crate::cst::{
    base_simple_names, is_error_tainted, issue, modifiers_of, node_text, parameter_signature_texts,
    range_of, simple_name,
};
use crate::project_index::{IndexedParameter, IndexedType, ProjectTypeIndex};
use crate::rules::modifiers::{has_modifier, type_parameter_list_of};
use crate::rules::naming::support::{
    full_type_identity, has_explicit_interface_specifier, type_members,
};
use crate::rules::tier_c::support::{
    graph_reaches, local_inheritance_graph, local_type_declarations, local_type_table,
};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use std::collections::HashMap;
use tree_sitter::Node;

/// A hidden base-method candidate: identity plus comparison shape.
struct HiddenSite {
    owner_name: String,
    parameters: Vec<IndexedParameter>,
    display: String,
}

/// csharpsquid:S4019 — a derived method hides a same-name base-class method
/// when their signatures are compatible: same arity, equal ref-kind, and
/// every derived parameter type equal to or wider than the base's, so calls
/// intended for the base method can no longer bind to it. Only base classes
/// count: interface members are implemented, never hidden, so an
/// interface-only base contributes no candidates. Base resolution uses the
/// file-local type table, and every accepted project file when a
/// [`ProjectTypeIndex`] is supplied; the querying type's own (partial)
/// declarations are never base candidates, even when a generic sibling
/// shares the simple-name key.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let project = options.project_type_index.as_deref();
    let types = local_type_table(root, source);
    let graph = (project.is_none()).then(|| local_inheritance_graph(root, source));
    let mut issues = Vec::new();
    for declaration in local_type_declarations(root) {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(base_name) = base_simple_names(declaration, source).first().copied() else {
            continue;
        };
        if is_interface_base(base_name, &types, project) {
            continue;
        }
        let own = (
            full_type_identity(declaration, source),
            type_parameter_list_of(declaration).map_or(0, |(_, count)| count),
        );
        for (name_node, method_name, derived_parameters) in derived_methods(declaration, source) {
            for hidden in hidden_sites(base_name, method_name, &types, source, project, &own) {
                if !hides(&derived_parameters, &hidden, project, graph.as_ref()) {
                    continue;
                }
                issues.push(issue(
                    language,
                    "S4019",
                    format!(
                        "Remove or rename that method because it hides '{}.{}({})'.",
                        hidden.owner_name, method_name, hidden.display
                    ),
                    range_of(name_node, source),
                ));
            }
        }
    }
    issues
}

/// Selected hiding candidates of one type declaration: name anchor, simple
/// name, and normalized parameter signature.
fn derived_methods<'a>(
    declaration: Node<'a>,
    source: &'a str,
) -> Vec<(Node<'a>, &'a str, Vec<IndexedParameter>)> {
    type_members(declaration)
        .into_iter()
        .filter(|method| method.kind() == "method_declaration")
        .filter(|method| !has_explicit_interface_specifier(*method))
        .filter(|method| !is_error_tainted(*method))
        .filter_map(|method| hiding_method(method, source))
        .collect()
}

fn hiding_method<'a>(
    method: Node<'a>,
    source: &'a str,
) -> Option<(Node<'a>, &'a str, Vec<IndexedParameter>)> {
    let modifiers = modifiers_of(method, source);
    if has_modifier(&modifiers, "override") || has_modifier(&modifiers, "new") {
        return None;
    }
    let name_node = method.child_by_field_name("name")?;
    let parameters = parameter_signature_texts(method, source)
        .into_iter()
        .map(|(ref_kind, type_key, display)| IndexedParameter {
            ref_kind,
            type_key,
            display,
        })
        .collect();
    Some((name_node, node_text(name_node, source), parameters))
}
/// Collects same-name methods of the named base type, from the project index
/// when present, otherwise from the file-local base declaration. The
/// querying type's own declarations never count as their own base: a type
/// cannot hide members it (partially) declares itself, even when a generic
/// sibling shares the simple-name key. Interface declarations sharing the
/// base's simple name contribute no candidates either: interface members
/// are implemented, never hidden.
fn hidden_sites<'a>(
    base_name: &'a str,
    method_name: &str,
    types: &HashMap<&'a str, Node<'a>>,
    source: &'a str,
    project: Option<&ProjectTypeIndex>,
    own: &(Option<String>, u32),
) -> Vec<HiddenSite> {
    if let Some(project) = project {
        return project
            .same_name_methods(base_name, method_name)
            .into_iter()
            .filter(|(declaration, _)| {
                !declaration.is_interface && !is_own_declaration(declaration, own)
            })
            .map(|(_, method)| HiddenSite {
                owner_name: base_name.to_string(),
                parameters: method.parameters.clone(),
                display: parameters_display(&method.parameters),
            })
            .collect();
    }
    let Some(base) = types.get(base_name).copied() else {
        return Vec::new();
    };
    if base.kind() == "interface_declaration" || is_file_local_self(base, source, own) {
        return Vec::new();
    }
    type_members(base)
        .into_iter()
        .filter(|member| member.kind() == "method_declaration")
        .filter_map(|member| {
            let name = member.child_by_field_name("name")?;
            (node_text(name, source) == method_name).then_some(member)
        })
        .map(|member| {
            let parameters: Vec<IndexedParameter> = parameter_signature_texts(member, source)
                .into_iter()
                .map(|(ref_kind, type_key, display)| IndexedParameter {
                    ref_kind,
                    type_key,
                    display,
                })
                .collect();
            let display = parameters_display(&parameters);
            HiddenSite {
                owner_name: base_name.to_string(),
                parameters,
                display,
            }
        })
        .collect()
}

/// Whether an indexed declaration is the querying type itself: same
/// syntactic identity and type-parameter arity, so partial parts and a
/// generic sibling sharing the simple-name key are recognized.
fn is_own_declaration(declaration: &IndexedType, own: &(Option<String>, u32)) -> bool {
    Some(declaration.identity.as_str()) == own.0.as_deref() && declaration.arity == own.1
}

/// Whether the file-local base entry is the querying type's own declaration,
/// the last-wins collapse of a same-name pair (`class C` and `class C<T>`).
fn is_file_local_self<'a>(base: Node<'a>, source: &'a str, own: &(Option<String>, u32)) -> bool {
    full_type_identity(base, source).as_deref() == own.0.as_deref()
        && type_parameter_list_of(base).map_or(0, |(_, count)| count) == own.1
}

/// Whether the base spelling resolves only to interface declarations:
/// interface members are implemented, never hidden, so such a base
/// contributes no hiding candidates.
fn is_interface_base<'a>(
    base_name: &str,
    types: &HashMap<&'a str, Node<'a>>,
    project: Option<&ProjectTypeIndex>,
) -> bool {
    if let Some(project) = project {
        return project.interface_only_name(base_name);
    }
    types
        .get(base_name)
        .is_some_and(|base| base.kind() == "interface_declaration")
}

fn parameters_display(parameters: &[IndexedParameter]) -> String {
    parameters
        .iter()
        .map(|parameter| parameter.display.clone())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether `derived` hides `hidden`: same arity, equal ref-kind, and each
/// derived parameter type equal to or a known supertype of the base's.
fn hides(
    derived: &[IndexedParameter],
    hidden: &HiddenSite,
    project: Option<&ProjectTypeIndex>,
    graph: Option<&HashMap<&str, Vec<&str>>>,
) -> bool {
    derived.len() == hidden.parameters.len()
        && derived
            .iter()
            .zip(hidden.parameters.iter())
            .all(|(derived, base)| {
                derived.ref_kind == base.ref_kind
                    && type_covers(&derived.type_key, &base.type_key, project, graph)
            })
}

/// Whether the derived parameter type subsumes the base parameter type:
/// identical spellings, the universal `object` base, or a provable ancestor
/// through indexed or file-local inheritance. Generic and array spellings
/// pair only when identical, keeping the subset conservative.
fn type_covers(
    derived: &str,
    base: &str,
    project: Option<&ProjectTypeIndex>,
    graph: Option<&HashMap<&str, Vec<&str>>>,
) -> bool {
    if derived == base || matches!(derived, "object" | "System.Object") {
        return true;
    }
    if derived.contains(['<', '[']) || base.contains(['<', '[']) {
        return false;
    }
    let (derived_name, base_name) = (simple_name(derived), simple_name(base));
    if let Some(project) = project {
        project.type_reaches(base_name, derived_name)
    } else if let Some(graph) = graph {
        graph_reaches(graph, &base_name, |name| *name == derived_name)
    } else {
        false
    }
}
