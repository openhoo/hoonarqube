use super::support::local_type_declarations;
use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::member_declarations_of_kind;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3444 — interfaces re-declaring members already inherited
/// from a file-local base interface, which forces implementers to disambiguate.
/// Subset: direct single-file chains.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let interfaces: std::collections::HashMap<&str, Node<'_>> = local_type_declarations(root)
        .into_iter()
        .filter(|declaration| declaration.kind() == "interface_declaration")
        .filter_map(|declaration| {
            declaration
                .child_by_field_name("name")
                .map(|name| (node_text(name, source), declaration))
        })
        .collect();
    collect_kinds(root, &["interface_declaration"])
        .into_iter()
        .filter(|declaration| !is_error_tainted(*declaration))
        .filter_map(|declaration| {
            let base_name = *base_simple_names(declaration, source).first()?;
            let base = interfaces.get(base_name)?;
            let own = direct_member_names(declaration, source);
            let inherited = direct_member_names(*base, source);
            (!own.is_empty() && own.intersection(&inherited).next().is_some())
                .then(|| declaration.child_by_field_name("name"))
                .flatten()
        })
        .map(|name| {
            issue(
                language,
                "S3444",
                "Remove the inherited members re-declared by this interface.",
                range_of(name, source),
            )
        })
        .collect()
}

/// Names of members a type declares directly (`method_declaration` and
/// `property_declaration`).
fn direct_member_names<'a>(
    type_node: Node<'a>,
    source: &'a str,
) -> std::collections::HashSet<&'a str> {
    ["method_declaration", "property_declaration"]
        .into_iter()
        .flat_map(|kind| member_declarations_of_kind(type_node, kind))
        .filter_map(|member| member.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .collect()
}
