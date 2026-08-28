use crate::CsLanguage;
use crate::cst::{attributes_of, collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::modifiers::has_any_attribute;
use crate::rules::naming::type_members;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6803 — query binding only runs for routable components;
/// `[SupplyParameterFromQuery]` without a route silently never binds.
/// Bound: same-file classes; Razor routes outside `.razor` files are not
/// visible here.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_declaration) {
            continue;
        }
        let routable = attributes_of(class_declaration, source)
            .iter()
            .any(|name| name.ends_with("Route") || name.ends_with("RouteAttribute"));
        if routable {
            continue;
        }
        for property in type_members(class_declaration)
            .into_iter()
            .filter(|member| member.kind() == "property_declaration")
        {
            if has_any_attribute(property, source, &["SupplyParameterFromQuery"]) {
                issues.push(issue(
                    language,
                    "S6803",
                    "Component parameters can only receive query parameter values in routable components.",
                    range_of(name_anchor(property), source),
                ));
            }
        }
    }
    issues
}
