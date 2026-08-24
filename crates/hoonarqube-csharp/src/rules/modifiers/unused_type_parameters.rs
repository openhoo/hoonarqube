use super::support::type_parameter_list_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of, to_u32};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2326 — type parameters unused anywhere in their declaration
/// are dead weight; constraint references count as usage. Shadowing between
/// nested scopes is ignored.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut declarations = collect_kinds(root, &TYPE_DECLARATION_KINDS);
    declarations.extend(collect_kinds(
        root,
        &["method_declaration", "delegate_declaration"],
    ));
    let mut issues = Vec::new();
    for declaration in declarations {
        let Some((list, _)) = type_parameter_list_of(declaration) else {
            continue;
        };
        let mut counts: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
        for identifier in collect_kinds(declaration, &["identifier"]) {
            *counts.entry(node_text(identifier, source)).or_insert(0) += 1;
        }
        let declared: Vec<Node> = collect_kinds(list, &["type_parameter"]);
        for parameter in &declared {
            let name = node_text(*parameter, source);
            let occurrences_in_list = to_u32(
                declared
                    .iter()
                    .filter(|other| node_text(**other, source) == name)
                    .count(),
            );
            let uses_outside = counts
                .get(name)
                .copied()
                .unwrap_or(0)
                .saturating_sub(occurrences_in_list);
            if uses_outside == 0 {
                issues.push(issue(
                    language,
                    "S2326",
                    format!("Remove this unused type parameter \"{name}\"."),
                    range_of(*parameter),
                ));
            }
        }
    }
    issues
}
