use super::support::call_argument_nodes;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, simple_name};
use crate::rules::expressions::creation_type_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4581 — `new Guid()` yields all zeros; only `Guid.NewGuid`
/// produces a real identity.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if is_error_tainted(creation) {
            continue;
        }
        if simple_name(creation_type_text(creation, source)) == "Guid"
            && call_argument_nodes(creation).is_empty()
        {
            issues.push(issue(
                language,
                "S4581",
                "Generate a new GUID instead of relying on the empty value.",
                range_of(creation, source),
            ));
        }
    }
    issues
}
