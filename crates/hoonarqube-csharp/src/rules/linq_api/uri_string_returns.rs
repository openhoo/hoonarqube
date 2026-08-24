use super::support::methods_grouped_by_name;
use crate::CsLanguage;
use crate::cst::{issue, range_of, simple_name};
use crate::rules::security::return_type_text;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3995 — string returns beside a sibling `System.Uri`
/// overload lose structure.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for methods in methods_grouped_by_name(root, source).into_values() {
        if methods.len() < 2 {
            continue;
        }
        let returns_uri = methods
            .iter()
            .any(|method| simple_name(return_type_text(*method, source)) == "Uri");
        if !returns_uri {
            continue;
        }
        for method in &methods {
            if simple_name(return_type_text(*method, source)) == "string" {
                issues.push(issue(
                    language,
                    "S3995",
                    "Return a 'System.Uri' instead of a string here.",
                    range_of(name_anchor(*method)),
                ));
            }
        }
    }
    issues
}
