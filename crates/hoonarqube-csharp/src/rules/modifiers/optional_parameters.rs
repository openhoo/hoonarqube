use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, parameters_of, range_of};
use crate::rules::naming::has_explicit_interface_specifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2360 — optional parameters complicate overload resolution;
/// overrides and explicit implementations must repeat base defaults, so they
/// stay untouched.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let modifiers = modifiers_of(method, source);
        if has_modifier(&modifiers, "override") || has_explicit_interface_specifier(method) {
            continue;
        }
        for parameter in parameters_of(method) {
            let mut cursor = parameter.walk();
            let has_default = parameter
                .children(&mut cursor)
                .any(|child| child.kind() == "=");
            if has_default {
                issues.push(issue(
                    language,
                    "S2360",
                    "Remove this optional parameter's default value.",
                    range_of(parameter),
                ));
            }
        }
    }
    issues
}
