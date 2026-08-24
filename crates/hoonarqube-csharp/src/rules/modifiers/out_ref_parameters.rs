use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, parameters_of, range_of};
use crate::rules::naming::has_explicit_interface_specifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3874 — `out`/`ref` parameters obscure data flow; overrides
/// must mirror their base signature, so they stay untouched.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let modifiers = modifiers_of(method, source);
        if has_modifier(&modifiers, "override") || has_explicit_interface_specifier(method) {
            continue;
        }
        for parameter in parameters_of(method) {
            let parameter_modifiers = modifiers_of(parameter, source);
            for modifier_kind in ["out", "ref"] {
                if has_modifier(&parameter_modifiers, modifier_kind) {
                    issues.push(issue(
                        language,
                        "S3874",
                        format!("Remove this '{modifier_kind}' parameter."),
                        range_of(parameter),
                    ));
                }
            }
        }
    }
    issues
}
