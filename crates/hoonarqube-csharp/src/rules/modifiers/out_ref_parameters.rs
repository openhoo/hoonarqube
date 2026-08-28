use super::support::{accessibility_rank, has_modifier};
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, issue, modifiers_of, node_text, parameters_of, range_from_byte_offsets,
};
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
        if accessibility_rank(&modifiers) != 6 {
            continue;
        }
        for parameter in parameters_of(method) {
            let parameter_modifiers = modifiers_of(parameter, source);
            for modifier_kind in ["out", "ref"] {
                if has_modifier(&parameter_modifiers, modifier_kind) {
                    issues.push(issue(
                        language,
                        "S3874",
                        format!("Consider refactoring this method in order to remove the need for this '{modifier_kind}' modifier."),
                        node_text(parameter, source)
                            .find(modifier_kind)
                            .map_or_else(
                                || {
                                range_from_byte_offsets(
                                    parameter.start_byte(),
                                    parameter.end_byte(),
                                    source,
                                )
                                },
                                |offset| {
                                    let start = parameter.start_byte() + offset;
                                    range_from_byte_offsets(
                                        start,
                                        start + modifier_kind.len(),
                                        source,
                                    )
                                },
                            ),
                    ));
                }
            }
        }
    }
    issues
}
