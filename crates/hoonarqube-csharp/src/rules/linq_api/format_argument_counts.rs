use super::support::composite_template;
use super::support::is_composite_format_call;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, to_u32};
use crate::rules::logging::template_placeholders;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2275 — every referenced format slot needs an argument.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) || !is_composite_format_call(call, source) {
            continue;
        }
        let Some((literal, template, budget)) = composite_template(call, source) else {
            continue;
        };
        let highest = template_placeholders(template)
            .iter()
            .filter_map(|name| format_slot_index(name))
            .max();
        if highest.is_some_and(|index| index + 1 > to_u32(budget)) {
            issues.push(issue(
                language,
                "S2275",
                "Match the format-string slots to the arguments of this call.",
                range_of(literal),
            ));
        }
    }
    issues
}

/// Numeric index of a `{12}`-style format slot.
fn format_slot_index(name: &str) -> Option<u32> {
    if !name.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }
    name.parse().ok()
}
