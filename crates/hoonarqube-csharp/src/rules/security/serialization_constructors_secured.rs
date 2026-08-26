use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, parameters_of, range_of,
    simple_name,
};
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4212 — serialization constructors stay hidden from callers.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const SERIALIZATION_PARAM_TYPES: [&str; 2] = ["SerializationInfo", "StreamingContext"];
    let mut issues = Vec::new();
    for constructor in collect_kinds(root, &["constructor_declaration"]) {
        if is_error_tainted(constructor) {
            continue;
        }
        let param_types: Vec<String> = parameters_of(constructor)
            .into_iter()
            .filter_map(|param| param.child_by_field_name("type"))
            .map(|ty| simple_name(node_text(ty, source)).to_string())
            .collect();
        if !SERIALIZATION_PARAM_TYPES
            .iter()
            .all(|wanted| param_types.iter().any(|found| found == wanted))
        {
            continue;
        }
        let modifiers = modifiers_of(constructor, source);
        let family_visible = has_modifier(&modifiers, "protected");
        let exposed = has_modifier(&modifiers, "public")
            || (has_modifier(&modifiers, "internal") && !family_visible);
        if exposed {
            issues.push(issue(
                language,
                "S4212",
                "Reduce the visibility of this serialization constructor.",
                range_of(constructor, source),
            ));
        }
    }
    issues
}
