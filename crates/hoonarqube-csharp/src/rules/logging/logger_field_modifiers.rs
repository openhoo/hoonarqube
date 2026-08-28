use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of, simple_name,
};
use crate::rules::modifiers::has_modifier;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1312 — logger fields follow one shape so tooling finds them.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    _options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        if is_error_tainted(field) {
            continue;
        }
        let logger_typed = field
            .child_by_field_name("type")
            .or_else(|| {
                collect_kinds(field, &["variable_declaration"])
                    .into_iter()
                    .next()
                    .and_then(|declaration| declaration.child_by_field_name("type"))
            })
            .is_some_and(|type_node| simple_name(node_text(type_node, source)) == "ILogger");
        if !logger_typed {
            continue;
        }
        let modifiers = modifiers_of(field, source);
        let shaped = ["private", "static", "readonly"]
            .iter()
            .all(|wanted| has_modifier(&modifiers, wanted));
        if !shaped {
            for declarator in collect_kinds(field, &["variable_declarator"]) {
                if let Some(name) = declarator.child_by_field_name("name") {
                    issues.push(issue(
                        language,
                        "S1312",
                        format!(
                            "Make the logger '{}' private static readonly.",
                            node_text(name, source)
                        ),
                        range_of(name, source),
                    ));
                }
            }
        }
    }
    issues
}
