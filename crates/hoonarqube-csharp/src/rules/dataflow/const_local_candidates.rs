use super::support::callable_blocks;
use super::support::captured_names;
use super::support::identifier_write;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of, simple_name};
use crate::rules::literals::declarator_initializer;
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3353 — locals declared once from a literal and never
/// rewritten carry `const`. Bound: writes counted across the whole
/// member body; lambda-captured names stay exempt because capture
/// freezes their lifetime to the closure instead.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let captured = captured_names(body, source);
        let mut write_counts: std::collections::HashMap<&str, u32> =
            std::collections::HashMap::new();
        for identifier in collect_kinds(body, &["identifier"]) {
            if identifier_write(identifier).is_some() {
                *write_counts
                    .entry(node_text(identifier, source))
                    .or_default() += 1;
            }
        }
        for declaration in collect_kinds(body, &["local_declaration_statement"]) {
            if has_modifier(&modifiers_of(declaration, source), "const") {
                continue;
            }
            let type_text = declaration
                .children(&mut declaration.walk())
                .find(|child| child.kind() == "variable_declaration")
                .and_then(|variable| variable.child_by_field_name("type"))
                .map_or("", |type_node| simple_name(node_text(type_node, source)));
            if !CONST_CANDIDATE_TYPES.contains(&type_text) {
                continue;
            }
            for declarator in collect_kinds(declaration, &["variable_declarator"]) {
                let Some(name) = declarator.child_by_field_name("name") else {
                    continue;
                };
                let name = node_text(name, source);
                let literal_initializer = declarator_initializer(
                    declarator,
                    declarator.child_by_field_name("name").unwrap_or(declarator),
                )
                .is_some_and(|value| {
                    matches!(
                        value.kind(),
                        "integer_literal"
                            | "real_literal"
                            | "string_literal"
                            | "character_literal"
                            | "boolean_literal"
                    )
                });
                if literal_initializer
                    && !captured.contains(name)
                    && write_counts.get(name).copied().unwrap_or(0) <= 1
                {
                    issues.push(issue(
                        language,
                        "S3353",
                        format!("Declare '{name}' as 'const'."),
                        range_of(declarator),
                    ));
                }
            }
        }
    }
    issues
}

/// Primitive types a `const` local may declare.
const CONST_CANDIDATE_TYPES: [&str; 14] = [
    "bool", "byte", "char", "decimal", "double", "float", "int", "long", "sbyte", "short",
    "string", "uint", "ulong", "ushort",
];
