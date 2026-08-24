use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::structure::binary_operator;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2257 — cipher-named members containing raw XOR bit-mixing,
/// the canonical hand-rolled-cipher tell. Subset: method names matching
/// Encrypt/Decrypt/Crypt plus an XOR somewhere in the body.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const CIPHER_NAME_PARTS: [&str; 2] = ["Encrypt", "Decrypt"];
    collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| !is_error_tainted(*method))
        .filter(|method| {
            method.child_by_field_name("name").is_some_and(|name| {
                let text = node_text(name, source);
                CIPHER_NAME_PARTS.iter().any(|part| text.contains(part))
            })
        })
        .filter(|method| {
            collect_kinds(*method, &["binary_expression"])
                .into_iter()
                .any(|expression| binary_operator(expression, source) == "^")
        })
        .filter_map(|method| method.child_by_field_name("name"))
        .map(|name| {
            issue(
                language,
                "S2257",
                "Replace this hand-written cipher routine with a vetted library implementation.",
                range_of(name),
            )
        })
        .collect()
}
