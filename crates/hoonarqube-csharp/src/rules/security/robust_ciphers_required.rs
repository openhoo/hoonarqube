use super::support::identifier_usages;
use crate::CsLanguage;
use crate::cst::{ancestors_of, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5547 — legacy block ciphers belong in museums, not code.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const WEAK_CIPHER_PROVIDERS: [&str; 7] = [
        "DES",
        "TripleDES",
        "RC2",
        "RC4",
        "DESCryptoServiceProvider",
        "TripleDESCryptoServiceProvider",
        "RC2CryptoServiceProvider",
    ];
    identifier_usages(root, source, &WEAK_CIPHER_PROVIDERS)
        .into_iter()
        .map(|identifier| {
            let expression = ancestors_of(identifier)
                .find(|ancestor| {
                    matches!(
                        ancestor.kind(),
                        "invocation_expression" | "object_creation_expression"
                    )
                })
                .unwrap_or(identifier);
            let anchor = if expression.kind() == "object_creation_expression" {
                expression.child_by_field_name("type").unwrap_or(expression)
            } else {
                expression
            };
            issue(
                language,
                "S5547",
                "Use a strong cipher algorithm.",
                range_of(anchor, source),
            )
        })
        .collect()
}
