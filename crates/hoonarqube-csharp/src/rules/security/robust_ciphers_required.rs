use super::support::identifier_usages;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
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
            issue(
                language,
                "S5547",
                "Use a robust cipher such as 'Aes' instead of this provider.",
                range_of(identifier),
            )
        })
        .collect()
}
