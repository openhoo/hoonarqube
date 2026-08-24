use super::support::identifier_usages;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4790 — 'MD5' and 'SHA1' are broken for security purposes.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const WEAK_HASH_TYPES: [&str; 9] = [
        "MD5",
        "HMACMD5",
        "MD5CryptoServiceProvider",
        "MD5Cng",
        "SHA1",
        "HMACSHA1",
        "SHA1CryptoServiceProvider",
        "SHA1Cng",
        "SHA1Managed",
    ];
    identifier_usages(root, source, &WEAK_HASH_TYPES)
        .into_iter()
        .map(|identifier| {
            issue(
                language,
                "S4790",
                "Use a stronger hash algorithm such as 'SHA256'.",
                range_of(identifier),
            )
        })
        .collect()
}
