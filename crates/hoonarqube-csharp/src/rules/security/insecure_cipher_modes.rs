use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5542 — unauthenticated modes and zero padding leak or forge
/// plaintext.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mode_accesses = banned_member_accesses(root, source, "CipherMode", &["ECB", "OFB", "CFB"]);
    let padding_accesses = banned_member_accesses(root, source, "PaddingMode", &["None", "Zeros"]);
    mode_accesses
        .into_iter()
        .chain(padding_accesses)
        .map(|access| {
            issue(
                language,
                "S5542",
                "Encrypt with an authenticated cipher mode and explicit padding.",
                range_of(access),
            )
        })
        .collect()
}
