use super::support::literal_inner_text;
use super::support::string_literals;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1075 — URIs belong in configuration, not literals.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    string_literals(root)
        .into_iter()
        .filter(|literal| {
            let lowered = literal_inner_text(*literal, source).to_lowercase();
            URI_SCHEMES.iter().any(|scheme| lowered.starts_with(scheme))
        })
        .map(|literal| {
            issue(
                language,
                "S1075",
                "Refactor your code not to use hard-coded URLs.",
                range_of(literal, source),
            )
        })
        .collect()
}

/// URI schemes whose hard-coded presence S1075 tracks.
const URI_SCHEMES: [&str; 7] = [
    "http://", "https://", "ftp://", "ftps://", "file://", "ws://", "wss://",
];
