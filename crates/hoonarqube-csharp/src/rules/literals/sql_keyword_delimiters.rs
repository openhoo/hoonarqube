use super::support::literal_inner_text;
use super::support::string_literals;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2857 — SQL keywords must be delimited by whitespace;
/// glued spellings indicate dynamically concatenated queries.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    string_literals(root)
        .into_iter()
        .flat_map(|literal| {
            squeezed_sql_keywords(literal_inner_text(literal, source))
                .into_iter()
                .map(move |keyword| {
                    issue(
                        language,
                        "S2857",
                        format!(
                            "Delimit the SQL keyword '{}' with whitespace.",
                            keyword.to_ascii_uppercase()
                        ),
                        range_of(literal, source),
                    )
                })
        })
        .collect()
}

/// SQL keywords whose squeezed spelling (`SELECT*FROM`) betrays concatenated
/// query strings.
const SQL_KEYWORDS: [&str; 12] = [
    "select", "insert", "update", "delete", "drop", "alter", "create", "truncate", "union",
    "merge", "exec", "execute",
];

/// SQL keywords inside the literal that touch a following punctuation symbol
/// instead of whitespace (`SELECT*`). Longer words merely containing a
/// keyword (`SELECTION`) stay clean.
fn squeezed_sql_keywords(text: &str) -> Vec<&'static str> {
    let lowered = text.to_lowercase();
    SQL_KEYWORDS
        .iter()
        .filter(|keyword| {
            let mut search_from = 0;
            while let Some(found) = lowered[search_from..].find(*keyword) {
                let start = search_from + found;
                let end = start + keyword.len();
                let bytes = lowered.as_bytes();
                let word_started = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
                let squeezed = end < bytes.len()
                    && !bytes[end].is_ascii_whitespace()
                    && !bytes[end].is_ascii_alphanumeric();
                if word_started && squeezed {
                    return true;
                }
                search_from = start + keyword.len();
            }
            false
        })
        .copied()
        .collect()
}
