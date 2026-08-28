use super::support::literal_inner_text;
use super::support::string_literals;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1313 — hard-coded IP addresses belong in configuration.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    string_literals(root)
        .into_iter()
        .filter_map(|literal| {
            let address = literal_inner_text(literal, source);
            is_ipv4_address(address).then(|| {
                issue(
                    language,
                    "S1313",
                    format!("Make sure using this hardcoded IP address '{address}' is safe here."),
                    range_of(literal, source),
                )
            })
        })
        .collect()
}

/// Strict dotted-quad IPv4 shape with octets in range; versions and dates
/// never fully match.
fn is_ipv4_address(text: &str) -> bool {
    let octets: Vec<&str> = text.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.len() <= 3
                && octet.bytes().all(|byte| byte.is_ascii_digit())
                && octet.parse::<u16>().is_ok_and(|value| value <= 255)
        })
}
