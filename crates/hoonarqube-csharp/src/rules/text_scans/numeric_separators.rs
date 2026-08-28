use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2148 — large numbers use digit separators. Decimal literals
/// of 10 000 and above without an underscore are flagged; hexadecimal and
/// binary literals are exempt.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if node.kind() != "integer_literal" {
            return;
        }
        let lowered = node_text(node, source).to_ascii_lowercase();
        if lowered.contains('_') || lowered.starts_with("0x") || lowered.starts_with("0b") {
            return;
        }
        if !is_large_unseparated_number(&lowered) {
            return;
        }
        issues.push(issue(
            language,
            "S2148",
            "Add underscores to this numeric value for readability.",
            range_of(node, source),
        ));
    });
    issues
}

fn is_large_unseparated_number(lowered: &str) -> bool {
    let digits = lowered.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    digits.chars().filter(char::is_ascii_digit).count() >= 7
}
