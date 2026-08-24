use super::support::block_statements;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::structure::{else_alternative, embedded_bodies, is_else_alternative};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3923 — every branch of a conditional runs the same code.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &["if_statement"]) {
        if is_error_tainted(header) || is_else_alternative(header) {
            continue;
        }
        let Some(texts) = if_chain_branch_texts(header, source) else {
            continue;
        };
        let identical = texts.len() >= 2
            && texts.iter().all(|text| !text.is_empty())
            && texts.windows(2).all(|pair| pair[0] == pair[1]);
        if identical {
            issues.push(issue(
                language,
                "S3923",
                "Every branch of this conditional performs the same actions.",
                range_of(header),
            ));
        }
    }
    issues
}

/// Statement text of a branch body; block wrappers are flattened so
/// `{ return 1; }` and `return 1;` compare equal.
fn branch_body_text(body: Node<'_>, source: &str) -> String {
    if body.kind() == "block" {
        block_statements(body)
            .iter()
            .map(|statement| node_text(*statement, source))
            .collect::<Vec<_>>()
            .concat()
    } else {
        node_text(body, source).to_string()
    }
}

/// Branch body texts of a complete if/else-if/else chain, or `None` when the
/// chain lacks a terminal `else` (incomplete coverage).
fn if_chain_branch_texts(header: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut texts = Vec::new();
    let mut current = Some(header);
    while let Some(if_statement) = current {
        let consequence = *embedded_bodies(if_statement).first()?;
        texts.push(branch_body_text(consequence, source));
        let alternative = else_alternative(if_statement)?;
        if alternative.kind() == "if_statement" {
            current = Some(alternative);
        } else {
            texts.push(branch_body_text(alternative, source));
            current = None;
        }
    }
    Some(texts)
}
