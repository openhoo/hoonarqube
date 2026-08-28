use crate::CsLanguage;
use crate::cst::{issue, range_from_byte_offsets, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S122 — statements live on separate lines. Only statements
/// directly inside statement-list containers count, so embedded bodies such
/// as `if (x) DoIt();` stay clean.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut statements_per_row: std::collections::BTreeMap<usize, Vec<Node>> =
        std::collections::BTreeMap::new();
    walk_all(root, &mut |node| {
        let kind = node.kind();
        if kind == "global_statement" || !kind.ends_with("_statement") {
            return;
        }
        let Some(parent) = node.parent() else {
            return;
        };
        if !STATEMENT_CONTAINER_KINDS.contains(&parent.kind()) {
            return;
        }
        statements_per_row
            .entry(node.start_position().row)
            .or_default()
            .push(node);
    });
    let mut issues = Vec::new();
    for row_statements in statements_per_row.values() {
        if let (Some(first), Some(last)) = (row_statements.first(), row_statements.last())
            && row_statements.len() > 1
        {
            issues.push(issue(
                language,
                "S122",
                "Reformat the code to have only one statement per line.",
                range_from_byte_offsets(first.start_byte(), last.end_byte(), source),
            ));
        }
    }
    issues
}

/// Containers whose direct children form statement lists; `global_statement`
/// wraps top-level statements in top-level-program files.
const STATEMENT_CONTAINER_KINDS: [&str; 6] = [
    "block",
    "compilation_unit",
    "declaration_list",
    "switch_body",
    "switch_section",
    "global_statement",
];
