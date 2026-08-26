use super::support::creation_argument_expressions;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{creation_type_text, integer_literal_value};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6588 — the Unix epoch literal spells `UnixEpoch`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const EPOCH_COMPONENTS: [u64; 3] = [1970, 1, 1];
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if is_error_tainted(creation)
            || simple_name(creation_type_text(creation, source)) != "DateTime"
        {
            continue;
        }
        let arguments = creation_argument_expressions(creation);
        if arguments.len() < 3 {
            continue;
        }
        let matches_epoch = EPOCH_COMPONENTS.iter().enumerate().all(|(index, wanted)| {
            arguments[index].kind() == "integer_literal"
                && integer_literal_value(node_text(arguments[index], source)) == Some(*wanted)
        });
        if matches_epoch {
            issues.push(issue(
                language,
                "S6588",
                "Use 'DateTimeOffset.UnixEpoch' instead of this literal.",
                range_of(creation, source),
            ));
        }
    }
    issues
}
