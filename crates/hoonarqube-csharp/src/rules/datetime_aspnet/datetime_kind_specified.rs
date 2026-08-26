use super::support::creation_argument_expressions;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::creation_type_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6562 — `DateTime` values without an explicit
/// `DateTimeKind` flip meaning across timezones and DST boundaries.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if is_error_tainted(creation)
            || simple_name(creation_type_text(creation, source)) != "DateTime"
        {
            continue;
        }
        let arguments = creation_argument_expressions(creation);
        let kind_specified = arguments
            .iter()
            .any(|argument| node_text(*argument, source).contains("DateTimeKind"));
        if !kind_specified {
            issues.push(issue(
                language,
                "S6562",
                "Specify the 'DateTimeKind' when constructing this value.",
                range_of(creation, source),
            ));
        }
    }
    issues
}
