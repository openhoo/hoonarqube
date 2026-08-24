use super::support::field_declarator_names;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, matches_logger_format, modifiers_of, range_of,
};
use crate::rules::modifiers::has_modifier;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1312 — logger fields follow one shape so tooling finds them.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        if is_error_tainted(field) {
            continue;
        }
        let logger_named = field_declarator_names(field, source)
            .into_iter()
            .any(|name| matches_logger_format(name, &options.logger_name_format));
        if !logger_named {
            continue;
        }
        let modifiers = modifiers_of(field, source);
        let shaped = ["private", "static", "readonly"]
            .iter()
            .all(|wanted| has_modifier(&modifiers, wanted));
        if !shaped {
            issues.push(issue(
                language,
                "S1312",
                "Declare this logger field 'private static readonly'.",
                range_of(field),
            ));
        }
    }
    issues
}
