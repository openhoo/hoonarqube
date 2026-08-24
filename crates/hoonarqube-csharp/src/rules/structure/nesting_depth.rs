use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, range_of, to_u32};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S134 — control-flow nesting stays within the configured
/// depth.
pub(crate) fn check(root: Node<'_>, language: CsLanguage, options: &AnalyzerOptions) -> Vec<Issue> {
    let mut issues = Vec::new();
    for construct in collect_kinds(root, &NESTING_CONSTRUCT_KINDS) {
        if is_error_tainted(construct) {
            continue;
        }
        let depth = ancestors_of(construct)
            .filter(|ancestor| NESTING_CONSTRUCT_KINDS.contains(&ancestor.kind()))
            .count();
        if to_u32(depth) > options.maximum_nesting_level {
            issues.push(issue(
                language,
                "S134",
                format!("Reduce this code's nesting depth ({depth} levels deep)."),
                range_of(construct),
            ));
        }
    }
    issues
}

/// Control-flow constructs counted by the S134 nesting-depth walk.
const NESTING_CONSTRUCT_KINDS: [&str; 12] = [
    "if_statement",
    "for_statement",
    "foreach_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "try_statement",
    "catch_clause",
    "finally_clause",
    "using_statement",
    "lock_statement",
    "fixed_statement",
];
