use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, range_of, to_u32};
use crate::rules::structure::is_callable_scope;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S134 — control-flow nesting stays within the configured
/// depth.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for construct in collect_kinds(root, &NESTING_CONSTRUCT_KINDS) {
        if is_error_tainted(construct) {
            continue;
        }
        let depth = ancestors_of(construct)
            .take_while(|ancestor| !is_callable_scope(ancestor.kind()))
            .filter(|ancestor| NESTING_CONSTRUCT_KINDS.contains(&ancestor.kind()))
            .count();
        if to_u32(depth) == options.maximum_nesting_level {
            let keyword = match construct.kind() {
                "if_statement" => "if",
                "for_statement" => "for",
                "foreach_statement" => "foreach",
                "while_statement" => "while",
                "do_statement" => "do",
                "switch_statement" => "switch",
                "try_statement" => "try",
                "catch_clause" => "catch",
                "finally_clause" => "finally",
                "using_statement" => "using",
                "lock_statement" => "lock",
                "fixed_statement" => "fixed",
                _ => construct.kind(),
            };
            let mut cursor = construct.walk();
            let anchor = construct
                .children(&mut cursor)
                .find(|child| child.kind() == keyword)
                .unwrap_or(construct);
            issues.push(issue(
                language,
                "S134",
                format!(
                    "Refactor this code to not nest more than {} control flow statements.",
                    options.maximum_nesting_level
                ),
                range_of(anchor, source),
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

#[cfg(test)]
mod tests {
    use crate::AnalyzerOptions;
    use crate::tests::{analyze_options, with_key};

    #[test]
    fn s134_resets_nesting_inside_local_callable_scopes() {
        let source = "class C\n{\n    void M(bool outer, bool inner)\n    {\n        if (outer)\n        {\n            void Local()\n            {\n                if (inner) { }\n            }\n        }\n    }\n}\n";
        let options = AnalyzerOptions {
            maximum_nesting_level: 1,
            ..Default::default()
        };
        assert!(with_key(&analyze_options(source, &options), "csharpsquid:S134").is_empty());
    }
}
