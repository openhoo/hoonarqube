use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::callee_name;
use crate::rules::structure::accessor_keyword;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2365 — getters that copy their collection allocate a
/// fresh list per read and mislead callers into thinking they own the
/// data. Bound: `get` accessors and expression-bodied properties.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for accessor in collect_kinds(root, &["accessor_declaration"]) {
        if accessor_keyword(accessor, source) != "get" || is_error_tainted(accessor) {
            continue;
        }
        for call in collect_kinds(accessor, &["invocation_expression"]) {
            if COLLECTION_COPY_METHODS.contains(&callee_name(call, source).unwrap_or("")) {
                issues.push(issue(
                    language,
                    "S2365",
                    "This getter copies the collection on every read; expose a read-only view instead.",
                    range_of(call, source),
                ));
            }
        }
    }
    issues
}

/// Copy-producing members that defeat shared references.
const COLLECTION_COPY_METHODS: [&str; 3] = ["ToList", "ToArray", "Clone"];
