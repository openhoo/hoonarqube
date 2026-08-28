use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, invocation_function};
use crate::rules::structure::{accessor_keyword, name_anchor};
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
            if callee_name(call, source) == Some("ToList") {
                let property = accessor.parent().and_then(|node| node.parent());
                let property_name = property
                    .map(name_anchor)
                    .map_or("property", |name| node_text(name, source));
                issues.push(issue(
                    language,
                    "S2365",
                    format!(
                        "Refactor '{property_name}' into a method, properties should not copy collections."
                    ),
                    range_of(invocation_function(call).unwrap_or(call), source),
                ));
            }
        }
    }
    issues
}
