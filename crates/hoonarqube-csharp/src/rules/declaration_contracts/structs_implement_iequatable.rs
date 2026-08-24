use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3898 — value types compare by value; `IEquatable<T>` avoids
/// boxing in every comparison.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for struct_declaration in collect_kinds(root, &["struct_declaration"]) {
        if is_error_tainted(struct_declaration) {
            continue;
        }
        let implements = base_simple_names(struct_declaration, source)
            .iter()
            .any(|base| base.starts_with("IEquatable"));
        if !implements {
            issues.push(issue(
                language,
                "S3898",
                "Implement 'IEquatable<T>' on this value type.",
                range_of(name_anchor(struct_declaration)),
            ));
        }
    }
    issues
}
