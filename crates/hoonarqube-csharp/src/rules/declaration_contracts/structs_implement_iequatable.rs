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
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3898_flags_value_types_missing_iequatable() {
        let report = analyze_default("struct Pair\n{\n    public int X;\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S3898").len(), 1);
    }

    #[test]
    fn s3898_accepts_direct_and_qualified_iequatable_bases() {
        let direct = analyze_default(
            "struct Pair : IEquatable<Pair>\n{\n    public bool Equals(Pair other) => true;\n}\n",
        );
        assert!(with_key(&direct, "csharpsquid:S3898").is_empty());

        let qualified = analyze_default(
            "struct Pair : System.IEquatable<Pair>\n{\n    public bool Equals(Pair other) => true;\n}\n",
        );
        assert!(with_key(&qualified, "csharpsquid:S3898").is_empty());
    }

    #[test]
    fn s3898_spares_reference_types_and_counts_each_struct() {
        let class_form = analyze_default("class Ref\n{\n    public int X;\n}\n");
        assert!(with_key(&class_form, "csharpsquid:S3898").is_empty());

        let two_structs = analyze_default("struct A\n{\n}\n\nstruct B\n{\n}\n");
        assert_eq!(with_key(&two_structs, "csharpsquid:S3898").len(), 2);
    }
}
