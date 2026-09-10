use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2257 — custom `HashAlgorithm` implementations require
/// review.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class| !is_error_tainted(*class))
        .filter(|class| has_hash_algorithm_base(*class, source))
        .filter_map(|class| class.child_by_field_name("name"))
        .map(|name| {
            issue(
                language,
                "S2257",
                "Use a standard cryptographic algorithm.",
                range_of(name, source),
            )
        })
        .collect()
}

fn has_hash_algorithm_base(class: Node<'_>, source: &str) -> bool {
    let mut class_cursor = class.walk();
    class
        .children(&mut class_cursor)
        .filter(|child| child.kind() == "base_list")
        .any(|base_list| {
            let mut base_cursor = base_list.walk();
            base_list.named_children(&mut base_cursor).any(|base| {
                matches!(
                    node_text(base, source).trim(),
                    "HashAlgorithm"
                        | "System.Security.Cryptography.HashAlgorithm"
                        | "global::System.Security.Cryptography.HashAlgorithm"
                )
            })
        })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2257_flags_hash_algorithm_subclasses() {
        let report = analyze_default(
            "using System;\nusing System.Security.Cryptography;\n\npublic sealed class CustomDigest : HashAlgorithm\n{\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S2257");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].message, "Use a standard cryptographic algorithm.");
        assert_eq!(found[0].range.start.line, 4);
        assert_eq!(found[0].range.start.column, 20);
    }

    #[test]
    fn s2257_ignores_standard_algorithms_and_unrelated_classes() {
        let report = analyze_default(
            "using System.Security.Cryptography;\nclass Cipher\n{\n    HashAlgorithm Make() => HashAlgorithm.Create(\"SHA256\");\n    AesGcm Encrypt(byte[] key) => new AesGcm(key);\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2257").is_empty());
    }

    #[test]
    fn s2257_ignores_sources_without_hash_algorithm_bases() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S2257").is_empty());
    }
}
