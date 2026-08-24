use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::structure::binary_operator;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2257 — cipher-named members containing raw XOR bit-mixing,
/// the canonical hand-rolled-cipher tell. Subset: method names matching
/// Encrypt/Decrypt/Crypt plus an XOR somewhere in the body.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const CIPHER_NAME_PARTS: [&str; 2] = ["Encrypt", "Decrypt"];
    collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| !is_error_tainted(*method))
        .filter(|method| {
            method.child_by_field_name("name").is_some_and(|name| {
                let text = node_text(name, source);
                CIPHER_NAME_PARTS.iter().any(|part| text.contains(part))
            })
        })
        .filter(|method| {
            collect_kinds(*method, &["binary_expression"])
                .into_iter()
                .any(|expression| binary_operator(expression, source) == "^")
        })
        .filter_map(|method| method.child_by_field_name("name"))
        .map(|name| {
            issue(
                language,
                "S2257",
                "Replace this hand-written cipher routine with a vetted library implementation.",
                range_of(name),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2257_ignores_sources_without_methods() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S2257").is_empty());
    }

    #[test]
    fn s2257_ignores_cipher_names_without_xor() {
        let report = analyze_default(
            "class Vault\n{\n    byte[] Encrypt(byte[] data)\n    {\n        return data;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2257").is_empty());
    }

    #[test]
    fn s2257_ignores_compound_xor_assignment() {
        let report = analyze_default(
            "class Crypto\n{\n    void Encrypt(int value)\n    {\n        value ^= 0x42;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2257").is_empty());
    }

    #[test]
    fn s2257_ignores_case_sensitive_name_matching() {
        let report =
            analyze_default("class Crypto\n{\n    int encryptbyte(int b) => b ^ 0xFF;\n}\n");
        assert!(with_key(&report, "csharpsquid:S2257").is_empty());
    }

    #[test]
    fn s2257_flags_decrypt_names_with_lambda_xor() {
        let report = analyze_default(
            "class Crypto\n{\n    byte[] Decrypt(byte[] data)\n    {\n        return data.Select(b => b ^ 0x20).ToArray();\n    }\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S2257");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }

    #[test]
    fn s2257_flags_each_cipher_method_at_its_own_line() {
        let report = analyze_default(
            "class Crypto\n{\n    int EncryptByte(int b) => b ^ 0xFF;\n\n    int DecryptByte(int b) => b ^ 0xAA;\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S2257");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 3);
        assert_eq!(found[1].range.start.line, 5);
    }
}
