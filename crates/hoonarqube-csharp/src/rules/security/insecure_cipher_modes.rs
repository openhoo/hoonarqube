use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, creation_type_text};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

const MESSAGE: &str = "Use secure mode and padding scheme.";

/// csharpsquid:S5542 — insecure symmetric mode/padding configurations and
/// PKCS#1 v1.5 RSA encryption.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();

    for creation in collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
    {
        let creation_type = creation_type_text(creation, source);
        let text = node_text(creation, source);
        let symmetric_cipher = creation_type.ends_with("AesManaged")
            || creation_type.ends_with("AesCryptoServiceProvider")
            || creation_type.ends_with("TripleDESCryptoServiceProvider")
            || creation_type.ends_with("DESCryptoServiceProvider");
        let insecure_setting = [
            "CipherMode.ECB",
            "CipherMode.CFB",
            "CipherMode.OFB",
            "PaddingMode.None",
            "PaddingMode.Zeros",
        ]
        .iter()
        .any(|setting| text.contains(setting));
        if symmetric_cipher && insecure_setting {
            issues.push(issue(
                language,
                "S5542",
                MESSAGE,
                range_of(creation, source),
            ));
        }
    }

    for invocation in collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
    {
        if callee_name(invocation, source) != Some("Encrypt")
            || !node_text(invocation, source).trim_end().ends_with("false)")
        {
            continue;
        }
        let rsa_context = ancestors_of(invocation)
            .find(|ancestor| ancestor.kind() == "method_declaration")
            .is_some_and(|method| node_text(method, source).contains("RSACryptoServiceProvider"));
        if rsa_context {
            issues.push(issue(
                language,
                "S5542",
                MESSAGE,
                range_of(invocation, source),
            ));
        }
    }

    issues
}
