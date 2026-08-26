use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments, invocation_receiver};
use crate::rules::literals::{argument_expression, literal_inner_text};
use crate::rules::security::identifier_usages;
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        let identifiers = collect_kinds(method, &["identifier"]);
        if !identifiers
            .iter()
            .any(|identifier| password_named(node_text(*identifier, source)))
        {
            continue;
        }
        let uses_slow_kdf = identifiers
            .iter()
            .any(|identifier| SLOW_KDF_NAMES.contains(&node_text(*identifier, source)));
        for hash in identifier_usages(method, source, &FAST_HASH_TYPES) {
            issues.push(issue(
                language,
                "S5344",
                "Do not hash passwords with this fast hash; store them under a slow, salted KDF such as PBKDF2 or bcrypt instead.",
                range_of(hash, source),
            ));
        }
        if uses_slow_kdf {
            continue;
        }
        for call in collect_kinds(method, &["invocation_expression"]) {
            if !is_error_tainted(call) && password_bytes_conversion(call, source) {
                issues.push(issue(
                    language,
                    "S5344",
                    "Do not convert password material into plain bytes; store only its slow, salted hash such as PBKDF2 or bcrypt.",
                    range_of(call, source),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S5344 — passwords stored as plaintext bytes or under fast
/// hashes. Subset: within one method that mentions a password-named
/// identifier, flag fast-hash type usage and UTF8/ASCII `GetBytes` over the
/// password material — unless a proper KDF (Rfc2898DeriveBytes/Pbkdf2/
/// BCrypt/Argon2/...) is present in the same method.
const FAST_HASH_TYPES: [&str; 9] = [
    "MD5",
    "HMACMD5",
    "MD5CryptoServiceProvider",
    "MD5Cng",
    "SHA1",
    "HMACSHA1",
    "SHA1CryptoServiceProvider",
    "SHA1Cng",
    "SHA1Managed",
];

const SLOW_KDF_NAMES: [&str; 7] = [
    "Rfc2898DeriveBytes",
    "Pbkdf2",
    "PBKDF2",
    "BCrypt",
    "Argon2",
    "SCrypt",
    "KeyDerivation",
];

const PASSWORD_NAME_PARTS: [&str; 3] = ["password", "passwd", "pwd"];

/// Whether an identifier or literal carries password material naming.
fn password_named(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    PASSWORD_NAME_PARTS.iter().any(|part| lower.contains(part))
}

/// A UTF8/ASCII `GetBytes` call over password-named material, if any.
fn password_bytes_conversion(call: Node<'_>, source: &str) -> bool {
    if callee_name(call, source) != Some("GetBytes") {
        return false;
    }
    let Some(receiver) = invocation_receiver(call) else {
        return false;
    };
    let receiver_text = node_text(receiver, source).to_ascii_lowercase();
    if !(receiver_text.contains("utf8") || receiver_text.contains("ascii")) {
        return false;
    }
    let Some(argument) = invocation_arguments(call).into_iter().next() else {
        return false;
    };
    let expression = argument_expression(argument);
    match expression.kind() {
        "identifier" => password_named(node_text(expression, source)),
        "string_literal" => password_named(literal_inner_text(expression, source)),
        _ => false,
    }
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s5344_method_without_password_identifiers_stays_silent() {
        let report = analyze_default(
            "class Repo\n{\n    byte[] Encode(string payload)\n    {\n        return Encoding.UTF8.GetBytes(payload);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S5344").is_empty());
    }

    #[test]
    fn s5344_flags_ascii_getbytes_over_password_material() {
        let report = analyze_default(
            "class Repo\n{\n    byte[] Encode(string pwd)\n    {\n        return Encoding.ASCII.GetBytes(pwd);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S5344");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s5344_flags_utf8_getbytes_over_password_named_literal() {
        let report = analyze_default(
            "class Repo\n{\n    byte[] Encode(string pwd)\n    {\n        return Encoding.UTF8.GetBytes(\"Hunter2Password\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S5344");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s5344_fast_hash_is_reported_even_when_a_slow_kdf_suppresses_conversions() {
        let report = analyze_default(
            "class Kdf\n{\n    byte[] Derive(string password)\n    {\n        var bytes = Encoding.UTF8.GetBytes(password);\n        var kdf = new Rfc2898DeriveBytes(password, salt);\n        var md5 = MD5.Create();\n        return md5.ComputeHash(bytes);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S5344");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s5344_other_encodings_do_not_count_as_plaintext_conversion() {
        let report = analyze_default(
            "class Repo\n{\n    byte[] Encode(string password)\n    {\n        return Encoding.BigEndianUnicode.GetBytes(password);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S5344").is_empty());
    }

    #[test]
    fn s5344_non_getbytes_callees_stay_silent_despite_password_gate() {
        let report = analyze_default(
            "class Repo\n{\n    string Decode(byte[] pwd)\n    {\n        return Encoding.UTF8.GetString(pwd);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S5344").is_empty());
    }

    #[test]
    fn s5344_reports_each_fast_hash_and_the_byte_conversion_in_document_order() {
        let report = analyze_default(
            "class Hasher\n{\n    byte[] Weak(string password)\n    {\n        var sha1 = SHA1.Create();\n        var hmac = HMACMD5.Create();\n        return sha1.ComputeHash(Encoding.UTF8.GetBytes(password));\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S5344");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
        assert_eq!(flagged[2].range.start.line, 7);
    }
}
