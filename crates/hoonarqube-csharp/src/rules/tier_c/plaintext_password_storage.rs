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
                "Store passwords with a slow, salted hash such as PBKDF2 or bcrypt; do not handle them as plain bytes or fast hashes.",
                range_of(hash),
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
                    "Store passwords with a slow, salted hash such as PBKDF2 or bcrypt; do not handle them as plain bytes or fast hashes.",
                    range_of(call),
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
