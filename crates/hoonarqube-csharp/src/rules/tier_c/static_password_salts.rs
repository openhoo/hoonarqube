use super::support::is_static_literal;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, simple_name};
use crate::rules::expressions::{callee_name, creation_type_text, invocation_arguments};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    salted_hash_candidates(root, source)
        .into_iter()
        .filter(|candidate| invocation_arguments(*candidate).len() >= 2)
        .filter(|candidate| {
            invocation_arguments(*candidate)
                .into_iter()
                .skip(1)
                .any(|argument| is_static_literal(argument_expression(argument), source))
        })
        .map(|candidate| {
            issue(
                language,
                "S2053",
                "Use a random, unpredictable salt for this password hashing call.",
                range_of(candidate, source),
            )
        })
        .collect()
}

/// csharpsquid:S2053 — password hashing invoked with a compile-time constant
/// salt. Subset: `Rfc2898DeriveBytes` construction, `Rfc2898DeriveBytes.
/// Pbkdf2`, and any `HashPassword/Pbkdf2/PBKDF2` call whose second argument
/// is a static literal; salts computed at runtime stay untouched.
const SALT_TAKING_HASH_APIS: [&str; 3] = ["HashPassword", "Pbkdf2", "PBKDF2"];

fn salted_hash_candidates<'t>(root: Node<'t>, source: &str) -> Vec<Node<'t>> {
    let creations = collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| {
            simple_name(creation_type_text(*creation, source)) == "Rfc2898DeriveBytes"
        });
    let calls = collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| {
            callee_name(*call, source).is_some_and(|callee| SALT_TAKING_HASH_APIS.contains(&callee))
        });
    creations
        .chain(calls)
        .filter(|candidate| !is_error_tainted(*candidate))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2053_minimal_input_emits_nothing() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S2053").is_empty());
    }

    #[test]
    fn s2053_boundary_single_argument_creation_is_not_flagged() {
        let report = analyze_default(
            "byte[] Derive(byte[] password)\n{\n    var derive = new Rfc2898DeriveBytes(password);\n    return derive.GetBytes(16);\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2053").is_empty());
    }

    #[test]
    fn s2053_boundary_literal_only_as_first_argument_is_not_flagged() {
        let report = analyze_default(
            "byte[] Load()\n{\n    byte[] hash = HashPassword(\"admin\", storedSalt);\n    return hash;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2053").is_empty());
    }

    #[test]
    fn s2053_flags_pbkdf2_uppercase_call_with_static_salt() {
        let report = analyze_default(
            "byte[] Derive(byte[] password)\n{\n    var derived = PBKDF2(password, \"static-pepper\", 1000, 32);\n    return derived;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2053");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s2053_runtime_generated_salt_control_stays_clean() {
        let report = analyze_default(
            "byte[] Derive(byte[] password)\n{\n    byte[] salt = RandomNumberGenerator.GetBytes(16);\n    int iterations = 100000;\n    var derive = new Rfc2898DeriveBytes(password, salt, iterations);\n    return derive.GetBytes(32);\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2053").is_empty());
    }

    #[test]
    fn s2053_flags_two_static_salts_on_distinct_lines() {
        let report = analyze_default(
            "class Users\n{\n    void Store(string password)\n    {\n        var first = HashPassword(password, \"pepper\");\n        var second = HashPassword(first, \"salt\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2053");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }
}
