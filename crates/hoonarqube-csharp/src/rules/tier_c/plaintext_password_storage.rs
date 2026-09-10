use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::integer_literal_value;
use crate::rules::literals::argument_nodes;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5344 — PBKDF2 needs at least 100,000 iterations. The legacy
/// two-argument overload also inherits a weak digest default.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            creation
                .child_by_field_name("type")
                .is_some_and(|type_node| is_rfc2898_type(node_text(type_node, source)))
        })
        .filter_map(|creation| {
            let arguments = creation
                .child_by_field_name("arguments")
                .map(argument_nodes)
                .unwrap_or_default();
            if arguments.len() < 4 {
                return Some(issue(
                    language,
                    "S5344",
                    "Use at least 100,000 iterations and a state-of-the-art digest algorithm here.",
                    range_of(creation, source),
                ));
            }
            let iterations = arguments
                .get(2)
                .map(|argument| actual_argument_expression(*argument))?;
            let value = integer_literal_value(node_text(iterations, source))?;
            (value < 100_000).then(|| {
                issue(
                    language,
                    "S5344",
                    "Use at least 100,000 iterations here.",
                    range_of(iterations, source),
                )
            })
        })
        .collect()
}

fn actual_argument_expression(argument: Node<'_>) -> Node<'_> {
    let mut cursor = argument.walk();
    argument
        .named_children(&mut cursor)
        .last()
        .unwrap_or(argument)
}

fn is_rfc2898_type(type_text: &str) -> bool {
    matches!(
        type_text.trim(),
        "Rfc2898DeriveBytes"
            | "System.Security.Cryptography.Rfc2898DeriveBytes"
            | "global::System.Security.Cryptography.Rfc2898DeriveBytes"
    )
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s5344_flags_weak_pbkdf2_defaults_iterations_and_digest() {
        let report = analyze_default(
            "class Kdf\n{\n    void M(string password, byte[] salt)\n    {\n        var a = new Rfc2898DeriveBytes(password, salt);\n        var b = new Rfc2898DeriveBytes(password, salt, 10_000, HashAlgorithmName.SHA256);\n        var c = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA1);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S5344");
        assert_eq!(flagged.len(), 2);
        assert_eq!(
            flagged[0].message,
            "Use at least 100,000 iterations and a state-of-the-art digest algorithm here."
        );
        assert_eq!(flagged[0].range.start.column, 16);
        assert_eq!(flagged[1].message, "Use at least 100,000 iterations here.");
        assert_eq!(flagged[1].range.start.column, 55);
    }

    #[test]
    fn s5344_accepts_strong_pbkdf2_configuration_and_unrelated_hashes() {
        let report = analyze_default(
            "class Kdf\n{\n    void M(string password, byte[] salt)\n    {\n        var kdf = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);\n        var sha = SHA1.Create();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S5344").is_empty());
    }
    #[test]
    fn s5344_does_not_guess_at_nonliteral_iteration_values() {
        let report = analyze_default(
            "using System.Security.Cryptography;\npublic static class PasswordHasherAlias\n{\n    public static byte[] Hash(string password, byte[] salt)\n        => Derive(password, salt, 100_000);\n\n    private static byte[] Derive(string password, byte[] salt, int iterations)\n    {\n        using var kdf = new Rfc2898DeriveBytes(\n            password, salt, iterations, HashAlgorithmName.SHA256);\n        return kdf.GetBytes(32);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S5344").is_empty());
    }
    #[test]
    fn s5344_uses_the_direct_constructor_argument_order() {
        let report = analyze_default(
            "class Kdf\n{\n    void M(string password, byte[] salt)\n    {\n        var kdf = new Rfc2898DeriveBytes(Read(password), salt, 10_000, HashAlgorithmName.SHA256);\n    }\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S5344");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.column, 63);
    }
}
