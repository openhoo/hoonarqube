use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::integer_literal_value;
use crate::rules::literals::argument_expression;
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
                .is_some_and(|type_node| {
                    simple_name(node_text(type_node, source)) == "Rfc2898DeriveBytes"
                })
        })
        .filter_map(|creation| {
            let arguments = collect_kinds(creation, &["argument"]);
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
                .map(|argument| argument_expression(*argument));
            let value =
                iterations.and_then(|value| integer_literal_value(node_text(value, source)));
            value.is_none_or(|value| value < 100_000).then(|| {
                issue(
                    language,
                    "S5344",
                    "Use at least 100,000 iterations here.",
                    range_of(iterations.unwrap_or(creation), source),
                )
            })
        })
        .collect()
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
}
