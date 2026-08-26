use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::creation_type_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| simple_name(creation_type_text(*creation, source)).ends_with("Random"))
        .filter(|creation| security_context_hit(*creation, source))
        .map(|creation| {
            issue(
                language,
                "S2245",
                "Use a cryptographically secure random number generator for this security-sensitive value.",
                range_of(creation, source),
            )
        })
        .collect()
}

/// csharpsquid:S2245 — `System.Random` created inside a security-named
/// context (token/password/secret/nonce/salt/csrf naming heuristic over the
/// enclosing member, type, or assigned variable).
const SECURITY_CONTEXT_WORDS: [&str; 6] =
    ["token", "password", "passwd", "secret", "nonce", "csrf"];

/// Whether a candidate context name carries a security word.
fn security_named(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SECURITY_CONTEXT_WORDS
        .iter()
        .any(|word| lower.contains(word))
}

/// Any enclosing declaration or assigned-variable name carrying a security
/// word around the given expression.
fn security_context_hit(expression: Node<'_>, source: &str) -> bool {
    let mut context_names: Vec<&str> = Vec::new();
    let mut ancestor = expression.parent();
    while let Some(current) = ancestor {
        if matches!(
            current.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "class_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "interface_declaration"
                | "variable_declarator"
        ) && let Some(name) = current.child_by_field_name("name")
        {
            context_names.push(node_text(name, source));
        }
        ancestor = current.parent();
    }
    context_names.iter().any(|name| security_named(name))
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2245_minimal_class_without_random_creations_stays_silent() {
        let report = analyze_default(
            "class Vault\n{\n    void Rotate()\n    {\n        var seed = 1234;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2245").is_empty());
    }

    #[test]
    fn s2245_flags_creation_inside_security_named_method() {
        let report = analyze_default(
            "class Vault\n{\n    void IssueToken()\n    {\n        var rng = new Random();\n        rng.Next();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2245");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s2245_matches_every_security_word_case_insensitively() {
        for method in [
            "    void ResetPasswd()\n    {\n        var rng = new Random();\n    }\n",
            "    byte[] BuildNonce()\n    {\n        var rng = new Random();\n    }\n",
            "    bool ValidateCsrf(string header)\n    {\n        var rng = new Random();\n    }\n",
            "    string GENERATESECRET()\n    {\n        var rng = new Random();\n    }\n",
        ] {
            let report = analyze_default(&format!("class Auth\n{{\n{method}}}\n"));
            assert_eq!(with_key(&report, "csharpsquid:S2245").len(), 1);
        }
    }

    #[test]
    fn s2245_flags_qualified_system_random_via_security_variable_name() {
        let report = analyze_default(
            "class Vault\n{\n    void Roll()\n    {\n        var token = new System.Random();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2245");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s2245_flags_password_named_field_initializer_in_plain_class() {
        let report = analyze_default(
            "class Store\n{\n    private readonly Random passwordGenerator = new Random();\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2245");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s2245_ignores_security_words_outside_the_creation_ancestry() {
        let report = analyze_default(
            "class Vault\n{\n    void SetPassword(string value)\n    {\n    }\n\n    void Roll()\n    {\n        var rng = new Random();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2245").is_empty());
    }

    #[test]
    fn s2245_reports_each_security_context_creation_at_its_own_line() {
        let report = analyze_default(
            "class Store\n{\n    string GenerateSecret()\n    {\n        var a = new Random();\n        var b = new Random();\n        return a.Next().ToString();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2245");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s2245_substring_context_names_count() {
        let report = analyze_default(
            "class Lexer\n{\n    void TokenizeInput()\n    {\n        var rng = new Random();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2245");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }
}
