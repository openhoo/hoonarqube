use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use crate::rules::literals::{argument_expression, literal_inner_text};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2115 — database connection strings must not select password
/// authentication without supplying a password.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation)
            || !matches!(
                callee_name(invocation, source),
                Some("UseSqlServer" | "UseSqlite" | "UseMySql" | "UseOracle")
            )
        {
            continue;
        }
        let insecure = invocation_arguments(invocation)
            .into_iter()
            .map(argument_expression)
            .filter(|argument| {
                matches!(
                    argument.kind(),
                    "string_literal" | "verbatim_string_literal" | "raw_string_literal"
                )
            })
            .any(|literal| has_empty_password(literal_inner_text(literal, source)));
        if insecure {
            issues.push(issue(
                language,
                "S2115",
                "Use a secure password when connecting to this database.",
                range_of(invocation, source),
            ));
        }
    }
    issues
}

fn has_empty_password(connection: &str) -> bool {
    let password = connection_property(connection, &["password", "pwd"]);
    let integrated =
        connection_property(connection, &["integrated security", "trusted_connection"])
            .is_some_and(|value| {
                value.eq_ignore_ascii_case("true")
                    || value.eq_ignore_ascii_case("yes")
                    || value.eq_ignore_ascii_case("sspi")
            });
    password.is_some_and(str::is_empty) && !integrated
}

/// Exact semicolon-delimited connection-string property, ignoring key case
/// and surrounding whitespace. Substrings such as `NotPassword` do not match.
fn connection_property<'a>(connection: &'a str, keys: &[&str]) -> Option<&'a str> {
    connection.split(';').find_map(|property| {
        let (key, value) = property.split_once('=')?;
        keys.iter()
            .any(|candidate| key.trim().eq_ignore_ascii_case(candidate))
            .then(|| value.trim())
    })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2115_flags_empty_password_in_database_configuration() {
        let report = analyze_default(
            "class A\n{\n    void M(DbContextOptionsBuilder options)\n    {\n        options.UseSqlServer(\"Server=s;User=u;Password=\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2115");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(
            flagged[0].message,
            "Use a secure password when connecting to this database."
        );
    }

    #[test]
    fn s2115_accepts_integrated_security_and_non_database_literals() {
        let report = analyze_default(
            "options.UseSqlServer(\"Server=s;Integrated Security=true;\");\nvar label = \"Password=\";\n",
        );
        assert!(with_key(&report, "csharpsquid:S2115").is_empty());
    }

    #[test]
    fn s2115_requires_integrated_security_to_be_enabled() {
        let report = analyze_default(
            "class A\n{\n    void M(DbContextOptionsBuilder options)\n    {\n        options.UseSqlServer(\"Server=s;Integrated Security=false;Password=\");\n        options.UseSqlServer(\"Server=s;Trusted_Connection=no;Pwd = ;\");\n        options.UseSqlServer(\"Server=s;Integrated Security=SSPI;Password=\");\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2115").len(), 2);
    }

    #[test]
    fn s2115_matches_exact_connection_properties_and_direct_arguments() {
        let report = analyze_default(
            "class A\n{\n    void M(DbContextOptionsBuilder options)\n    {\n        options.UseSqlServer(\"Server=s;NotPassword=\");\n        options.UseSqlServer(Build(\"Password=\"));\n        options.UseSqlServer(\"Server=s;Password = ;\");\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2115").len(), 1);
    }
}
