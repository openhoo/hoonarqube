use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{
    callee_name, invocation_arguments, invocation_receiver, resolved_identifier_type,
};
use crate::rules::literals::{argument_expression, literal_inner_text};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2115 — database connection strings must not select password
/// authentication without supplying a password.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation) || !is_database_configuration_call(root, invocation, source)
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

fn is_database_configuration_call(root: Node<'_>, invocation: Node<'_>, source: &str) -> bool {
    match callee_name(invocation, source) {
        Some("UseSqlServer" | "UseSqlite" | "UseMySql" | "UseOracle") => true,
        Some("UseNpgsql") => invocation_receiver(invocation)
            .is_some_and(|receiver| is_ef_options_builder(root, receiver, source)),
        _ => false,
    }
}

fn is_ef_options_builder(root: Node<'_>, receiver: Node<'_>, source: &str) -> bool {
    let receiver_text = node_text(receiver, source).trim();
    let direct_creation = receiver_text
        .strip_prefix("new ")
        .and_then(|rest| rest.split(['(', '{']).next())
        .is_some_and(|type_text| simple_name(type_text.trim()) == "DbContextOptionsBuilder");
    let resolved = resolved_identifier_type(receiver, source)
        .is_some_and(|type_text| simple_name(type_text) == "DbContextOptionsBuilder");
    (direct_creation || resolved) && !has_local_type(root, "DbContextOptionsBuilder", source)
}

fn has_local_type(root: Node<'_>, wanted: &str, source: &str) -> bool {
    collect_kinds(
        root,
        &[
            "class_declaration",
            "struct_declaration",
            "record_declaration",
            "interface_declaration",
            "enum_declaration",
        ],
    )
    .into_iter()
    .filter_map(|declaration| declaration.child_by_field_name("name"))
    .any(|name| simple_name(node_text(name, source)) == wanted)
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
    #[test]
    fn s2115_flags_empty_password_in_ef_npgsql_configuration() {
        let report = analyze_default(
            "using Microsoft.EntityFrameworkCore;\n\npublic static class DatabaseConnection\n{\n    public static DbContextOptionsBuilder Create()\n        => new DbContextOptionsBuilder()\n            .UseNpgsql(\"Host=db.internal;Username=app;Password=\");\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2115");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
        assert_eq!(flagged[0].range.end.line, 7);
        assert_eq!(
            flagged[0].message,
            "Use a secure password when connecting to this database."
        );
    }

    #[test]
    fn s2115_keeps_npgsql_environment_and_alias_inputs_clean() {
        let report = analyze_default(
            "using System;\nusing Microsoft.EntityFrameworkCore;\n\npublic static class DatabaseConnectionAlias\n{\n    public static DbContextOptionsBuilder Create()\n    {\n        var connectionString = Environment.GetEnvironmentVariable(\"DB_CONNECTION\")\n            ?? throw new InvalidOperationException(\"DB_CONNECTION is required\");\n        return Build(connectionString);\n    }\n\n    private static DbContextOptionsBuilder Build(string connectionString)\n        => new DbContextOptionsBuilder().UseNpgsql(connectionString);\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2115").is_empty());
    }
}
