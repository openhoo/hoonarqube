use super::support::WriteKind;
use super::support::callable_blocks;
use super::support::identifier_write;
use super::support::walk_except_blocks;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{
    binary_operands, block_statements, callee_name, expression_name, first_named_child,
    invocation_arguments, operator_of,
};
use crate::rules::literals::declarator_initializer;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2077 — dynamically formatted SQL invites injection.
/// Bound: straight-line taint inside each block — locals composed by
/// interpolation or concatenation flow into execute calls, command
/// constructors, and `CommandText` assignments. Taint through fields,
/// parameters, or across branches counts as dynamic on arrival.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        for block in collect_kinds(body, &["block"]) {
            let mut tainted = std::collections::HashSet::new();
            let mut clean = std::collections::HashSet::new();
            for statement in block_statements(block) {
                scan_sql_usages(statement, source, language, &tainted, &clean, &mut issues);
                update_sql_taint(statement, source, &mut tainted, &mut clean);
            }
        }
    }
    issues
}

/// Methods that execute a command's SQL text directly.
const SQL_EXECUTE_METHODS: [&str; 4] = [
    "ExecuteReader",
    "ExecuteNonQuery",
    "ExecuteScalar",
    "ExecuteXmlReader",
];

/// Command types whose constructor takes the SQL text as first argument.
const SQL_COMMAND_TYPES: [&str; 6] = [
    "SqlCommand",
    "OleDbCommand",
    "OdbcCommand",
    "MySqlCommand",
    "SqliteCommand",
    "NpgsqlCommand",
];

/// Whether an expression builds its text from non-literal parts:
/// string interpolation, a concatenation with such a part, or an
/// identifier that is not a provably literal-only local. Unknown
/// provenance (parameters, fields) counts as dynamic — the rule is
/// deliberately one-sided.
fn is_dynamic_sql_text(
    expression: Node<'_>,
    source: &str,
    tainted: &std::collections::HashSet<String>,
    clean: &std::collections::HashSet<String>,
) -> bool {
    match expression.kind() {
        "string_literal" => false,
        "interpolated_string_expression" => collect_kinds(expression, &["interpolation"])
            .iter()
            .any(|part| !is_error_tainted(*part)),
        "binary_expression" if operator_of(expression) == Some("+") => binary_operands(expression)
            .is_some_and(|(left, right)| {
                is_dynamic_sql_text(left, source, tainted, clean)
                    || is_dynamic_sql_text(right, source, tainted, clean)
            }),
        // `invocation_arguments` yields `argument` wrappers around the
        // actual expressions; unwrap them here.
        "argument" => first_named_child(expression)
            .is_some_and(|inner| is_dynamic_sql_text(inner, source, tainted, clean)),
        "identifier" => {
            let name = node_text(expression, source);
            tainted.contains(name) || !clean.contains(name)
        }
        _ => true,
    }
}

/// Reports SQL-executing sites inside one statement whose command text
/// is dynamic: execute calls and command constructors with a tainted or
/// interpolated first argument, plus dynamic `CommandText` assignments.
fn scan_sql_usages<'t>(
    statement: Node<'t>,
    source: &str,
    language: CsLanguage,
    tainted: &std::collections::HashSet<String>,
    clean: &std::collections::HashSet<String>,
    issues: &mut Vec<Issue>,
) {
    let mut report = |anchor: Node<'t>| {
        issues.push(issue(
            language,
            "S2077",
            "Use a parameterized query or stored procedure for this SQL statement.",
            range_of(anchor, source),
        ));
    };
    walk_except_blocks(statement, &mut |node| match node.kind() {
        "invocation_expression" => {
            let dynamic = invocation_arguments(node)
                .first()
                .is_some_and(|argument| is_dynamic_sql_text(*argument, source, tainted, clean));
            if dynamic && SQL_EXECUTE_METHODS.contains(&callee_name(node, source).unwrap_or("")) {
                report(node);
            }
        }
        "object_creation_expression" => {
            let type_name = node
                .child_by_field_name("type")
                .map_or("", |type_node| simple_name(node_text(type_node, source)));
            let dynamic = invocation_arguments(node)
                .first()
                .is_some_and(|argument| is_dynamic_sql_text(*argument, source, tainted, clean));
            if dynamic && SQL_COMMAND_TYPES.contains(&type_name) {
                report(node);
            }
        }
        "assignment_expression" => {
            let targets_command_text = operator_of(node) == Some("=")
                && node.child_by_field_name("left").is_some_and(|left| {
                    expression_name(left, source) == Some("CommandText")
                        && left.kind() == "member_access_expression"
                });
            let dynamic = node
                .child_by_field_name("right")
                .is_some_and(|right| is_dynamic_sql_text(right, source, tainted, clean));
            if targets_command_text && dynamic {
                report(node);
            }
        }
        _ => {}
    });
}

/// Updates the per-block taint sets with one statement's stores: a
/// store of dynamic text taints the name; any other store marks it
/// provably literal-only.
fn update_sql_taint(
    statement: Node<'_>,
    source: &str,
    tainted: &mut std::collections::HashSet<String>,
    clean: &mut std::collections::HashSet<String>,
) {
    for identifier in collect_kinds(statement, &["identifier"]) {
        let Some(write) = identifier_write(identifier) else {
            continue;
        };
        let name = node_text(identifier, source).to_owned();
        let stores_dynamic = match write {
            WriteKind::Increment => false,
            WriteKind::Store => identifier.parent().is_some_and(|parent| {
                parent
                    .child_by_field_name("right")
                    .is_some_and(|right| is_dynamic_sql_text(right, source, tainted, clean))
                    || declarator_initializer(parent, identifier)
                        .is_some_and(|value| is_dynamic_sql_text(value, source, tainted, clean))
            }),
        };
        if stores_dynamic {
            tainted.insert(name.clone());
            clean.remove(&name);
        } else {
            clean.insert(name.clone());
            tainted.remove(&name);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S2077";

    #[test]
    fn s2077_minimal_empty_body_is_clean() {
        let report = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2077_interpolated_text_into_execute_reader_flags() {
        let report = analyze_default(
            "class C {\n    void M(string table) {\n        var sql = $\"SELECT * FROM {table}\";\n        cmd.ExecuteReader(sql);\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 4);
    }

    #[test]
    fn s2077_concatenated_text_into_command_constructor_flags() {
        let report = analyze_default(
            "class C {\n    void M(string user) {\n        var c = new SqlCommand(\"SELECT \" + user);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, KEY).len(), 1);
    }

    #[test]
    fn s2077_literal_only_local_stays_clean() {
        let report = analyze_default(
            "class C {\n    void M() {\n        var sql = \"SELECT COUNT(*) FROM users\";\n        cmd.ExecuteScalar(sql);\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2077_parameter_provenance_counts_as_dynamic() {
        let report = analyze_default(
            "class C {\n    void M(string filter) {\n        cmd.ExecuteNonQuery(filter);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, KEY).len(), 1);
    }

    #[test]
    fn s2077_dynamic_command_text_assignment_flags() {
        let report = analyze_default(
            "class C {\n    void M(string name) {\n        c.CommandText = $\"DELETE FROM t WHERE n = {name}\";\n    }\n}\n",
        );
        assert_eq!(with_key(&report, KEY).len(), 1);
    }

    #[test]
    fn s2077_non_sql_callee_with_interpolation_is_ignored() {
        let report = analyze_default(
            "class C {\n    void M(string name) {\n        Log($\"hello {name}\");\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }
}
