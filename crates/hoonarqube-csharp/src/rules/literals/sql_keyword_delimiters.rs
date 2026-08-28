use super::support::{literal_inner_text, string_literals};
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use crate::rules::expressions::operator_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2857 — adjacent SQL query fragments need whitespace at their
/// concatenation boundary.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    if !has_sql_context(source) {
        return Vec::new();
    }

    let mut issues = Vec::new();
    for concatenation in collect_kinds(root, &["binary_expression"])
        .into_iter()
        .filter(|expression| operator_of(*expression) == Some("+"))
        .filter(|expression| {
            expression.parent().is_none_or(|parent| {
                parent.kind() != "binary_expression" || operator_of(parent) != Some("+")
            })
        })
    {
        let mut literals = string_literals(concatenation);
        literals.sort_by_key(tree_sitter::Node::start_byte);
        if literals.len() < 2 || !starts_sql_query(literal_inner_text(literals[0], source)) {
            continue;
        }
        for pair in literals.windows(2) {
            let left = literal_inner_text(pair[0], source);
            let right = literal_inner_text(pair[1], source);
            let missing_boundary_space = left
                .chars()
                .next_back()
                .is_some_and(|character| !character.is_whitespace())
                && right
                    .chars()
                    .next()
                    .is_some_and(|character| !character.is_whitespace());
            let Some(keyword) = leading_sql_keyword(right) else {
                continue;
            };
            if missing_boundary_space {
                issues.push(issue(
                    language,
                    "S2857",
                    format!("Add a space before '{keyword}'."),
                    range_of(pair[1], source),
                ));
            }
        }
    }
    issues
}

fn has_sql_context(source: &str) -> bool {
    const SQL_CONTEXTS: [&str; 9] = [
        "SqlClient",
        "EntityFrameworkCore",
        "OrmLite",
        "SQLite",
        "SqlServerCe",
        "Odbc",
        "OracleClient",
        "SqlCommand",
        "DbContext",
    ];
    SQL_CONTEXTS.iter().any(|context| source.contains(context))
}

fn starts_sql_query(text: &str) -> bool {
    ["SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "WITH"]
        .iter()
        .any(|keyword| starts_with_keyword(text, keyword))
}

fn leading_sql_keyword(text: &str) -> Option<&'static str> {
    const BOUNDARY_KEYWORDS: [&str; 15] = [
        "FROM", "WHERE", "JOIN", "INNER", "LEFT", "RIGHT", "FULL", "GROUP", "ORDER", "HAVING",
        "UNION", "VALUES", "SET", "ON", "LIMIT",
    ];
    BOUNDARY_KEYWORDS
        .iter()
        .find(|keyword| starts_with_keyword(text, keyword))
        .copied()
}

fn starts_with_keyword(text: &str, keyword: &str) -> bool {
    let Some(prefix) = text.get(..keyword.len()) else {
        return false;
    };
    prefix.eq_ignore_ascii_case(keyword)
        && text
            .as_bytes()
            .get(keyword.len())
            .is_none_or(|next| !next.is_ascii_alphanumeric() && *next != b'_')
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2857_reports_each_missing_sql_fragment_boundary() {
        let report = analyze_default(
            "using System.Data.SqlClient;\nclass C\n{\n    string Q() => \"SELECT p.Name\" +\n        \"FROM Person p\" +\n        \"WHERE p.Id = 1\";\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2857");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[0].message, "Add a space before 'FROM'.");
        assert_eq!(flagged[1].message, "Add a space before 'WHERE'.");
    }

    #[test]
    fn s2857_accepts_spaced_boundaries_and_non_sql_contexts() {
        let spaced = analyze_default(
            "using System.Data.SqlClient;\nvar q = \"SELECT p.Name \" + \"FROM Person p\";\n",
        );
        assert!(with_key(&spaced, "csharpsquid:S2857").is_empty());

        let unrelated = analyze_default("var q = \"SELECT p.Name\" + \"FROM Person p\";\n");
        assert!(with_key(&unrelated, "csharpsquid:S2857").is_empty());
    }
}
