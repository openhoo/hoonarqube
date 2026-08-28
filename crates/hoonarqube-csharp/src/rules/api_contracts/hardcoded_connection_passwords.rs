use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::callee_name;
use crate::rules::literals::{literal_inner_text, string_literals};
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
        let insecure = string_literals(invocation).into_iter().any(|literal| {
            let inner = literal_inner_text(literal, source);
            let lowered = inner.to_ascii_lowercase();
            !lowered.contains("integrated security")
                && embedded_password_value(inner, &lowered).is_some_and(str::is_empty)
        });
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

/// The credential value inside a connection-string literal, if present.
fn embedded_password_value<'a>(literal_text: &'a str, lowered: &str) -> Option<&'a str> {
    for marker in ["password=", "pwd="] {
        if let Some(position) = lowered.find(marker) {
            let value_start = position + marker.len();
            let value_end = lowered[value_start..]
                .find(';')
                .map_or(lowered.len(), |relative| value_start + relative);
            return Some(literal_text[value_start..value_end].trim());
        }
    }
    None
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
}
