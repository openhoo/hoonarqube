use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{invocation_arguments, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

const MESSAGE: &str =
    "Set the 'AuthenticationType' property of this DirectoryEntry to 'AuthenticationTypes.Secure'.";

/// csharpsquid:S4433 — explicit anonymous or unauthenticated LDAP binds are
/// unsafe. A one-argument `DirectoryEntry` uses the secure framework default.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if is_error_tainted(creation)
            || !creation
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    simple_name(node_text(type_node, source)) == "DirectoryEntry"
                })
        {
            continue;
        }
        if invocation_arguments(creation)
            .last()
            .is_some_and(|argument| insecure_authentication(node_text(*argument, source)))
        {
            issues.push(issue(
                language,
                "S4433",
                MESSAGE,
                range_of(creation, source),
            ));
        }
    }
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if operator_of(assignment) != Some("=") {
            continue;
        }
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        if node_text(left, source).ends_with(".AuthenticationType")
            && insecure_authentication(node_text(right, source))
        {
            issues.push(issue(
                language,
                "S4433",
                MESSAGE,
                range_of(assignment, source),
            ));
        }
    }
    issues
}

fn insecure_authentication(text: &str) -> bool {
    text.ends_with("AuthenticationTypes.Anonymous") || text.ends_with("AuthenticationTypes.None")
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4433_flags_explicit_anonymous_constructor_and_assignment() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        var first = new DirectoryEntry(\"LDAP://srv\", null, null, AuthenticationTypes.Anonymous);\n        var second = new DirectoryEntry(\"LDAP://srv\");\n        second.AuthenticationType = AuthenticationTypes.None;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4433");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 7);
    }

    #[test]
    fn s4433_accepts_default_and_explicit_secure_authentication() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        var first = new DirectoryEntry(\"LDAP://srv\");\n        var second = new DirectoryEntry(\"LDAP://srv\", \"user\", \"pass\", AuthenticationTypes.Secure);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4433").is_empty());
    }
}
