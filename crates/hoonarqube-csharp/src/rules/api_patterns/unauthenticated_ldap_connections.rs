use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{
    enclosing_callable, expression_name, first_named_child, invocation_arguments, operator_of,
    resolved_identifier_type,
};
use crate::rules::literals::declarator_initializer;
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
        let arguments = invocation_arguments(creation);
        let authentication = arguments
            .iter()
            .find(|argument| {
                argument
                    .child_by_field_name("name")
                    .is_some_and(|name| canonical(node_text(name, source)) == "authenticationType")
            })
            .and_then(|argument| argument_value(*argument))
            .or_else(|| {
                arguments
                    .get(3)
                    .and_then(|argument| argument_value(*argument))
            });
        if authentication.is_some_and(|value| insecure_authentication(value, root, source)) {
            issues.push(issue(
                language,
                "S4433",
                MESSAGE,
                range_of(creation, source),
            ));
        }
    }
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if is_error_tainted(assignment) || operator_of(assignment) != Some("=") {
            continue;
        }
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        if left.kind() == "member_access_expression"
            && canonical(expression_name(left, source).unwrap_or("")) == "AuthenticationType"
            && first_named_child(left).is_some_and(|receiver| {
                is_directory_entry(receiver, root, source, assignment.start_byte())
            })
            && insecure_authentication(right, root, source)
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

fn canonical(name: &str) -> &str {
    name.strip_prefix('@').unwrap_or(name)
}

fn argument_value(argument: Node<'_>) -> Option<Node<'_>> {
    let name = argument.child_by_field_name("name").map(|node| node.id());
    let mut cursor = argument.walk();
    argument
        .children(&mut cursor)
        .filter(tree_sitter::Node::is_named)
        .find(|child| Some(child.id()) != name)
}

fn is_directory_entry(receiver: Node<'_>, root: Node<'_>, source: &str, before: usize) -> bool {
    if receiver.kind() == "object_creation_expression" {
        return receiver
            .child_by_field_name("type")
            .is_some_and(|ty| simple_name(node_text(ty, source)) == "DirectoryEntry");
    }
    receiver.kind() == "identifier"
        && (resolved_identifier_type(receiver, source)
            .is_some_and(|ty| simple_name(ty) == "DirectoryEntry")
            || variable_initializer(receiver, root, source, before).is_some_and(|initializer| {
                is_directory_entry(initializer, root, source, initializer.start_byte())
            }))
}

#[derive(Default)]
struct AuthenticationEvidence {
    anonymous: bool,
    none: bool,
    other: bool,
}

fn insecure_authentication(expression: Node<'_>, root: Node<'_>, source: &str) -> bool {
    let evidence = authentication_evidence(expression, root, source, &mut Vec::new());
    evidence.anonymous || (evidence.none && !evidence.other)
}

fn authentication_evidence(
    expression: Node<'_>,
    root: Node<'_>,
    source: &str,
    resolving: &mut Vec<String>,
) -> AuthenticationEvidence {
    if expression.kind() == "member_access_expression" {
        return member_access_evidence(expression, source);
    }
    if expression.kind() == "identifier" {
        return identifier_evidence(expression, root, source, resolving);
    }
    if expression.kind() == "integer_literal" && node_text(expression, source).trim() == "0" {
        return AuthenticationEvidence {
            none: true,
            ..AuthenticationEvidence::default()
        };
    }

    let mut evidence = AuthenticationEvidence::default();
    let mut cursor = expression.walk();
    for child in expression
        .children(&mut cursor)
        .filter(tree_sitter::Node::is_named)
    {
        let child = authentication_evidence(child, root, source, resolving);
        evidence.anonymous |= child.anonymous;
        evidence.none |= child.none;
        evidence.other |= child.other;
    }
    evidence
}

fn member_access_evidence(expression: Node<'_>, source: &str) -> AuthenticationEvidence {
    let owner =
        first_named_child(expression).map_or("", |node| simple_name(node_text(node, source)));
    if owner != "AuthenticationTypes" {
        return AuthenticationEvidence {
            other: true,
            ..AuthenticationEvidence::default()
        };
    }
    authentication_member_evidence(canonical(expression_name(expression, source).unwrap_or("")))
}

fn identifier_evidence(
    expression: Node<'_>,
    root: Node<'_>,
    source: &str,
    resolving: &mut Vec<String>,
) -> AuthenticationEvidence {
    let name = canonical(node_text(expression, source));
    if has_static_authentication_import(root, source) {
        return authentication_flag_evidence(name);
    }
    if resolving.iter().any(|resolved| resolved == name) {
        return AuthenticationEvidence::default();
    }
    let Some(initializer) = variable_initializer(expression, root, source, expression.start_byte())
    else {
        return AuthenticationEvidence::default();
    };
    resolving.push(name.to_owned());
    let evidence = authentication_evidence(initializer, root, source, resolving);
    resolving.pop();
    evidence
}

fn authentication_flag_evidence(name: &str) -> AuthenticationEvidence {
    match name {
        "Anonymous" => AuthenticationEvidence {
            anonymous: true,
            ..AuthenticationEvidence::default()
        },
        "None" => AuthenticationEvidence {
            none: true,
            ..AuthenticationEvidence::default()
        },
        "Secure" | "Encryption" | "Signing" | "Sealing" | "ServerBind" => AuthenticationEvidence {
            other: true,
            ..AuthenticationEvidence::default()
        },
        _ => AuthenticationEvidence::default(),
    }
}

fn authentication_member_evidence(name: &str) -> AuthenticationEvidence {
    match name {
        "Anonymous" => AuthenticationEvidence {
            anonymous: true,
            ..AuthenticationEvidence::default()
        },
        "None" => AuthenticationEvidence {
            none: true,
            ..AuthenticationEvidence::default()
        },
        _ => AuthenticationEvidence {
            other: true,
            ..AuthenticationEvidence::default()
        },
    }
}

fn variable_initializer<'t>(
    identifier: Node<'t>,
    root: Node<'t>,
    source: &str,
    before: usize,
) -> Option<Node<'t>> {
    let wanted = canonical(node_text(identifier, source));
    let owner = enclosing_callable(identifier).map(|callable| callable.id());
    collect_kinds(root, &["variable_declarator"])
        .into_iter()
        .filter(|declarator| declarator.end_byte() <= before)
        .filter(|declarator| enclosing_callable(*declarator).map(|callable| callable.id()) == owner)
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            (canonical(node_text(name, source)) == wanted)
                .then(|| declarator_initializer(declarator, name))
                .flatten()
                .map(|initializer| (declarator.start_byte(), initializer))
        })
        .max_by_key(|(start, _)| *start)
        .map(|(_, initializer)| initializer)
}

fn has_static_authentication_import(root: Node<'_>, source: &str) -> bool {
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .map(|using| {
            node_text(using, source)
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                .replace('@', "")
        })
        .any(|using| {
            using == "usingstaticSystem.DirectoryServices.AuthenticationTypes;"
                || using == "usingstaticAuthenticationTypes;"
        })
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

    #[test]
    fn s4433_understands_named_and_combined_authentication_flags() {
        let report = analyze_default(
            "class C { void M() {\nvar bad = new DirectoryEntry(authenticationType: (AuthenticationTypes.Anonymous | AuthenticationTypes.ServerBind), path: \"LDAP://srv\");\nvar good = new DirectoryEntry(authenticationType: AuthenticationTypes.None | AuthenticationTypes.Secure, path: \"LDAP://srv\");\n} }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4433").len(), 1);
    }

    #[test]
    fn s4433_ignores_similarly_named_properties_on_other_types() {
        let report = analyze_default(
            "class Other { public AuthenticationTypes AuthenticationType { get; set; } }\nclass C { void M(Other other) { other.AuthenticationType = AuthenticationTypes.Anonymous; } }\n",
        );
        assert!(with_key(&report, "csharpsquid:S4433").is_empty());
    }
}
