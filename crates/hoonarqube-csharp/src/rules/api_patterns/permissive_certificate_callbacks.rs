use crate::CsLanguage;
use crate::cst::{
    ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name,
};
use crate::rules::expressions::{
    block_statements, expression_name, first_named_child, lambda_shape, operator_of,
    resolved_identifier_type,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4830 — callbacks that accept any certificate disable
/// TLS server verification entirely.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if assignment.has_error()
            || is_error_tainted(assignment)
            || !matches!(operator_of(assignment), Some("=" | "+="))
        {
            continue;
        }
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        if !is_certificate_callback(left, source) {
            continue;
        }
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        if accepts_every_certificate(right, source) {
            let anchor = collect_kinds(left, &["identifier"])
                .into_iter()
                .last()
                .unwrap_or(left);
            issues.push(issue(
                language,
                "S4830",
                "Enable server certificate validation on this SSL/TLS connection",
                range_of(anchor, source),
            ));
        }
    }
    issues
}

fn is_certificate_callback(left: Node<'_>, source: &str) -> bool {
    match expression_name(left, source) {
        Some("ServerCertificateValidationCallback") => {
            member_receiver(left).is_some_and(|receiver| is_service_point_manager(receiver, source))
        }
        Some("ServerCertificateCustomValidationCallback") => {
            member_receiver(left).is_some_and(|receiver| is_http_client_handler(receiver, source))
                || is_http_client_handler_initializer(left, source)
        }
        _ => false,
    }
}

fn is_service_point_manager(receiver: Node<'_>, source: &str) -> bool {
    let receiver = compact_text(receiver, source);
    let receiver = receiver.strip_prefix("global::").unwrap_or(&receiver);
    matches!(
        receiver,
        "ServicePointManager" | "System.Net.ServicePointManager"
    )
}

fn is_http_client_handler(receiver: Node<'_>, source: &str) -> bool {
    if receiver.kind() == "object_creation_expression" {
        return receiver
            .child_by_field_name("type")
            .is_some_and(|ty| simple_name(node_text(ty, source)) == "HttpClientHandler");
    }

    let Some(identifier) = collect_kinds(receiver, &["identifier"]).into_iter().last() else {
        return false;
    };
    resolved_identifier_type(identifier, source)
        .is_some_and(|ty| simple_name(ty) == "HttpClientHandler")
}

fn is_http_client_handler_initializer(left: Node<'_>, source: &str) -> bool {
    if left.kind() != "identifier" {
        return false;
    }
    for ancestor in ancestors_of(left) {
        if matches!(
            ancestor.kind(),
            "lambda_expression" | "anonymous_method_expression"
        ) {
            return false;
        }
        if ancestor.kind() == "object_creation_expression" {
            return ancestor
                .child_by_field_name("type")
                .is_some_and(|ty| simple_name(node_text(ty, source)) == "HttpClientHandler");
        }
    }
    false
}

fn accepts_every_certificate(right: Node<'_>, source: &str) -> bool {
    let right = unwrap_parentheses(right);
    if is_dangerous_framework_validator(right, source) {
        return true;
    }
    let body = match right.kind() {
        "lambda_expression" => lambda_shape(right, source).map(|(_, body)| body),
        "anonymous_method_expression" => last_named_child(right),
        _ => None,
    };
    body.is_some_and(|body| returns_true(body, source))
}

fn is_dangerous_framework_validator(expression: Node<'_>, source: &str) -> bool {
    let expression = compact_text(expression, source);
    let expression = expression.strip_prefix("global::").unwrap_or(&expression);
    matches!(
        expression,
        "HttpClientHandler.DangerousAcceptAnyServerCertificateValidator"
            | "System.Net.Http.HttpClientHandler.DangerousAcceptAnyServerCertificateValidator"
    )
}

fn returns_true(body: Node<'_>, source: &str) -> bool {
    let value = if body.kind() == "block" {
        let statements = block_statements(body);
        match statements.as_slice() {
            [statement] if statement.kind() == "return_statement" => first_named_child(*statement),
            _ => None,
        }
    } else {
        Some(body)
    };
    value.map(unwrap_parentheses).is_some_and(|value| {
        value.kind() == "boolean_literal" && node_text(value, source) == "true"
    })
}

fn unwrap_parentheses(mut expression: Node<'_>) -> Node<'_> {
    while expression.kind() == "parenthesized_expression" {
        let Some(inner) = first_named_child(expression) else {
            break;
        };
        expression = inner;
    }
    expression
}

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .filter(tree_sitter::Node::is_named)
        .last()
}

fn compact_text(node: Node<'_>, source: &str) -> String {
    node_text(node, source)
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn member_receiver(left: Node<'_>) -> Option<Node<'_>> {
    (left.kind() == "member_access_expression")
        .then_some(left)
        .and_then(first_named_child)
}

#[cfg(test)]
mod tests {
    use super::check;
    use crate::CsLanguage;
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4830_handles_addition_parentheses_and_block_returns() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, errors) => (true);\n        ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => { return true; };\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4830").len(), 2);
    }

    #[test]
    fn s4830_handles_anonymous_methods_and_framework_validator() {
        let report = analyze_default(
            "class C\n{\n    void M(HttpClientHandler handler)\n    {\n        handler.ServerCertificateCustomValidationCallback = delegate (object request, object cert, object chain, object errors) { return (true); };\n        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;\n        var other = new HttpClientHandler\n        {\n            ServerCertificateCustomValidationCallback = global::System.Net.Http.HttpClientHandler.DangerousAcceptAnyServerCertificateValidator\n        };\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4830").len(), 3);
    }

    #[test]
    fn s4830_requires_framework_callback_receivers_and_unconditional_true() {
        let report = analyze_default(
            "class Fake\n{\n    public object ServerCertificateValidationCallback { get; set; }\n    public object ServerCertificateCustomValidationCallback { get; set; }\n}\nclass C\n{\n    void M(Fake fake, HttpClientHandler handler)\n    {\n        fake.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;\n        fake.ServerCertificateCustomValidationCallback += delegate { return true; };\n        handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) => errors == null;\n        handler.ServerCertificateCustomValidationCallback = delegate { Log(); return true; };\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4830").is_empty());
    }

    #[test]
    fn s4830_skips_error_tainted_assignments() {
        let source = "class C { void M() { ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true +; } }";
        let tree = crate::parse(source);
        assert!(tree.root_node().has_error());
        assert!(check(tree.root_node(), source, CsLanguage::CSharp).is_empty());
    }
}
