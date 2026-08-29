use crate::CsLanguage;
use crate::cst::{
    ancestors_of, collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of,
    simple_name,
};
use crate::rules::expressions::{
    binary_operands, creation_type_text, expression_name, first_named_child, integer_literal_value,
    invocation_arguments, operator_of,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4426 — weak asymmetric providers and short keys give way.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const MINIMUM_ASYMMETRIC_KEY_SIZE: u64 = 2048;
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        let algorithm = match simple_name(creation_type_text(creation, source)) {
            "RSACryptoServiceProvider" => "RSA",
            "DSACryptoServiceProvider" => "DSA",
            _ => continue,
        };
        if explicit_creation_size(creation, source)
            .is_some_and(|bits| bits >= MINIMUM_ASYMMETRIC_KEY_SIZE)
        {
            continue;
        }
        issues.push(issue(
            language,
            "S4426",
            format!("Use a key length of at least 2048 bits for {algorithm} cipher algorithm."),
            range_of(creation, source),
        ));
    }
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if is_error_tainted(assignment) || operator_of(assignment) != Some("=") {
            continue;
        }
        let Some((target, value)) = binary_operands(assignment) else {
            continue;
        };
        if target.kind() != "member_access_expression"
            || expression_name(target, source) != Some("KeySize")
            || value.kind() != "integer_literal"
        {
            continue;
        }
        let undersized = integer_literal_value(node_text(value, source))
            .is_some_and(|bits| bits < MINIMUM_ASYMMETRIC_KEY_SIZE);
        if undersized
            && let Some(receiver) = first_named_child(target)
            && let Some(variable) = expression_name(receiver, source)
            && let Some(algorithm) = declared_algorithm(assignment, variable, source)
        {
            issues.push(issue(
                language,
                "S4426",
                format!(
                    "Use a key length of at least 2048 bits for {algorithm} cipher algorithm. This assignment does not update the underlying key size."
                ),
                range_of(assignment, source),
            ));
        }
    }
    issues
}

fn explicit_creation_size(creation: Node<'_>, source: &str) -> Option<u64> {
    invocation_arguments(creation)
        .first()
        .and_then(|argument| {
            let mut cursor = argument.walk();
            argument.named_children(&mut cursor).last()
        })
        .filter(|value| value.kind() == "integer_literal")
        .and_then(|value| integer_literal_value(node_text(value, source)))
}

fn declared_algorithm<'a>(assignment: Node<'_>, name: &str, source: &'a str) -> Option<&'a str> {
    let callable = ancestors_of(assignment).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "destructor_declaration"
                | "operator_declaration"
                | "accessor_declaration"
                | "local_function_statement"
        )
    })?;

    if let Some(local_algorithm) = visible_local_algorithm(callable, assignment, name, source) {
        return Some(local_algorithm);
    }
    if let Some(parameter_type) = parameters_of(callable).into_iter().find_map(|parameter| {
        parameter
            .child_by_field_name("name")
            .filter(|parameter_name| node_text(*parameter_name, source) == name)?;
        parameter.child_by_field_name("type")
    }) {
        return asymmetric_algorithm(node_text(parameter_type, source));
    }
    let owner = ancestors_of(callable).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "class_declaration" | "struct_declaration" | "record_declaration"
        )
    })?;
    crate::rules::naming::type_members(owner)
        .into_iter()
        .filter(|member| member.kind() == "field_declaration")
        .find_map(|field| {
            let declaration = collect_kinds(field, &["variable_declaration"])
                .into_iter()
                .next()?;
            collect_kinds(declaration, &["variable_declarator"])
                .into_iter()
                .any(|declarator| {
                    declarator
                        .child_by_field_name("name")
                        .is_some_and(|field_name| node_text(field_name, source) == name)
                })
                .then(|| declaration.child_by_field_name("type"))
                .flatten()
        })
        .and_then(|field_type| asymmetric_algorithm(node_text(field_type, source)))
}

fn visible_local_algorithm(
    callable: Node<'_>,
    assignment: Node<'_>,
    name: &str,
    source: &str,
) -> Option<&'static str> {
    let ancestor_blocks: std::collections::HashSet<usize> = ancestors_of(assignment)
        .filter(|ancestor| ancestor.kind() == "block")
        .map(|block| block.id())
        .collect();
    collect_kinds(callable, &["variable_declaration"])
        .into_iter()
        .filter(|declaration| declaration.start_byte() < assignment.start_byte())
        .filter(|declaration| {
            declaration
                .parent()
                .and_then(|statement| ancestors_of(statement).find(|node| node.kind() == "block"))
                .is_some_and(|block| ancestor_blocks.contains(&block.id()))
        })
        .rev()
        .find_map(|declaration| {
            let declarator = collect_kinds(declaration, &["variable_declarator"])
                .into_iter()
                .find(|declarator| {
                    declarator
                        .child_by_field_name("name")
                        .is_some_and(|local_name| node_text(local_name, source) == name)
                })?;
            let type_node = declaration.child_by_field_name("type")?;
            let declared_type = node_text(type_node, source);
            asymmetric_algorithm(declared_type).or_else(|| {
                (declared_type == "var")
                    .then(|| {
                        let mut cursor = declarator.walk();
                        declarator
                            .named_children(&mut cursor)
                            .find(|child| child.kind() == "object_creation_expression")
                    })
                    .flatten()
                    .and_then(|creation| asymmetric_algorithm(creation_type_text(creation, source)))
            })
        })
}

fn asymmetric_algorithm(type_text: &str) -> Option<&'static str> {
    match simple_name(type_text) {
        "RSA" | "RSACryptoServiceProvider" => Some("RSA"),
        "DSA" | "DSACryptoServiceProvider" => Some("DSA"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4426_unrelated_key_size_members_are_not_cryptographic_keys() {
        let report = analyze_default(
            "class Cache { void Set(BufferOptions options) { options.KeySize = 32; } }",
        );
        assert!(with_key(&report, "csharpsquid:S4426").is_empty());
    }

    #[test]
    fn s4426_exact_rsa_and_dsa_declarations_are_resolved() {
        let report = analyze_default(
            "class Crypto { RSA rsa; void Set(DSA dsa) { rsa.KeySize = 1024; dsa.KeySize = 512; } }",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4426").len(), 2);
    }

    #[test]
    fn s4426_resolves_using_var_provider_initializers() {
        let source = "using System.Security.Cryptography; class Crypto { void Set() { using var rsa = new RSACryptoServiceProvider(); rsa.KeySize = 1024; using var dsa = new DSACryptoServiceProvider(); dsa.KeySize = 512; } }";
        let tree = crate::parse(source);
        let report = analyze_default(source);
        let issues = with_key(&report, "csharpsquid:S4426");
        assert_eq!(issues.len(), 4, "{}", tree.root_node().to_sexp());
        assert_eq!(
            issues
                .iter()
                .filter(|issue| issue.message.contains("does not update"))
                .count(),
            2
        );
    }

    #[test]
    fn s4426_explicit_adequate_provider_size_is_clean() {
        let report =
            analyze_default("class Crypto { RSA Make() => new RSACryptoServiceProvider(4096); }");
        assert!(with_key(&report, "csharpsquid:S4426").is_empty());
    }
}
