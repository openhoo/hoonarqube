//! `java:S2211` — types should be used in lambdas.
//!
//! Contract pinned against the live SonarQube 26.8 Community reference
//! (rule show: scope MAIN, MAJOR CODE_SMELL, no parameters; oracle: the
//! pinned `gson` scan with 44 findings). A lambda with at least one
//! implicitly typed parameter is reported once, listing every parameter,
//! unless the reference exception applies: one or two parameters with an
//! expression body (no block) stay silent. Explicitly typed parameters,
//! method references, and zero-parameter lambdas never fire. The finding
//! spans from the first to the last parameter name.

use crate::support::{LineIndex, collect_kinds, node_text};
use hoonarqube_ir::{Issue, Range};
use tree_sitter::Node;

pub(crate) fn check(root: Node<'_>, source: &str, lines: &LineIndex) -> Vec<Issue> {
    let mut issues = Vec::new();
    for lambda in collect_kinds(root, &["lambda_expression"]) {
        let Some(parameters) = lambda.child_by_field_name("parameters") else {
            continue;
        };
        let names: Vec<Node<'_>> = match parameters.kind() {
            "identifier" | "_reserved_identifier" => vec![parameters],
            "inferred_parameters" => {
                let mut cursor = parameters.walk();
                parameters
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "identifier")
                    .collect()
            }
            // `formal_parameters` means every parameter carries an explicit type.
            _ => continue,
        };
        if names.is_empty() {
            continue;
        }
        let expression_body = lambda
            .child_by_field_name("body")
            .is_some_and(|body| body.kind() != "block");
        if names.len() <= 2 && expression_body {
            continue;
        }
        let list = names
            .iter()
            .map(|name| format!("'{}'", node_text(*name, source)))
            .collect::<Vec<_>>()
            .join(", ");
        let range: Range = lines.range(
            source,
            names[0].start_byte(),
            names[names.len() - 1].end_byte(),
        );
        issues.push(Issue::new("java:S2211", format!("Specify a type for: {list}"), range));
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::parse;

    fn messages(source: &str) -> Vec<String> {
        let tree = parse(source).expect("valid Java fixture");
        let lines = LineIndex::new(source);
        check(tree.root_node(), source, &lines)
            .into_iter()
            .map(|issue| issue.message)
            .collect()
    }

    #[test]
    fn reports_three_parameter_lambda_listing_every_name() {
        let message = &messages("class A { void f() { g((a, b, c) -> a); } }")[0];
        assert_eq!(message, "Specify a type for: 'a', 'b', 'c'");
    }

    #[test]
    fn short_expression_lambdas_stay_silent() {
        let source = concat!(
            "class A {\n",
            "  void f() {\n",
            "    g(a -> a, (a, b) -> a + b, (A x) -> x);\n",
            "  }\n",
            "}"
        );
        assert!(messages(source).is_empty());
    }

    #[test]
    fn block_bodied_and_long_lambdas_fire() {
        let source = concat!(
            "class A {\n",
            "  void f() {\n",
            "    g(c -> { return c; });\n",
            "    h((a, b) -> { return a; });\n",
            "    i((a, b, c) -> a);\n",
            "  }\n",
            "}"
        );
        let messages = messages(source);
        assert_eq!(
            messages,
            vec![
                "Specify a type for: 'c'".to_string(),
                "Specify a type for: 'a', 'b'".to_string(),
                "Specify a type for: 'a', 'b', 'c'".to_string(),
            ]
        );
    }

    #[test]
    fn explicit_types_and_empty_parameters_stay_silent() {
        let source = concat!(
            "class A {\n",
            "  void f() {\n",
            "    g((A a, B b, C c) -> a);\n",
            "    h(() -> 1);\n",
            "    i(this::toString);\n",
            "  }\n",
            "}"
        );
        assert!(messages(source).is_empty());
    }
}
