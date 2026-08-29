use crate::CsLanguage;
use crate::cst::{ancestors_of, is_error_tainted, issue, node_text, parameters_of, range_of};
use crate::rules::literals::{literal_inner_text, string_literals};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

const PARAMETER_OWNER_KINDS: [&str; 7] = [
    "method_declaration",
    "constructor_declaration",
    "operator_declaration",
    "conversion_operator_declaration",
    "local_function_statement",
    "lambda_expression",
    "anonymous_method_expression",
];

const NESTED_EXPRESSION_CALLABLE_KINDS: [&str; 2] =
    ["lambda_expression", "anonymous_method_expression"];

/// csharpsquid:S2302 — strings that mirror an enclosing parameter name
/// should travel through `nameof`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let inner = literal_inner_text(literal, source);
        let Some(throw_statement) = enclosing_throw(literal) else {
            continue;
        };
        if let Some(parameter) = mirrored_parameter(throw_statement, inner, source) {
            issues.push(issue(
                language,
                "S2302",
                format!("Replace the string '{inner}' with 'nameof({parameter})'."),
                range_of(literal, source),
            ));
        }
    }
    issues
}

/// Nearest containing throw, unless the literal belongs to a deferred nested
/// expression inside that throw (for example, a lambda argument).
fn enclosing_throw(node: Node<'_>) -> Option<Node<'_>> {
    for ancestor in ancestors_of(node) {
        if ancestor.kind() == "throw_statement" {
            return Some(ancestor);
        }
        if NESTED_EXPRESSION_CALLABLE_KINDS.contains(&ancestor.kind()) {
            return None;
        }
    }
    None
}

/// Source spelling of a visible callable parameter mirrored by `literal`.
/// Verbatim identifiers compare without their source-only `@` prefix while
/// the returned spelling remains valid inside `nameof`.
fn mirrored_parameter<'a>(
    throw_statement: Node<'_>,
    literal: &str,
    source: &'a str,
) -> Option<&'a str> {
    ancestors_of(throw_statement)
        .filter(|ancestor| PARAMETER_OWNER_KINDS.contains(&ancestor.kind()))
        .flat_map(parameters_of)
        .filter_map(|parameter| parameter.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .find(|name| name.strip_prefix('@').unwrap_or(name) == literal)
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2302_requires_identifier_text_and_method_scope() {
        let report = analyze_default(
            "class A\n{\n    string tag = \"fallback\";\n\n    void Render(string label)\n    {\n        log(label + \":\");\n        Use(\"label with space\");\n        Use(\"1st\");\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2302").is_empty());
    }

    #[test]
    fn s2302_ignores_parameter_names_outside_throw_statements() {
        let report = analyze_default(
            "class A\n{\n    void Save(string userId)\n    {\n        audit(\"userId\");\n        audit(\"userId\");\n    }\n\n    void Send(string batch)\n    {\n        audit(\"batch\");\n        audit(\"userId\");\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2302").is_empty());
    }

    #[test]
    fn s2302_supports_nested_callables_and_verbatim_parameter_names() {
        let report = analyze_default(
            "class A\n{\n    A(string @class)\n    {\n        throw new Exception(\"class\");\n    }\n\n    void Outer(string outer)\n    {\n        void Inner(string inner)\n        {\n            throw new Exception(\"inner\");\n            throw new Exception(\"outer\");\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2302");
        assert_eq!(flagged.len(), 3);
        assert_eq!(
            flagged[0].message,
            "Replace the string 'class' with 'nameof(@class)'."
        );
        assert_eq!(flagged[2].range.start.line, 13);
    }

    #[test]
    fn s2302_ignores_literals_deferred_inside_throw_arguments() {
        let report = analyze_default(
            "class A\n{\n    void Save(string userId)\n    {\n        throw new Exception(() => \"userId\");\n        throw new Exception(delegate { return \"userId\"; });\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2302").is_empty());
    }
}
