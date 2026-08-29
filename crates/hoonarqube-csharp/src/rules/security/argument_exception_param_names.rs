use super::support::{argument_value, call_argument_nodes, named_argument_value};
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of, simple_name,
};
use crate::rules::declaration_contracts::enclosing_method;
use crate::rules::expressions::creation_type_text;
use crate::rules::literals::literal_inner_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3928 — the 'paramName' argument must name a parameter that
/// actually exists on the throwing method.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const ARGUMENT_EXCEPTION_TYPES: [&str; 3] = [
        "ArgumentException",
        "ArgumentNullException",
        "ArgumentOutOfRangeException",
    ];
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if is_error_tainted(creation) {
            continue;
        }
        if !ARGUMENT_EXCEPTION_TYPES.contains(&simple_name(creation_type_text(creation, source))) {
            continue;
        }
        let exception_type = simple_name(creation_type_text(creation, source));
        let arguments = call_argument_nodes(creation);
        let parameter_name_index = usize::from(exception_type == "ArgumentException");
        let Some(argument) = arguments
            .iter()
            .find(|argument| named_argument_value(**argument, source, "paramName").is_some())
            .copied()
            .or_else(|| arguments.get(parameter_name_index).copied())
        else {
            continue;
        };
        let value = argument_value(argument);
        if value.kind() != "string_literal" {
            continue;
        }
        let wanted = literal_inner_text(value, source);
        let Some(method) = enclosing_method(creation) else {
            continue;
        };
        let known = parameters_of(method).iter().any(|param| {
            param
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == wanted)
        });
        if !known {
            issues.push(issue(
                language,
                "S3928",
                format!("The parameter name '{wanted}' is not declared in the argument list."),
                range_of(creation, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3928_named_param_name_uses_its_value_regardless_of_order() {
        let clean = analyze_default(
            "class Guard { void Check(int amount) { throw new ArgumentException(paramName: \"amount\", message: \"bad\"); } }",
        );
        assert!(with_key(&clean, "csharpsquid:S3928").is_empty());

        let bad = analyze_default(
            "class Guard { void Check(int amount) { throw new ArgumentException(paramName: \"other\", message: \"bad\"); } }",
        );
        let flagged = with_key(&bad, "csharpsquid:S3928");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'other'"));
    }
}
