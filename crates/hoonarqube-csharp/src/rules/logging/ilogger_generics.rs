use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{enclosing_type, first_named_child};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6672 — an injected `ILogger<T>` must name its enclosing type.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for generic in collect_kinds(root, &["generic_name"])
        .into_iter()
        .filter(|generic| !is_error_tainted(*generic))
        .filter(|generic| simple_name(node_text(*generic, source)) == "ILogger")
    {
        let Some(owner) = enclosing_type(generic) else {
            continue;
        };
        let Some(owner_name) = owner.child_by_field_name("name") else {
            continue;
        };
        let Some(arguments) = collect_kinds(generic, &["type_argument_list"])
            .into_iter()
            .next()
        else {
            continue;
        };
        let Some(argument) = first_named_child(arguments) else {
            continue;
        };
        if simple_name(node_text(argument, source)) != node_text(owner_name, source) {
            issues.push(issue(
                language,
                "S6672",
                "Update this logger to use its enclosing type.",
                range_of(argument, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6672_supports_namespace_qualified_ilogger_types() {
        let report = analyze_default(
            "class Order\n{\n    Microsoft.Extensions.Logging.ILogger<Customer> logger;\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6672").len(), 1);
    }
}
