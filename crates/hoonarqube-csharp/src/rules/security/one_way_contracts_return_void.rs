use super::support::{attributed_declaration, named_argument_value, return_type_text};
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::declaration_contracts::attribute_applications;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3598 — one-way operations cannot report a result.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, args, attribute) in attribute_applications(root, source) {
        if !matches!(name, "OperationContract" | "OperationContractAttribute") {
            continue;
        }
        let Some(args) = args else { continue };
        let is_one_way = collect_kinds(args, &["attribute_argument"])
            .into_iter()
            .any(|argument| {
                named_argument_value(argument, source, "IsOneWay")
                    .is_some_and(|value| node_text(value, source) == "true")
            });
        if !is_one_way {
            continue;
        }
        let Some(method) = attributed_declaration(attribute) else {
            continue;
        };
        if method.kind() == "method_declaration" && return_type_text(method, source) != "void" {
            let return_type = method
                .child_by_field_name("returns")
                .or_else(|| method.child_by_field_name("type"))
                .unwrap_or(method);
            issues.push(issue(
                language,
                "S3598",
                "This method can't return any values because it is marked as one-way operation.",
                range_of(return_type, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3598_does_not_borrow_true_from_an_unrelated_attribute_argument() {
        let report = analyze_default(
            "class Service { [OperationContract(IsOneWay = false, Name = \"true\")] int Read() => 1; }",
        );
        assert!(with_key(&report, "csharpsquid:S3598").is_empty());
    }

    #[test]
    fn s3598_recognizes_compact_named_boolean_argument() {
        let report = analyze_default(
            "class Service { [OperationContract(IsOneWay=true)] int Read() => 1; }",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3598").len(), 1);
    }
}
