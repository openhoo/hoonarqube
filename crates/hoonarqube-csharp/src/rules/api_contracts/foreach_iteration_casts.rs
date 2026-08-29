use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::enclosing_type;
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3217 — a typed `foreach` over a generic collection must not
/// silently downcast each element.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for each in collect_kinds(root, &["foreach_statement"]) {
        if is_error_tainted(each) {
            continue;
        }
        let Some(loop_variable) = each.child_by_field_name("left") else {
            continue;
        };
        let Some(loop_type) = each.child_by_field_name("type") else {
            continue;
        };
        let Some(collection) = each.child_by_field_name("right") else {
            continue;
        };
        if collection.kind() != "identifier" {
            continue;
        }
        let collection_name = node_text(collection, source);
        let Some(element_type) = generic_element_type(each, collection_name, source) else {
            continue;
        };
        let loop_type_text = node_text(loop_type, source);
        if element_type == "object" || element_type == loop_type_text {
            continue;
        }
        issues.push(issue(
            language,
            "S3217",
            format!(
                "Either change the type of '{}' to '{}' or iterate on a generic collection of type '{}'.",
                node_text(loop_variable, source),
                element_type,
                loop_type_text
            ),
            range_of(loop_type, source),
        ));
    }
    issues
}

fn generic_element_type<'a>(each: Node<'_>, name: &str, source: &'a str) -> Option<&'a str> {
    let callable = enclosing_callable(each)?;
    let type_node = visible_local_declaration(callable, each, name, source)
        .and_then(declaration_type)
        .or_else(|| callable_parameter_type(callable, name, source))
        .or_else(|| field_type(each, name, source))?;
    first_generic_argument(node_text(type_node, source))
}

/// Closest visible local declaration with `name`; declarations in later or
/// sibling scopes and nested callables cannot bind the collection expression.
fn visible_local_declaration<'t>(
    callable: Node<'t>,
    use_site: Node<'t>,
    name: &str,
    source: &str,
) -> Option<Node<'t>> {
    collect_kinds(callable, &["variable_declarator"])
        .into_iter()
        .filter(|declaration| enclosing_callable(*declaration) == Some(callable))
        .filter(|declaration| declaration.start_byte() < use_site.start_byte())
        .filter(|declaration| {
            declaration_scope(*declaration).is_some_and(|scope| {
                scope == use_site || ancestors_of(use_site).any(|ancestor| ancestor == scope)
            })
        })
        .filter(|declaration| {
            declaration
                .child_by_field_name("name")
                .is_some_and(|declared| node_text(declared, source) == name)
        })
        .max_by_key(tree_sitter::Node::start_byte)
}

fn callable_parameter_type<'t>(callable: Node<'t>, name: &str, source: &str) -> Option<Node<'t>> {
    collect_kinds(callable, &["parameter"])
        .into_iter()
        .filter(|parameter| enclosing_callable(*parameter) == Some(callable))
        .find(|parameter| {
            parameter
                .child_by_field_name("name")
                .is_some_and(|declared| node_text(declared, source) == name)
        })?
        .child_by_field_name("type")
}

fn field_type<'t>(use_site: Node<'t>, name: &str, source: &str) -> Option<Node<'t>> {
    type_members(enclosing_type(use_site)?)
        .into_iter()
        .filter(|member| member.kind() == "field_declaration")
        .flat_map(|field| collect_kinds(field, &["variable_declarator"]))
        .find(|declaration| {
            declaration
                .child_by_field_name("name")
                .is_some_and(|declared| node_text(declared, source) == name)
        })
        .and_then(declaration_type)
}

fn declaration_type(declaration: Node<'_>) -> Option<Node<'_>> {
    declaration
        .parent()
        .and_then(|parent| parent.child_by_field_name("type"))
}

fn declaration_scope(declaration: Node<'_>) -> Option<Node<'_>> {
    ancestors_of(declaration).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "block"
                | "for_statement"
                | "foreach_statement"
                | "using_statement"
                | "fixed_statement"
                | "switch_section"
        )
    })
}

fn enclosing_callable(node: Node<'_>) -> Option<Node<'_>> {
    ancestors_of(node).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "destructor_declaration"
                | "accessor_declaration"
                | "operator_declaration"
                | "conversion_operator_declaration"
                | "local_function_statement"
                | "anonymous_method_expression"
                | "lambda_expression"
        )
    })
}

/// First type argument of the outer generic type, retaining nested generics.
fn first_generic_argument(type_text: &str) -> Option<&str> {
    let start = type_text.find('<')? + 1;
    let mut depth = 0_usize;
    for (relative, character) in type_text[start..].char_indices() {
        match character {
            '<' => depth += 1,
            '>' | ',' if depth == 0 => {
                return Some(type_text[start..start + relative].trim());
            }
            '>' => depth -= 1,
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3217_flags_typed_iteration_downcasts() {
        let report = analyze_default(
            "class Fruit { }\nclass Orange : Fruit { }\nclass A\n{\n    void M(System.Collections.Generic.List<Fruit> rows)\n    {\n        foreach (Orange row in rows)\n            Log(row);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3217").len(), 1);
    }

    #[test]
    fn s3217_matching_iteration_types_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M(System.Collections.Generic.List<string> values)\n    {\n        foreach (string raw in values)\n            Log(raw.Length);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3217").is_empty());
    }

    #[test]
    fn s3217_resolves_collection_types_inside_the_current_callable() {
        let report = analyze_default(
            "class Fruit { }\nclass Orange : Fruit { }\nclass A\n{\n    void Other(System.Collections.Generic.List<Fruit> rows) { }\n\n    void M(System.Collections.Generic.List<Orange> rows)\n    {\n        foreach (Orange row in rows)\n            Log(row);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3217").is_empty());
    }

    #[test]
    fn s3217_ignores_later_and_sibling_declarations() {
        let report = analyze_default(
            "class Fruit { }\nclass Orange : Fruit { }\nclass A\n{\n    void M(System.Collections.Generic.List<Orange> rows)\n    {\n        { var other = new System.Collections.Generic.List<Fruit>(); }\n        foreach (Orange row in rows) Log(row);\n        var rows2 = new System.Collections.Generic.List<Fruit>();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3217").is_empty());
    }

    #[test]
    fn s3217_preserves_nested_generic_element_types() {
        let report = analyze_default(
            "class A\n{\n    void M(System.Collections.Generic.List<System.Collections.Generic.Dictionary<string, int>> rows)\n    {\n        foreach (System.Collections.Generic.Dictionary<string, int> row in rows)\n            Log(row);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3217").is_empty());
    }

    #[test]
    fn s3217_resolves_field_backed_collections_in_the_enclosing_type() {
        let report = analyze_default(
            "class Fruit { }\nclass Orange : Fruit { }\nclass A\n{\n    System.Collections.Generic.List<Fruit> rows;\n    void M()\n    {\n        foreach (Orange row in rows) Log(row);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3217").len(), 1);
    }
}
