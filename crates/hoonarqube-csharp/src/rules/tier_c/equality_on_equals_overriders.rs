use super::support::declared_type_names;
use crate::CsLanguage;
use crate::cst::{
    ancestors_of, canonical_identifier, collect_kinds, containing_namespace, is_error_tainted,
    issue, modifiers_of, node_text, parameters_of, range_of, simple_name,
};
use crate::rules::expressions::{
    binary_operands, member_declarations_of_kind, overloaded_operator,
};
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::structure::binary_operator;
use hoonarqube_ir::Issue;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

fn equals_overriding_class_names<'a>(root: Node<'a>, source: &'a str) -> HashSet<&'a str> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class| {
            member_declarations_of_kind(*class, "method_declaration")
                .into_iter()
                .any(|method| {
                    has_modifier(&modifiers_of(method, source), "override")
                        && method
                            .child_by_field_name("name")
                            .is_some_and(|name| node_text(name, source) == "Equals")
                })
        })
        .filter_map(|class| class.child_by_field_name("name"))
        .map(|name| canonical_identifier(node_text(name, source)))
        .collect()
}

struct EqualityOperatorOverload {
    owner_namespace: String,
    operator: &'static str,
    parameter_types: Vec<String>,
}

fn normalized_type_name(text: &str) -> String {
    text.trim()
        .replace(' ', "")
        .trim_end_matches('?')
        .to_string()
}

fn declared_type<'a>(
    types: &'a HashMap<&'a str, &'a str>,
    operand: Node<'_>,
    source: &str,
) -> Option<&'a str> {
    let name = canonical_identifier(node_text(operand, source));
    types.get(name).copied().or_else(|| {
        types
            .iter()
            .find(|(declared, _)| canonical_identifier(declared) == name)
            .map(|(_, type_name)| *type_name)
    })
}

fn equality_operator_overloads(root: Node<'_>, source: &str) -> Vec<EqualityOperatorOverload> {
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter_map(|type_node| {
            type_node.child_by_field_name("name")?;
            let owner_namespace = containing_namespace(type_node, source);
            let overloads = member_declarations_of_kind(type_node, "operator_declaration")
                .into_iter()
                .filter_map(|declaration| {
                    let operator = overloaded_operator(declaration)?;
                    if !matches!(operator, "==" | "!=") {
                        return None;
                    }
                    let parameter_types = parameters_of(declaration)
                        .into_iter()
                        .filter_map(|parameter| parameter.child_by_field_name("type"))
                        .map(|type_node| normalized_type_name(node_text(type_node, source)))
                        .collect::<Vec<_>>();
                    Some(EqualityOperatorOverload {
                        owner_namespace: owner_namespace.clone(),
                        operator,
                        parameter_types,
                    })
                })
                .collect::<Vec<_>>();
            (!overloads.is_empty()).then_some(overloads)
        })
        .flatten()
        .collect()
}

fn has_system_import(root: Node<'_>, use_site: Node<'_>, source: &str) -> bool {
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .filter(|using| {
            containing_namespace(*using, source) == containing_namespace(use_site, source)
                || containing_namespace(*using, source).is_empty()
        })
        .any(|using| {
            let text = node_text(using, source)
                .trim()
                .trim_end_matches(';')
                .trim()
                .trim_start_matches("global")
                .trim()
                .trim_start_matches("using")
                .trim();
            text == "System"
        })
        || containing_namespace(use_site, source) == "System"
}

fn is_object_cast(root: Node<'_>, operand: Node<'_>, source: &str) -> bool {
    if operand.kind() != "cast_expression" {
        return false;
    }
    let Some(type_node) = operand.child_by_field_name("type") else {
        return false;
    };
    let raw = normalized_type_name(node_text(type_node, source));
    if raw == "object" || raw == "global::System.Object" || raw == "System.Object" {
        return true;
    }
    raw == "Object"
        && has_system_import(root, operand, source)
        && !collect_kinds(root, &TYPE_DECLARATION_KINDS)
            .into_iter()
            .filter_map(|declaration| declaration.child_by_field_name("name"))
            .any(|name| canonical_identifier(node_text(name, source)) == "Object")
}

fn is_equals_override_context(comparison: Node<'_>, source: &str) -> bool {
    let Some(callable) = ancestors_of(comparison).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "method_declaration"
                | "local_function_statement"
                | "lambda_expression"
                | "anonymous_method_expression"
                | "operator_declaration"
                | "constructor_declaration"
        )
    }) else {
        return false;
    };
    callable.kind() == "method_declaration"
        && callable
            .child_by_field_name("name")
            .is_some_and(|name| canonical_identifier(node_text(name, source)) == "Equals")
        && has_modifier(&modifiers_of(callable, source), "override")
}

fn is_type_match(
    actual: &str,
    expected: &str,
    overload: &EqualityOperatorOverload,
    comparison: Node<'_>,
    source: &str,
) -> bool {
    if actual == expected {
        return actual.contains('.')
            || actual.contains("::")
            || containing_namespace(comparison, source).as_str()
                == overload.owner_namespace.as_str();
    }
    let actual_namespace = actual
        .rsplit_once('.')
        .map(|(namespace, _)| namespace.strip_prefix("global::").unwrap_or(namespace));
    simple_name(actual) == simple_name(expected)
        && (actual_namespace == Some(overload.owner_namespace.as_str())
            || containing_namespace(comparison, source).as_str()
                == overload.owner_namespace.as_str())
}
fn comparison_uses_overloaded_operator(
    comparison: Node<'_>,
    left: Node<'_>,
    right: Node<'_>,
    operator: &str,
    types: &HashMap<&str, &str>,
    overloads: &[EqualityOperatorOverload],
    source: &str,
) -> bool {
    let declared = |operand: Node<'_>| {
        (operand.kind() == "identifier")
            .then(|| declared_type(types, operand, source).map(normalized_type_name))
            .flatten()
    };
    let Some(left_type) = declared(left) else {
        return false;
    };
    let Some(right_type) = declared(right) else {
        return false;
    };
    overloads.iter().any(|overload| {
        overload.operator == operator
            && overload.parameter_types.len() == 2
            && ((is_type_match(
                &left_type,
                &overload.parameter_types[0],
                overload,
                comparison,
                source,
            ) && is_type_match(
                &right_type,
                &overload.parameter_types[1],
                overload,
                comparison,
                source,
            )) || (is_type_match(
                &left_type,
                &overload.parameter_types[1],
                overload,
                comparison,
                source,
            ) && is_type_match(
                &right_type,
                &overload.parameter_types[0],
                overload,
                comparison,
                source,
            )))
    })
}

/// csharpsquid:S1698 — `==`/`!=` on operands typed to a file-local class that
/// overrides `Equals`, where reference identity almost certainly is not the
/// intended comparison. Null checks and resolved overloaded equality operators
/// are intentional and stay clean.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const EQUALITY_OPERATORS: [&str; 2] = ["==", "!="];
    let types = declared_type_names(root, source);
    let overriders = equals_overriding_class_names(root, source);
    let overloads = equality_operator_overloads(root, source);
    collect_kinds(root, &["binary_expression"])
        .into_iter()
        .filter(|comparison| !is_error_tainted(*comparison))
        .filter(|comparison| EQUALITY_OPERATORS.contains(&binary_operator(*comparison, source)))
        .filter(|comparison| {
            let Some((left, right)) = binary_operands(*comparison) else {
                return false;
            };
            if is_equals_override_context(*comparison, source)
                || left.kind() == "null_literal"
                || right.kind() == "null_literal"
                || is_object_cast(root, left, source)
                || is_object_cast(root, right, source)
            {
                return false;
            }
            let operator = binary_operator(*comparison, source);
            if comparison_uses_overloaded_operator(
                *comparison,
                left,
                right,
                operator,
                &types,
                &overloads,
                source,
            ) {
                return false;
            }
            [left, right].iter().any(|operand| {
                operand.kind() == "identifier"
                    && declared_type(&types, *operand, source)
                        .is_some_and(|declared| overriders.contains(simple_name(declared)))
            })
        })
        .map(|comparison| {
            let operator = collect_kinds(comparison, &["==", "!="])
                .into_iter()
                .next()
                .unwrap_or(comparison);
            issue(
                language,
                "S1698",
                "Consider using 'Equals' if value comparison was intended.",
                range_of(operator, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const OVERRIDER: &str = "class Money\n{\n    public override bool Equals(object other)\n    {\n        return true;\n    }\n}\n";

    #[test]
    fn s1698_ignores_overrider_without_comparisons() {
        let report = analyze_default(OVERRIDER);
        assert!(with_key(&report, "csharpsquid:S1698").is_empty());
    }

    #[test]
    fn s1698_ignores_types_without_equals_override() {
        let report = analyze_default(
            "class Plain\n{\n}\nvoid Check(Plain left, Plain right)\n{\n    var eq = left == right;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1698").is_empty());
    }

    #[test]
    fn s1698_flags_inequality_operator() {
        let report = analyze_default(&format!(
            "{OVERRIDER}void Check(Money left, Money right)\n{{\n    var ne = left != right;\n}}\n"
        ));
        let found = with_key(&report, "csharpsquid:S1698");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 10);
    }

    #[test]
    fn s1698_flags_each_comparison_at_its_own_line() {
        let report = analyze_default(&format!(
            "{OVERRIDER}void Check(Money left, Money right)\n{{\n    var eq = left == right;\n    var ne = left != right;\n}}\n"
        ));
        let found = with_key(&report, "csharpsquid:S1698");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 10);
        assert_eq!(found[1].range.start.line, 11);
    }

    #[test]
    fn s1698_ignores_member_access_and_invocation_operands() {
        let report = analyze_default(
            "class Money\n{\n    public override bool Equals(object other)\n    {\n        return true;\n    }\n    public int Value;\n}\nMoney Make() => new Money();\nvoid Check(Money left)\n{\n    var eq = left.Value == Make().Value;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1698").is_empty());
    }

    #[test]
    fn s1698_excludes_null_checks_and_overloaded_equality() {
        let report = analyze_default(
            "class Item\n\
             {\n\
                 public override bool Equals(object other) => true;\n\
                 public override int GetHashCode() => 1;\n\
                 public static bool operator ==(Item a, Item b) => true;\n\
                 public static bool operator !=(Item a, Item b) => false;\n\
             }\n\
             class C\n\
             {\n\
                 bool Null(Item value) => value == null;\n\
                 bool Equal(Item left, Item right) => left == right;\n\
             }\n",
        );
        assert!(with_key(&report, "csharpsquid:S1698").is_empty());
    }

    #[test]
    fn s1698_keeps_object_casts_out_of_identifier_subset() {
        let report = analyze_default(
            "class Item\n\
             {\n\
                 public override bool Equals(object other) => true;\n\
             }\n\
             class C\n\
             {\n\
                 bool Compare(Item left, Item right) => (object)left == (object)right;\n\
             }\n",
        );
        assert!(with_key(&report, "csharpsquid:S1698").is_empty());
    }

    #[test]
    fn s1698_excludes_mixed_object_casts_and_equals_body_comparisons() {
        let report = analyze_default(
            "class Item\n\
             {\n\
                 public override bool Equals(object other)\n\
                 {\n\
                     Item value = null;\n\
                     return value == other;\n\
                 }\n\
                 public override int GetHashCode() => 1;\n\
             }\n\
             class C\n\
             {\n\
                 bool Compare(Item left, Item right) => (object)left == right;\n\
             }\n",
        );
        assert!(with_key(&report, "csharpsquid:S1698").is_empty());
    }

    #[test]
    fn s1698_requires_an_applicable_operator_signature() {
        let report = analyze_default(
            "class Other { }\n\
             class Item\n\
             {\n\
                 public override bool Equals(object other) => true;\n\
                 public override int GetHashCode() => 0;\n\
                 public static bool operator ==(Item left, Other right) => true;\n\
                 public static bool operator !=(Item left, Other right) => false;\n\
             }\n\
             class Probe { bool Run(Item left, Item right) => left == right; }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1698").len(), 1);
    }

    #[test]
    fn s1698_does_not_cross_namespace_operator_owners() {
        let report = analyze_default(
            "namespace A\n\
             {\n\
                 class Item\n\
                 {\n\
                     public override bool Equals(object other) => true;\n\
                     public static bool operator ==(Item left, Item right) => true;\n\
                     public static bool operator !=(Item left, Item right) => false;\n\
                 }\n\
             }\n\
             namespace B\n\
             {\n\
                 class Item\n\
                 {\n\
                     public override bool Equals(object other) => true;\n\
                 }\n\
                 class Probe { bool Run(Item left, Item right) => left == right; }\n\
             }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1698").len(), 1);
    }

    #[test]
    fn s1698_keeps_custom_object_casts_reportable() {
        let report = analyze_default(
            "class Object { }\n\
             class Item\n\
             {\n\
                 public override bool Equals(object other) => true;\n\
                 public override int GetHashCode() => 0;\n\
             }\n\
             class Probe { bool Run(Item left, Item right) => (Object)left == right; }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1698").len(), 1);
    }

    #[test]
    fn s1698_checks_nested_callable_inside_equals() {
        let report = analyze_default(
            "class Item\n\
             {\n\
                 public override bool Equals(object other)\n\
                 {\n\
                     Item left = null, right = null;\n\
                     System.Func<bool> compare = () => left == right;\n\
                     return compare();\n\
                 }\n\
                 public override int GetHashCode() => 0;\n\
             }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1698").len(), 1);
    }
}
