use super::support::declared_type_names;
use super::support::is_predefined_value_type_text;
use crate::CsLanguage;
use crate::cst::{
    ancestors_of, canonical_identifier, collect_kinds, containing_namespace, is_error_tainted,
    issue, node_text, range_of, simple_name,
};
use crate::rules::expressions::{
    callee_name, enclosing_callable, enclosing_type, invocation_arguments, invocation_function,
};
use crate::rules::literals::argument_expression;
use crate::rules::naming::{TYPE_DECLARATION_KINDS, type_members};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

fn normalized_type_name(text: &str) -> String {
    let mut text = text.trim().replace(' ', "");
    if let Some(index) = text.find('<') {
        text.truncate(index);
    }
    text.trim_end_matches('?').to_string()
}

fn using_directive_text<'a>(using: Node<'_>, source: &'a str) -> &'a str {
    node_text(using, source)
        .trim()
        .trim_end_matches(';')
        .trim()
        .trim_start_matches("global")
        .trim()
        .trim_start_matches("using")
        .trim()
}

fn using_applies(using: Node<'_>, use_site: Node<'_>, source: &str) -> bool {
    let using_namespace = containing_namespace(using, source);
    using_namespace.is_empty() || using_namespace == containing_namespace(use_site, source)
}

fn using_alias_target(
    root: Node<'_>,
    use_site: Node<'_>,
    alias: &str,
    target: &str,
    source: &str,
) -> bool {
    let target = normalized_type_name(target);
    let target = target.strip_prefix("global::").unwrap_or(&target);
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .filter(|using| using_applies(*using, use_site, source))
        .any(|using| {
            let text = using_directive_text(using, source);
            let Some((left, right)) = text.split_once('=') else {
                return false;
            };
            let actual = normalized_type_name(right);
            let actual = actual.strip_prefix("global::").unwrap_or(&actual);
            canonical_identifier(left.trim()) == canonical_identifier(alias) && actual == target
        })
}

fn has_using_alias(root: Node<'_>, use_site: Node<'_>, alias: &str, source: &str) -> bool {
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .filter(|using| using_applies(*using, use_site, source))
        .any(|using| {
            using_directive_text(using, source)
                .split_once('=')
                .is_some_and(|(left, _)| canonical_identifier(left.trim()) == alias)
        })
}

fn has_system_import(root: Node<'_>, use_site: Node<'_>, source: &str) -> bool {
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .filter(|using| using_applies(*using, use_site, source))
        .any(|using| using_directive_text(using, source) == "System")
        || containing_namespace(use_site, source) == "System"
}

fn source_declares_simple_type(
    root: Node<'_>,
    wanted: &str,
    use_site: Node<'_>,
    source: &str,
) -> bool {
    let namespace = containing_namespace(use_site, source);
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter(|declaration| containing_namespace(*declaration, source) == namespace)
        .filter_map(|declaration| declaration.child_by_field_name("name"))
        .any(|name| canonical_identifier(node_text(name, source)) == wanted)
}

fn is_object_receiver(root: Node<'_>, call: Node<'_>, receiver: Node<'_>, source: &str) -> bool {
    let raw = normalized_type_name(node_text(receiver, source));
    if raw == "object" {
        return true;
    }
    if raw == "global::System.Object" {
        return true;
    }
    if raw == "System.Object" {
        return !has_using_alias(root, call, "System", source);
    }
    if raw == "Object" {
        if using_alias_target(root, call, "Object", "System.Object", source) {
            return true;
        }
        return has_system_import(root, call, source)
            && !has_using_alias(root, call, "Object", source)
            && !source_declares_simple_type(root, "Object", call, source);
    }
    receiver.kind() == "identifier"
        && using_alias_target(
            root,
            call,
            canonical_identifier(node_text(receiver, source)),
            "System.Object",
            source,
        )
}

fn bare_reference_equals_is_framework(call: Node<'_>, source: &str) -> bool {
    if enclosing_type(call).is_some_and(|owner| {
        type_members(owner).into_iter().any(|member| {
            member.kind() == "method_declaration"
                && member.child_by_field_name("name").is_some_and(|name| {
                    canonical_identifier(node_text(name, source)) == "ReferenceEquals"
                })
        })
    }) {
        return false;
    }
    let Some(callable) = ancestors_of(call).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "method_declaration"
                | "local_function_statement"
                | "lambda_expression"
                | "anonymous_method_expression"
        )
    }) else {
        return true;
    };
    !collect_kinds(
        callable,
        &[
            "parameter",
            "variable_declarator",
            "local_function_statement",
        ],
    )
    .into_iter()
    .filter(|declaration| enclosing_callable(*declaration) == Some(callable))
    .any(|declaration| {
        declaration.start_byte() < call.start_byte()
            && declaration.child_by_field_name("name").is_some_and(|name| {
                canonical_identifier(node_text(name, source)) == "ReferenceEquals"
            })
    })
}

fn is_value_type_declaration(declaration: Node<'_>) -> bool {
    if declaration.kind() == "struct_declaration" {
        return true;
    }
    if declaration.kind() != "record_declaration" {
        return false;
    }
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .any(|child| child.kind() == "struct")
}

fn is_object_reference_equals(root: Node<'_>, call: Node<'_>, source: &str) -> bool {
    let Some(function) = invocation_function(call) else {
        return false;
    };
    if callee_name(call, source) != Some("ReferenceEquals") {
        return false;
    }
    if function.kind() == "member_access_expression" {
        return function
            .child_by_field_name("expression")
            .or_else(|| function.child(0))
            .is_some_and(|receiver| is_object_receiver(root, call, receiver, source));
    }
    function.kind() == "identifier" && bare_reference_equals_is_framework(call, source)
}

/// csharpsquid:S2995 — 'Object.ReferenceEquals' called with value-typed
/// arguments, where it can only ever return false.  The target is resolved to
/// the framework method before argument types are inspected.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const VALUE_LITERALS: [&str; 4] = [
        "integer_literal",
        "real_literal",
        "boolean_literal",
        "character_literal",
    ];
    let types = declared_type_names(root, source);
    let structs: std::collections::HashSet<&str> =
        collect_kinds(root, &["struct_declaration", "record_declaration"])
            .into_iter()
            .filter(|declaration| is_value_type_declaration(*declaration))
            .filter_map(|declaration| declaration.child_by_field_name("name"))
            .map(|name| canonical_identifier(node_text(name, source)))
            .collect();
    let value_typed = |operand: Node<'_>| -> bool {
        if operand.kind() != "identifier" {
            return false;
        }
        let name = canonical_identifier(node_text(operand, source));
        types
            .get(name)
            .or_else(|| {
                types
                    .iter()
                    .find(|(declared, _)| canonical_identifier(declared) == name)
                    .map(|(_, ty)| ty)
            })
            .is_some_and(|declared| {
                is_predefined_value_type_text(declared) || structs.contains(simple_name(declared))
            })
    };
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| is_object_reference_equals(root, *call, source))
        .filter(|call| invocation_arguments(*call).len() == 2)
        .filter(|call| {
            let expressions: Vec<Node<'_>> = invocation_arguments(*call)
                .into_iter()
                .map(argument_expression)
                .collect();
            expressions
                .iter()
                .any(|argument| VALUE_LITERALS.contains(&argument.kind()) || value_typed(*argument))
        })
        .map(|call| {
            issue(
                language,
                "S2995",
                "Use a different kind of comparison for these value types.",
                range_of(invocation_function(call).unwrap_or(call), source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2995_minimal_input_emits_nothing() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S2995").is_empty());
    }

    #[test]
    fn s2995_flags_numeric_literal_pair() {
        let report = analyze_default("var same = ReferenceEquals(1, 2);\n");
        let flagged = with_key(&report, "csharpsquid:S2995");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s2995_flags_boolean_and_character_literals() {
        let report = analyze_default("var equal = ReferenceEquals('x', true);\n");
        let flagged = with_key(&report, "csharpsquid:S2995");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s2995_mixed_value_and_reference_identifiers_are_flagged() {
        let report = analyze_default(
            "struct Point\n{\n}\nclass Box\n{\n}\nvoid Compare(Point point, Box box)\n{\n    var mixed = ReferenceEquals(point, box);\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2995").len(), 1);
    }

    #[test]
    fn s2995_boundary_wrong_arity_calls_are_not_flagged() {
        let report = analyze_default(
            "var one = ReferenceEquals(single);\nvar three = ReferenceEquals(a, b, extra);\n",
        );
        assert!(with_key(&report, "csharpsquid:S2995").is_empty());
    }

    #[test]
    fn s2995_flags_struct_pair_and_literal_pair_on_distinct_lines() {
        let report = analyze_default(
            "struct Pair\n{\n}\nvoid Check(Pair left, Pair right)\n{\n    var structs = ReferenceEquals(left, right);\n    var literals = ReferenceEquals(3, 4);\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2995");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 6);
        assert_eq!(flagged[1].range.start.line, 7);
    }

    #[test]
    fn s2995_binds_object_reference_equals_and_accepts_one_value_argument() {
        let report = analyze_default(
            "using ObjectAlias = System.Object;\n\
             class FakeObject { public static bool ReferenceEquals(int a, int b) => a == b; }\n\
             class C\n\
             {\n\
                 bool Alias(int value, object other) => ObjectAlias.ReferenceEquals(value, other);\n\
                 bool Fake() => FakeObject.ReferenceEquals(1, 2);\n\
             }\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2995");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s2995_does_not_treat_same_named_member_as_object_api() {
        let report = analyze_default(
            "class C\n\
             {\n\
                 static bool ReferenceEquals(int a, int b) => a == b;\n\
                 bool Run() => ReferenceEquals(1, 2);\n\
             }\n",
        );
        assert!(with_key(&report, "csharpsquid:S2995").is_empty());
    }

    #[test]
    fn s2995_flags_mixed_literal_and_reference_arguments() {
        let report = analyze_default(
            "class C\n\
             {\n\
                 bool Run(int value, object other) => object.ReferenceEquals(value, other);\n\
             }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2995").len(), 1);
    }

    #[test]
    fn s2995_global_object_ignores_unrelated_object_declarations() {
        let report = analyze_default(
            "namespace Fake { class Object { } }\n\
             class Probe { bool Run() => global::System.Object.ReferenceEquals(1, 2); }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2995").len(), 1);
    }

    #[test]
    fn s2995_respects_local_reference_equals_binding() {
        let report = analyze_default(
            "class C\n\
             {\n\
                 bool Run()\n\
                 {\n\
                     bool ReferenceEquals(int left, int right) => left == right;\n\
                     return ReferenceEquals(1, 2);\n\
                 }\n\
             }\n",
        );
        assert!(with_key(&report, "csharpsquid:S2995").is_empty());
    }
    #[test]
    fn s2995_flags_record_struct_value_arguments() {
        let report = analyze_default(
            "record struct Point(int X);\n\
             class C { bool Run(Point left, Point right) => ReferenceEquals(left, right); }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2995").len(), 1);
    }
}
