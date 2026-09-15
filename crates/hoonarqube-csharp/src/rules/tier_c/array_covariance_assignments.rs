use super::support::{graph_reaches, local_inheritance_graph};
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::creation_type_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2330 — array covariance assignments between file-local
/// element-type hierarchies (`Animal[] a = new Dog[2];`), plus
/// `ToArray()` results stored into `object[]` targets, the conversion
/// the reference flags on real code. Assignments to previously declared
/// arrays stay out beyond the `ToArray` facet.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let graph = local_inheritance_graph(root, source);
    let mut issues: Vec<Issue> = collect_kinds(root, &["variable_declaration"])
        .into_iter()
        .filter(|declaration| !is_error_tainted(*declaration))
        .filter_map(|declaration| {
            let type_node = declaration.child_by_field_name("type")?;
            if type_node.kind() != "array_type" {
                return None;
            }
            let element = simple_name(node_text(type_node, source).split('[').next()?);
            for declarator in collect_kinds(declaration, &["variable_declarator"]) {
                let Some(value) = collect_kinds(declarator, &["array_creation_expression"])
                    .into_iter()
                    .next()
                else {
                    continue;
                };
                let created = simple_name(creation_type_text(value, source).split('[').next()?);
                let covariant = created != element
                    && graph_reaches(&graph, &created, |current| *current == element);
                if covariant {
                    return Some(value);
                }
            }
            None
        })
        .map(|value| {
            issue(
                language,
                "S2330",
                "Refactor the code to not rely on potentially unsafe array conversions.",
                range_of(value, source),
            )
        })
        .collect();
    issues.extend(to_array_into_object_array_issues(root, source, language));
    issues
}

/// `x = collection.ToArray()` stores a `T[]` into an `object[]` slot —
/// the same covariant conversion the declaration facet flags, with the
/// element type proven by the receiver's `List<T>`/`IEnumerable<T>`
/// declaration in the same file. Only `object` targets are provably
/// covariant without a type graph.
fn to_array_into_object_array_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let object_arrays = object_array_names(root, source);
    if object_arrays.is_empty() {
        return Vec::new();
    }
    let list_elements = list_element_types(root, source);
    let mut issues = Vec::new();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if is_error_tainted(assignment) {
            continue;
        }
        let Some((left, right)) = crate::rules::expressions::binary_operands(assignment) else {
            continue;
        };
        if crate::rules::expressions::operator_of(assignment) != Some("=") {
            continue;
        }
        let target = assignment_target_name(left, source);
        if !target.is_some_and(|name| object_arrays.contains(name)) {
            continue;
        }
        if right.kind() != "invocation_expression"
            || crate::rules::expressions::callee_name(right, source) != Some("ToArray")
        {
            continue;
        }
        let Some(receiver) = crate::rules::expressions::invocation_receiver(right) else {
            continue;
        };
        let Some(element) = list_elements.get(node_text(receiver, source)) else {
            continue;
        };
        if !is_reference_element(element) {
            continue;
        }
        issues.push(issue(
            language,
            "S2330",
            "Refactor the code to not rely on potentially unsafe array conversions.",
            range_of(right, source),
        ));
    }
    issues
}

/// The plain identifier an assignment writes to (`x = …` or `this.x = …`).
fn assignment_target_name<'a>(left: Node<'_>, source: &'a str) -> Option<&'a str> {
    match left.kind() {
        "identifier" => Some(node_text(left, source)),
        "member_access_expression" => left
            .child_by_field_name("name")
            .map(|name| node_text(name, source)),
        _ => None,
    }
}

/// Field and local names declared `object[]` (or `dynamic[]`) in this file.
fn object_array_names<'t>(root: Node<'t>, source: &'t str) -> std::collections::HashSet<&'t str> {
    let mut names = std::collections::HashSet::new();
    for declaration in collect_kinds(root, &["variable_declaration"]) {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(type_node) = declaration.child_by_field_name("type") else {
            continue;
        };
        if type_node.kind() != "array_type" {
            continue;
        }
        let element = node_text(type_node, source)
            .split('[')
            .next()
            .map_or("", str::trim);
        if !matches!(element, "object" | "dynamic" | "System.Object") {
            continue;
        }
        for declarator in collect_kinds(declaration, &["variable_declarator"]) {
            if let Some(name) = declarator.child_by_field_name("name") {
                names.insert(node_text(name, source));
            }
        }
    }
    names
}

/// Element types of file-local `List<T>`/`IEnumerable<T>`-shaped
/// declarations, keyed by variable name. `var` declarators resolve
/// through a `new List<T>(…)` initializer, the only inferable shape.
fn list_element_types<'t>(
    root: Node<'t>,
    source: &'t str,
) -> std::collections::HashMap<&'t str, &'t str> {
    let mut elements = std::collections::HashMap::new();
    for declaration in collect_kinds(root, &["variable_declaration"]) {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(type_node) = declaration.child_by_field_name("type") else {
            continue;
        };
        let spelled = node_text(type_node, source).trim() != "var";
        for declarator in collect_kinds(declaration, &["variable_declarator"]) {
            let element = if spelled {
                generic_element_of(type_node, source)
            } else {
                collect_kinds(declarator, &["object_creation_expression"])
                    .into_iter()
                    .next()
                    .and_then(|creation| {
                        creation
                            .child_by_field_name("type")
                            .and_then(|created| generic_element_of(created, source))
                    })
            };
            let (Some(element), Some(name)) = (element, declarator.child_by_field_name("name"))
            else {
                continue;
            };
            elements.insert(node_text(name, source), element);
        }
    }
    elements
}

/// The single type argument of a `List<T>`/`IEnumerable<T>`-shaped
/// generic type spelling.
fn generic_element_of<'a>(type_node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let text = node_text(type_node, source);
    let inner = text.split('<').nth(1)?.split('>').next()?.trim();
    let outer = simple_name(text.split('<').next()?.trim());
    matches!(
        outer,
        "List"
            | "IList"
            | "IEnumerable"
            | "ICollection"
            | "IReadOnlyList"
            | "IReadOnlyCollection"
            | "HashSet"
            | "ISet"
    )
    .then_some(inner)
}
/// Array covariance only exists between distinct reference types, so
/// value-type elements and `object` itself (an identity conversion into
/// `object[]`) stay silent.
fn is_reference_element(element: &str) -> bool {
    !matches!(
        element,
        "object"
            | "dynamic"
            | "System.Object"
            | "bool"
            | "byte"
            | "sbyte"
            | "short"
            | "ushort"
            | "int"
            | "uint"
            | "long"
            | "ulong"
            | "char"
            | "float"
            | "double"
            | "decimal"
            | "nint"
            | "nuint"
            | "DateTime"
            | "TimeSpan"
            | "Guid"
    ) && !element.ends_with('?')
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2330_ignores_sources_without_array_declarations() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S2330").is_empty());
    }

    #[test]
    fn s2330_ignores_matching_element_types() {
        let report =
            analyze_default("class Dog\n{\n}\nvoid Kennel()\n{\n    Dog[] pack = new Dog[2];\n}\n");
        assert!(with_key(&report, "csharpsquid:S2330").is_empty());
    }

    #[test]
    fn s2330_ignores_unrelated_element_hierarchies() {
        let report = analyze_default(
            "class Rock\n{\n}\nclass Tree\n{\n}\nvoid Grove()\n{\n    Tree[] grove = new Rock[2];\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2330").is_empty());
    }

    #[test]
    fn s2330_flags_transitive_base_element_types() {
        let report = analyze_default(
            "class Animal\n{\n}\nclass Pet : Animal\n{\n}\nclass Dog : Pet\n{\n}\nvoid Kennel()\n{\n    Animal[] pack = new Dog[2];\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S2330");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 12);
    }

    #[test]
    fn s2330_ignores_contravariant_directions() {
        let report = analyze_default(
            "class Animal\n{\n}\nclass Dog : Animal\n{\n}\nvoid Kennel()\n{\n    Dog[] pack = new Animal[2];\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2330").is_empty());
    }

    #[test]
    fn s2330_ignores_reassignment_after_declaration() {
        let report = analyze_default(
            "class Animal\n{\n}\nclass Dog : Animal\n{\n}\nvoid Kennel()\n{\n    Animal[] pack = new Animal[2];\n    pack = new Dog[2];\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2330").is_empty());
    }

    #[test]
    fn s2330_reports_first_covariant_declarator_per_declaration() {
        let report = analyze_default(
            "class Animal\n{\n}\nclass Dog : Animal\n{\n}\nvoid Kennel()\n{\n    Animal[] left = new Dog[2], right = new Dog[2];\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S2330");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 9);
    }

    #[test]
    fn s2330_flags_each_violation_at_its_own_line() {
        let report = analyze_default(
            "class Animal\n{\n}\nclass Dog : Animal\n{\n}\nvoid Kennel()\n{\n    Animal[] pack = new Dog[2];\n    Animal[] herd = new Dog[3];\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S2330");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 9);
        assert_eq!(found[1].range.start.line, 10);
    }
}
