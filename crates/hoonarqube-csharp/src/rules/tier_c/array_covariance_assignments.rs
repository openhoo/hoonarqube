use super::support::{graph_reaches, local_inheritance_graph};
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::creation_type_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2330 — array covariance assignments between file-local
/// element-type hierarchies (`Animal[] a = new Dog[2];`). Subset:
/// declarations only; assignments to previously declared arrays stay out.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let graph = local_inheritance_graph(root, source);
    collect_kinds(root, &["variable_declaration"])
        .into_iter()
        .filter(|declaration| !is_error_tainted(*declaration))
        .filter_map(move |declaration| {
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
                    && graph_reaches(&graph, created, |current| current == element);
                if covariant {
                    return declarator.child_by_field_name("name");
                }
            }
            None
        })
        .map(|name| {
            issue(
                language,
                "S2330",
                "Avoid array covariance here; use an explicitly typed array or a common generic collection.",
                range_of(name, source),
            )
        })
        .collect()
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
