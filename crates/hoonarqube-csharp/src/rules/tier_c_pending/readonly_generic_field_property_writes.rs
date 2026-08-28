use super::support::member_declared_type;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::{expression_name, first_named_child};
use crate::rules::logging::field_declarator_names;
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::type_members;
use crate::rules::usage_analysis::unconstrained_generic_parameters;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2934 — property writes through `readonly` fields typed by an
/// unconstrained generic parameter. Subset: assignment expressions whose
/// left side is a property of such a field, inside the declaring type;
/// `class`/`struct`/`notnull`-constrained parameters and non-generic
/// readonly fields stay clean.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declaration in collect_kinds(
        root,
        &[
            "class_declaration",
            "struct_declaration",
            "record_declaration",
        ],
    ) {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(unconstrained) = unconstrained_generic_parameters(declaration, source) else {
            continue;
        };
        let readonly_fields: std::collections::HashSet<&str> = type_members(declaration)
            .into_iter()
            .filter(|member| {
                member.kind() == "field_declaration"
                    && has_modifier(&modifiers_of(*member, source), "readonly")
            })
            .filter(|member| {
                member_declared_type(*member)
                    .is_some_and(|type_node| unconstrained.contains(node_text(type_node, source)))
            })
            .flat_map(|member| field_declarator_names(member, source))
            .collect();
        if readonly_fields.is_empty() {
            continue;
        }
        for assignment in collect_kinds(declaration, &["assignment_expression"]) {
            if is_error_tainted(assignment) {
                continue;
            }
            let Some(left) = first_named_child(assignment) else {
                continue;
            };
            if left.kind() != "member_access_expression" {
                continue;
            }
            let Some(object) = first_named_child(left) else {
                continue;
            };
            let written = match object.kind() {
                "identifier" => Some(node_text(object, source)),
                "member_access_expression" => expression_name(object, source),
                _ => None,
            };
            if written.is_some_and(|name| readonly_fields.contains(name)) {
                let field_name = written.unwrap_or("field");
                let property_name = expression_name(left, source).unwrap_or("property");
                issues.push(issue(
                    language,
                    "S2934",
                    format!(
                        "Restrict '{field_name}' to be a reference type or remove this assignment of '{property_name}'; it is useless if '{field_name}' is a value type."
                    ),
                    range_of(left, source),
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2934_flags_each_property_write_through_readonly_generic_field() {
        let report = analyze_default(
            "class Box<T>\n{\n    private readonly T value;\n    public void Reset()\n    {\n        value.Count = 0;\n        value.Name = \"x\";\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2934");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 6);
        assert_eq!(flagged[1].range.start.line, 7);
    }

    #[test]
    fn s2934_this_qualified_receiver_is_still_flagged() {
        let report = analyze_default(
            "class Box<T>\n{\n    private readonly T value;\n    public void Reset()\n    {\n        this.value.Count = 0;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2934");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }

    #[test]
    fn s2934_record_declarations_are_checked_too() {
        let report = analyze_default(
            "record Box<T>\n{\n    private readonly T value;\n    public void Reset()\n    {\n        value.Count = 0;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2934");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }

    #[test]
    fn s2934_struct_constrained_parameters_stay_clean() {
        let report = analyze_default(
            "struct Pair<T>\n    where T : struct\n{\n    private readonly T value;\n    public void Reset()\n    {\n        value.Count = 0;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2934").is_empty());
    }

    #[test]
    fn s2934_non_generic_readonly_fields_are_not_in_scope() {
        let report = analyze_default(
            "class Store\n{\n    private readonly FileStream stream;\n    public void Reset()\n    {\n        stream.Name = \"x\";\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2934").is_empty());
    }

    #[test]
    fn s2934_plain_identifier_assignment_is_not_a_property_write() {
        let report = analyze_default(
            "class Box<T>\n{\n    private readonly T value;\n    public void Reset()\n    {\n        value = default;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2934").is_empty());
    }
}
