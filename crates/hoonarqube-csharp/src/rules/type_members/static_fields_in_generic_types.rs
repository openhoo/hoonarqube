use super::support::static_field_declarators;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use crate::rules::modifiers::type_parameter_list_of;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2743 — static fields in generic types are not shared among
/// instances of different close constructed types; each instantiation gets
/// its own copy, which is almost never intended.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if type_parameter_list_of(type_node).is_none() {
            continue;
        }
        for declarator in static_field_declarators(type_node, source) {
            let Some(name_node) = declarator.child_by_field_name("name") else {
                continue;
            };
            issues.push(issue(
                language,
                "S2743",
                "A static field in a generic type is not shared among instances of different close constructed types.",
                range_of(name_node, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2743_readonly_static_fields_in_generic_types_are_reported() {
        let report = analyze_default(
            "public class G<T>\n{\n    private static readonly int Size = 4;\n    private static int plain;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2743");
        assert_eq!(flagged.len(), 2);
        let mut spots: Vec<_> = flagged
            .iter()
            .map(|issue| (issue.range.start.line, issue.range.start.column))
            .collect();
        spots.sort_unstable();
        assert_eq!(spots, vec![(3, 32), (4, 23)]);
        assert_eq!(
            flagged[0].message,
            "A static field in a generic type is not shared among instances of different close constructed types."
        );
    }

    #[test]
    fn s2743_nongeneric_instance_and_const_fields_are_not_reported() {
        let report = analyze_default(
            "public class N\n{\n    private static readonly int Size = 4;\n}\npublic class G<T>\n{\n    private int instance;\n    private const int Fixed = 3;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2743");
        assert_eq!(flagged.len(), 0);
    }
}
