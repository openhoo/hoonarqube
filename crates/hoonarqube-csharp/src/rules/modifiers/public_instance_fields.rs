use super::support::{field_declarators, has_modifier};
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use crate::rules::expressions::enclosing_type;
use crate::rules::modifiers::type_declared_rank;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1104 — publicly accessible instance fields break
/// encapsulation; static and constant members belong to S2223 and S2339.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        if has_modifier(&modifiers, "public")
            && !has_modifier(&modifiers, "static")
            && !has_modifier(&modifiers, "const")
            && !has_modifier(&modifiers, "readonly")
            && enclosing_type(field)
                .is_some_and(|type_node| type_declared_rank(type_node, source) == 6)
        {
            for declarator in field_declarators(field) {
                let name = declarator.child_by_field_name("name").unwrap_or(declarator);
                let range = if declarator.named_child_count().gt(&1) {
                    range_of(declarator, source)
                } else {
                    range_of(name, source)
                };
                issues.push(issue(
                    language,
                    "S1104",
                    "Make this field 'private' and encapsulate it in a 'public' property.",
                    range,
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
    fn s1104_does_not_report_locals_inside_field_initializer_lambdas() {
        let report = analyze_default(
            "public class C\n{\n    public System.Func<int> Factory = () =>\n    {\n        int local = 1;\n        return local;\n    };\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1104");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s1104_public_readonly_instance_fields_are_not_reported() {
        let report = analyze_default(
            "public class C\n{\n    public readonly int Id = 1;\n    public readonly int A = 2, B = 3;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1104");
        assert_eq!(flagged.len(), 0);
    }

    #[test]
    fn s1104_genuinely_mutable_public_instance_field_is_still_reported() {
        let report = analyze_default(
            "public class C\n{\n    public int Count;\n    public static int Shared;\n    public const int Fixed = 1;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1104");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[0].range.start.column, 15);
        assert_eq!(
            flagged[0].message,
            "Make this field 'private' and encapsulate it in a 'public' property."
        );
    }
}
