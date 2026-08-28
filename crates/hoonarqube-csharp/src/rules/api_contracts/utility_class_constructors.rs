use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, range_of};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1118 — utility classes are reached through their static
/// members, not through instances.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_node) {
            continue;
        }
        let methods = member_declarations_of_kind(class_node, "method_declaration");
        if methods.is_empty()
            || !methods
                .iter()
                .all(|method| has_modifier(&modifiers_of(*method, source), "static"))
        {
            continue;
        }
        let fields_hold_state = type_members(class_node)
            .into_iter()
            .filter(|member| matches!(member.kind(), "field_declaration"))
            .any(|field| {
                let modifiers = modifiers_of(field, source);
                !has_modifier(&modifiers, "static") && !has_modifier(&modifiers, "const")
            });
        if fields_hold_state {
            continue;
        }
        for constructor in member_declarations_of_kind(class_node, "constructor_declaration") {
            let modifiers = modifiers_of(constructor, source);
            if has_modifier(&modifiers, "public") || has_modifier(&modifiers, "internal") {
                let name = constructor
                    .child_by_field_name("name")
                    .unwrap_or(constructor);
                issues.push(issue(
                    language,
                    "S1118",
                    "Hide this public constructor by making it 'protected'.",
                    range_of(name, source),
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
    fn s1118_flags_internal_constructors_in_const_only_utilities() {
        let report = analyze_default(
            "class Codec\n{\n    public const string Prefix = \"c\";\n    internal Codec() { }\n    public static void Run() { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1118");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
    }

    #[test]
    fn s1118_spares_stateful_classes_and_private_constructors() {
        let report = analyze_default(
            "class Cache\n{\n    int misses;\n    public Cache() { }\n    public static void Reset() { }\n}\n\nclass Hidden\n{\n    public static void Run() { }\n    private Hidden() { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1118").is_empty());
    }
}
