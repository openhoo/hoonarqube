use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of, simple_name,
};
use crate::rules::expressions::first_named_child;
use crate::rules::literals::declarator_initializer;
use crate::rules::modifiers::{has_any_accessibility, has_modifier};
use crate::rules::type_members::is_literal_node;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3887 — public readonly primitive literals are constants.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        if is_error_tainted(field) {
            continue;
        }
        let modifiers = modifiers_of(field, source);
        if !has_modifier(&modifiers, "readonly")
            || has_modifier(&modifiers, "static")
            || has_modifier(&modifiers, "const")
            || !has_any_accessibility(&modifiers)
            || has_modifier(&modifiers, "private")
        {
            continue;
        }
        let typed_primitive = collect_kinds(field, &["variable_declaration"])
            .first()
            .and_then(|declaration| first_named_child(*declaration))
            .is_some_and(|type_node| {
                PRIMITIVE_FIELD_TYPES.contains(&simple_name(node_text(type_node, source)))
            });
        if !typed_primitive {
            continue;
        }
        let literal_initialized =
            collect_kinds(field, &["variable_declarator"])
                .iter()
                .all(|declarator| {
                    declarator
                        .child_by_field_name("name")
                        .and_then(|name| declarator_initializer(*declarator, name))
                        .is_some_and(is_literal_node)
                });
        if literal_initialized {
            issues.push(issue(
                language,
                "S3887",
                "Declare this constant field 'const' instead of 'readonly'.",
                range_of(field),
            ));
        }
    }
    issues
}

/// Built-in types whose readonly fields read as constants.
const PRIMITIVE_FIELD_TYPES: [&str; 13] = [
    "int", "uint", "long", "ulong", "short", "ushort", "byte", "sbyte", "char", "bool", "double",
    "float", "decimal",
];

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3887_flags_protected_and_internal_readonly_literals() {
        let report = analyze_default(
            "class A\n{\n    protected readonly bool enabled = true;\n    internal readonly decimal rate = 1.5m;\n    public const int fixedValue = 3;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3887");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 4);
    }

    #[test]
    fn s3887_requires_literal_initializers_on_every_declarator() {
        let report = analyze_default(
            "class A\n{\n    public readonly int computed = Compute();\n    public readonly int unset;\n    public readonly int first = 1, second = Compute();\n    public readonly char letter = 'a', digit = '7';\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3887");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }
}
