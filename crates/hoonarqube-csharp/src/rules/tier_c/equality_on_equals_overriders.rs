use super::support::declared_type_names;
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of, simple_name,
};
use crate::rules::expressions::{binary_operands, member_declarations_of_kind};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::binary_operator;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1698 — `==`/`!=` on operands typed to a file-local class that
/// overrides `Equals`, where reference identity almost certainly is not the
/// intended comparison. Subset: identifier operands resolved through the
/// file-local declaration table.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const EQUALITY_OPERATORS: [&str; 2] = ["==", "!="];
    let types = declared_type_names(root, source);
    let overriders = equals_overriding_class_names(root, source);
    collect_kinds(root, &["binary_expression"])
        .into_iter()
        .filter(|comparison| !is_error_tainted(*comparison))
        .filter(|comparison| EQUALITY_OPERATORS.contains(&binary_operator(*comparison, source)))
        .filter(|comparison| {
            binary_operands(*comparison).is_some_and(|(left, right)| {
                [left, right].iter().any(|operand| {
                    operand.kind() == "identifier"
                        && types
                            .get(node_text(*operand, source))
                            .is_some_and(|declared| overriders.contains(simple_name(declared)))
                })
            })
        })
        .map(|comparison| {
            issue(
                language,
                "S1698",
                "Use 'Equals' instead of '=='; this type overrides equality semantics.",
                range_of(comparison),
            )
        })
        .collect()
}

/// File-local classes declaring an `Equals` override.
fn equals_overriding_class_names<'a>(
    root: Node<'a>,
    source: &'a str,
) -> std::collections::HashSet<&'a str> {
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
        .map(|name| node_text(name, source))
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
}
