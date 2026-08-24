use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, node_text,
    parameters_of, range_of,
};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6424 — durable entity interface restrictions. Subset:
/// interfaces named `I…Entity` or deriving an `IDurableEntity…` interface
/// whose methods declare `ref`/`out` parameters; the remaining signature
/// restrictions (return shapes, generics) stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["interface_declaration"])
        .into_iter()
        .filter(|interface| !is_error_tainted(*interface))
        .filter(|interface| {
            let named_entity = interface.child_by_field_name("name").is_some_and(|name| {
                let text = node_text(name, source);
                text.starts_with('I') && text.ends_with("Entity")
            });
            named_entity
                || base_simple_names(*interface, source)
                    .iter()
                    .any(|base| base.starts_with("IDurableEntity"))
        })
        .flat_map(|interface| member_declarations_of_kind(interface, "method_declaration"))
        .filter(|method| {
            parameters_of(*method).iter().any(|parameter| {
                let modifiers = modifiers_of(*parameter, source);
                has_modifier(&modifiers, "ref") || has_modifier(&modifiers, "out")
            })
        })
        .filter_map(|method| method.child_by_field_name("name"))
        .map(|name| {
            issue(
                language,
                "S6424",
                "Durable entity interface methods cannot use 'ref' or 'out' parameters.",
                range_of(name),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6424_idurable_entity_base_gate_flags_ref_params_without_entity_name() {
        let report = analyze_default(
            "interface IRepository : IDurableEntity\n{\n    void Reload(ref int key);\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6424");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s6424_plain_interfaces_with_ref_params_stay_out_of_scope() {
        let report =
            analyze_default("interface IRepository\n{\n    void Reload(ref int key);\n}\n");
        assert!(with_key(&report, "csharpsquid:S6424").is_empty());
    }

    #[test]
    fn s6424_in_parameters_are_not_restricted_by_this_subset() {
        let report = analyze_default(
            "interface ICartEntity\n{\n    void Push(in int value);\n    void Add(int value);\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6424").is_empty());
    }

    #[test]
    fn s6424_flags_each_offending_method_distinctly() {
        let report = analyze_default(
            "interface ICartEntity\n{\n    void Save(out int id);\n    void Load();\n    void Move(ref int position);\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6424");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 5);
    }

    #[test]
    fn s6424_entity_named_interfaces_without_ref_out_stay_clean() {
        let report = analyze_default("interface ICartEntity\n{\n    void Add(int value);\n}\n");
        assert!(with_key(&report, "csharpsquid:S6424").is_empty());
    }
}
