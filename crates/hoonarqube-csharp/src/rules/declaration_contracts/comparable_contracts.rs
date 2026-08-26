use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{overloaded_operators, overridden_names};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1210 — `IComparable` implementations owe callers `Equals`
/// and the comparison operators.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let comparable = base_simple_names(type_node, source)
            .iter()
            .any(|base| base.starts_with("IComparable"));
        if !comparable {
            continue;
        }
        let has_equals = overridden_names(type_node, source).contains("Equals");
        let has_comparison = overloaded_operators(type_node)
            .iter()
            .any(|operator| matches!(*operator, "<" | "<=" | ">" | ">="));
        if !has_equals || !has_comparison {
            issues.push(issue(
                language,
                "S1210",
                "Implement Equals and the comparison operators alongside IComparable.",
                range_of(name_anchor(type_node), source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1210_equals_alone_does_not_satisfy_the_contract() {
        let report = analyze_default(
            "class Temp : IComparable<Temp>\n{\n    public int value;\n\n    public int CompareTo(Temp other) => value.CompareTo(other.value);\n\n    public override bool Equals(object obj) => obj is Temp other && value == other.value;\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1210").len(), 1);
    }

    #[test]
    fn s1210_types_without_icomparable_are_out_of_scope() {
        let report =
            analyze_default("class Plain\n{\n    public int CompareTo(Plain other) => 0;\n}\n");
        assert!(with_key(&report, "csharpsquid:S1210").is_empty());
    }
}
