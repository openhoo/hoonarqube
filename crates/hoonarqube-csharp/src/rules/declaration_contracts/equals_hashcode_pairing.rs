use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{member_named, overridden_names};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1206 — overriding only one of `Equals`/`GetHashCode` breaks
/// hash-based collections.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let overrides = overridden_names(type_node, source);
        for lone in ["Equals", "GetHashCode"] {
            let partner = if lone == "Equals" {
                "GetHashCode"
            } else {
                "Equals"
            };
            if overrides.contains(lone)
                && !overrides.contains(partner)
                && member_named(type_node, "method_declaration", lone, source).is_some()
            {
                let type_name = type_node.child_by_field_name("name").unwrap_or(type_node);
                issues.push(issue(
                    language,
                    "S1206",
                    format!(
                        "This {} overrides '{lone}' and should therefore also override '{partner}'.",
                        if type_node.kind() == "struct_declaration" { "struct" } else { "class" }
                    ),
                    range_of(type_name, source),
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
    fn s1206_flags_lone_gethashcode_overrides_too() {
        let report =
            analyze_default("struct Key\n{\n    public override int GetHashCode() => 7;\n}\n");
        let flagged = with_key(&report, "csharpsquid:S1206");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("also override 'Equals'"));
    }

    #[test]
    fn s1206_counts_each_incomplete_type_separately() {
        let report = analyze_default(
            "class First\n{\n    public override bool Equals(object obj) => true;\n}\n\nclass Second\n{\n    public override int GetHashCode() => 1;\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1206").len(), 2);
    }
}
