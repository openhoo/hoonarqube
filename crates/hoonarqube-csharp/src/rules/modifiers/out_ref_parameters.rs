use super::support::{accessibility_rank, has_modifier};
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, parameters_of, range_of};
use crate::rules::naming::has_explicit_interface_specifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3874 — `out`/`ref` parameters obscure data flow; overrides
/// must mirror their base signature, so they stay untouched.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let modifiers = modifiers_of(method, source);
        if has_modifier(&modifiers, "override") || has_explicit_interface_specifier(method) {
            continue;
        }
        if accessibility_rank(&modifiers) != 6 {
            continue;
        }
        for parameter in parameters_of(method) {
            let parameter_modifiers = modifiers_of(parameter, source);
            for modifier_kind in ["out", "ref"] {
                if has_modifier(&parameter_modifiers, modifier_kind) {
                    let mut cursor = parameter.walk();
                    let modifier = parameter
                        .children(&mut cursor)
                        .find(|child| {
                            child.kind() == "modifier" && node_text(*child, source) == modifier_kind
                        })
                        .unwrap_or(parameter);
                    issues.push(issue(
                        language,
                        "S3874",
                        format!("Consider refactoring this method in order to remove the need for this '{modifier_kind}' modifier."),
                        range_of(modifier, source),
                    ));
                }
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3874_anchors_modifier_after_attribute_text_containing_ref() {
        let report = analyze_default(
            "public class C\n{\n    public void M([refMarker] ref int value) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3874");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.column, 30);
        assert_eq!(flagged[0].range.end.column, 33);
    }
}
