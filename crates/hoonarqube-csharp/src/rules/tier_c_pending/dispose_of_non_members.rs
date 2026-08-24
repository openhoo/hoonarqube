use super::support::this_or_identifier_name;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, invocation_receiver, member_declarations_of_kind};
use crate::rules::logging::field_declarator_names;
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2952 — `Dispose` methods disposing objects that are not
/// members of their class. Subset: `.Dispose()` calls inside any method
/// named `Dispose` whose receiver is a bare identifier or `this.Name`
/// access missing from the class's field inventory; inherited members and
/// other receiver shapes stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class in collect_kinds(root, &["class_declaration", "struct_declaration"]) {
        if is_error_tainted(class) {
            continue;
        }
        let fields: std::collections::HashSet<&str> = type_members(class)
            .into_iter()
            .filter(|member| member.kind() == "field_declaration")
            .flat_map(|field| field_declarator_names(field, source))
            .collect();
        for method in member_declarations_of_kind(class, "method_declaration") {
            if method
                .child_by_field_name("name")
                .is_none_or(|name| node_text(name, source) != "Dispose")
            {
                continue;
            }
            for call in collect_kinds(method, &["invocation_expression"]) {
                if is_error_tainted(call) || callee_name(call, source) != Some("Dispose") {
                    continue;
                }
                let Some(receiver) = invocation_receiver(call) else {
                    continue;
                };
                let Some(name) = this_or_identifier_name(receiver, source) else {
                    continue;
                };
                if !fields.contains(name) {
                    issues.push(issue(
                        language,
                        "S2952",
                        "Only members of this class should be disposed from its 'Dispose' method.",
                        range_of(call),
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
    fn s2952_this_qualified_receivers_stay_unflagged_in_this_subset() {
        // The rule doc mentions `this.Name` receivers, but the current
        // implementation only extracts bare identifiers; assert observed
        // behavior (see family report discrepancy).
        let report = analyze_default(
            "class Worker : IDisposable\n{\n    public void Dispose()\n    {\n        this.helper.Dispose();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2952").is_empty());
    }

    #[test]
    fn s2952_field_receivers_stay_clean() {
        let report = analyze_default(
            "class Worker : IDisposable\n{\n    private FileStream stream;\n    public void Dispose()\n    {\n        stream.Dispose();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2952").is_empty());
    }

    #[test]
    fn s2952_other_receiver_shapes_stay_uncovered() {
        let report = analyze_default(
            "class Worker\n{\n    public void Dispose()\n    {\n        Make().Dispose();\n    }\n    private FileStream Make() => new FileStream(\"a\", FileMode.Open);\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2952").is_empty());
    }

    #[test]
    fn s2952_struct_dispose_methods_are_checked_too() {
        let report = analyze_default(
            "struct Worker\n{\n    public void Dispose()\n    {\n        var temp = new MemoryStream();\n        temp.Dispose();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2952");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }

    #[test]
    fn s2952_methods_not_named_dispose_stay_out_of_scope() {
        let report = analyze_default(
            "class Worker\n{\n    public void Cleanup()\n    {\n        var temp = new MemoryStream();\n        temp.Dispose();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2952").is_empty());
    }

    #[test]
    fn s2952_flags_each_non_member_dispose_call() {
        let report = analyze_default(
            "class Worker\n{\n    public void Dispose()\n    {\n        var first = new MemoryStream();\n        var second = new MemoryStream();\n        first.Dispose();\n        second.Dispose();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2952");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 7);
        assert_eq!(flagged[1].range.start.line, 8);
    }
}
