use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{
    callee_name, invocation_function, invocation_receiver, member_declarations_of_kind,
};
use crate::rules::logging::field_declarator_names;
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2952 — disposable fields must be disposed from the owning
/// type's `Dispose` method, not from arbitrary methods.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class in collect_kinds(root, &["class_declaration", "struct_declaration"]) {
        if is_error_tainted(class) {
            continue;
        }
        check_class(class, source, language, &mut issues);
    }
    issues
}

fn check_class(class: Node<'_>, source: &str, language: CsLanguage, issues: &mut Vec<Issue>) {
    let fields: std::collections::HashSet<&str> = type_members(class)
        .into_iter()
        .filter(|member| member.kind() == "field_declaration")
        .flat_map(|field| field_declarator_names(field, source))
        .collect();
    for method in member_declarations_of_kind(class, "method_declaration") {
        if method
            .child_by_field_name("name")
            .is_some_and(|name| node_text(name, source) == "Dispose")
        {
            continue;
        }
        check_method(method, source, language, &fields, issues);
    }
}

fn check_method(
    method: Node<'_>,
    source: &str,
    language: CsLanguage,
    fields: &std::collections::HashSet<&str>,
    issues: &mut Vec<Issue>,
) {
    for call in collect_kinds(method, &["invocation_expression"]) {
        if is_error_tainted(call) || callee_name(call, source) != Some("Dispose") {
            continue;
        }
        let Some(receiver_name) =
            invocation_receiver(call).and_then(|receiver| match receiver.kind() {
                "identifier" => Some(node_text(receiver, source)),
                "member_access_expression" => collect_kinds(receiver, &["identifier"])
                    .into_iter()
                    .last()
                    .map(|name| node_text(name, source)),
                _ => None,
            })
        else {
            continue;
        };
        if !fields.contains(receiver_name) {
            continue;
        }
        let anchor = invocation_function(call)
            .and_then(|function| collect_kinds(function, &["identifier"]).into_iter().last())
            .unwrap_or(call);
        issues.push(issue(
            language,
            "S2952",
            "Move this 'Dispose' call into this class' own 'Dispose' method.",
            range_of(anchor, source),
        ));
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2952_this_qualified_receivers_stay_uncovered() {
        // The `this` token is anonymous in this grammar, so the extractor's
        // bare-identifier subset does not see `this.helper` receivers yet.
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
    fn s2952_locals_disposed_inside_dispose_are_clean() {
        let report = analyze_default(
            "struct Worker\n{\n    public void Dispose()\n    {\n        var temp = new MemoryStream();\n        temp.Dispose();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2952").is_empty());
    }

    #[test]
    fn s2952_fields_disposed_outside_dispose_are_flagged() {
        let report = analyze_default(
            "class Worker\n{\n    private MemoryStream stream;\n    public void Cleanup()\n    {\n        stream.Dispose();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2952").len(), 1);
    }

    #[test]
    fn s2952_non_member_dispose_calls_are_clean() {
        let report = analyze_default(
            "class Worker\n{\n    public void Dispose()\n    {\n        var first = new MemoryStream();\n        var second = new MemoryStream();\n        first.Dispose();\n        second.Dispose();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2952").is_empty());
    }
}
