use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name,
};
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4002 — disposable types owning unmanaged pointer fields need
/// a finalizer as a last-resort cleanup path.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_node)
            || !base_simple_names(class_node, source).contains(&"IDisposable")
            || !owns_unmanaged_pointer(class_node, source)
            || !collect_kinds(class_node, &["destructor_declaration"]).is_empty()
        {
            continue;
        }
        issues.push(issue(
            language,
            "S4002",
            "Implement a finalizer that calls your 'Dispose' method.",
            range_of(name_anchor(class_node), source),
        ));
    }
    issues
}

fn owns_unmanaged_pointer(class_node: Node<'_>, source: &str) -> bool {
    collect_kinds(class_node, &["field_declaration"])
        .into_iter()
        .filter_map(|field| {
            collect_kinds(field, &["variable_declaration"])
                .into_iter()
                .next()
        })
        .filter_map(|declaration| declaration.child_by_field_name("type"))
        .any(|field_type| {
            matches!(
                simple_name(node_text(field_type, source)),
                "IntPtr" | "UIntPtr" | "HandleRef"
            )
        })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4002_ignores_finalizers_on_plain_types() {
        let report = analyze_default("class A\n{\n    ~A()\n    {\n    }\n}\n");
        assert!(with_key(&report, "csharpsquid:S4002").is_empty());
    }

    #[test]
    fn s4002_matches_unqualified_disposable_base_with_pointer() {
        let report = analyze_default(
            "class A : IDisposable\n{\n    private IntPtr resource;\n    public void Dispose() { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4002");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s4002_reports_each_disposable_pointer_owner_distinctly() {
        let report = analyze_default(
            "class A : IDisposable\n{\n    private IntPtr first;\n}\n\nclass B : IDisposable\n{\n    private UIntPtr second;\n}\n",
        );
        let mut lines: Vec<u32> = with_key(&report, "csharpsquid:S4002")
            .iter()
            .map(|issue| issue.range.start.line)
            .collect();
        lines.sort_unstable();
        assert_eq!(lines, vec![1, 6]);
    }

    #[test]
    fn s4002_ignores_disposable_without_unmanaged_pointer() {
        let report = analyze_default(
            "class A : IDisposable\n{\n    public void Dispose()\n    {\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4002").is_empty());
    }
}
