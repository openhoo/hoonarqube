use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4002 — finalizers on `IDisposable` types fight the dispose
/// pattern.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_node)
            || !base_simple_names(class_node, source).contains(&"IDisposable")
        {
            continue;
        }
        for destructor in collect_kinds(class_node, &["destructor_declaration"]) {
            if is_error_tainted(destructor) {
                continue;
            }
            issues.push(issue(
                language,
                "S4002",
                "Remove this finalizer or implement the dispose pattern correctly.",
                range_of(name_anchor(destructor), source),
            ));
        }
    }
    issues
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
    fn s4002_matches_unqualified_disposable_base() {
        let report = analyze_default("class A : IDisposable\n{\n    ~A()\n    {\n    }\n}\n");
        let flagged = with_key(&report, "csharpsquid:S4002");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s4002_reports_each_disposable_finalizer_distinctly() {
        let report = analyze_default(
            "class A : IDisposable\n{\n    ~A()\n    {\n    }\n}\n\nclass B : IDisposable\n{\n    ~B()\n    {\n    }\n}\n",
        );
        let mut lines: Vec<u32> = with_key(&report, "csharpsquid:S4002")
            .iter()
            .map(|issue| issue.range.start.line)
            .collect();
        lines.sort_unstable();
        assert_eq!(lines, vec![3, 10]);
    }

    #[test]
    fn s4002_ignores_disposable_without_finalizer() {
        let report = analyze_default(
            "class A : IDisposable\n{\n    public void Dispose()\n    {\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4002").is_empty());
    }
}
