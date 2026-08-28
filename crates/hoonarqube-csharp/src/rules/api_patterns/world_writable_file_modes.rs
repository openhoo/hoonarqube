use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use crate::rules::literals::declarator_initializer;
use hoonarqube_ir::Issue;
use std::collections::HashSet;
use tree_sitter::Node;

/// csharpsquid:S2612 — permission rules that allow the broad `Everyone`
/// identity are security-sensitive when installed on a filesystem ACL.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let unsafe_rules: HashSet<&str> = collect_kinds(root, &["variable_declarator"])
        .into_iter()
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            let initializer = declarator_initializer(declarator, name)?;
            let text = node_text(initializer, source);
            (text.contains("FileSystemAccessRule")
                && text.contains("\"Everyone\"")
                && text.contains("AccessControlType.Allow"))
            .then_some(node_text(name, source))
        })
        .collect();

    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            matches!(
                callee_name(*invocation, source),
                Some("AddAccessRule" | "SetAccessRule")
            )
        })
        .filter(|invocation| {
            invocation_arguments(*invocation)
                .first()
                .is_some_and(|argument| unsafe_rules.contains(node_text(*argument, source).trim()))
        })
        .map(|invocation| {
            issue(
                language,
                "S2612",
                "Make sure this permission is safe.",
                range_of(invocation, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2612_flags_allow_everyone_acl_sinks() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        var unsafeRule = new FileSystemAccessRule(\"Everyone\", FileSystemRights.FullControl, AccessControlType.Allow);\n        var security = new FileSecurity();\n        security.AddAccessRule(unsafeRule);\n        security.SetAccessRule(unsafeRule);\n        security.ResetAccessRule(unsafeRule);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2612");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 7);
        assert_eq!(flagged[1].range.start.line, 8);
    }

    #[test]
    fn s2612_spares_deny_everyone_acl_rules() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        var safeRule = new FileSystemAccessRule(\"Everyone\", FileSystemRights.FullControl, AccessControlType.Deny);\n        var security = new FileSecurity();\n        security.AddAccessRule(safeRule);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2612").is_empty());
    }
}
