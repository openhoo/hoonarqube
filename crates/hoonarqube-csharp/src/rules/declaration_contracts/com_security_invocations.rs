use crate::CsLanguage;
use crate::cst::{attributes_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{invocation_function, invocation_targets};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3884 — mutating process-wide COM security from managed code
/// corrupts the whole apartment.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const BANNED: [&str; 2] = ["CoSetProxyBlanket", "CoInitializeSecurity"];
    let imported: std::collections::HashSet<&str> = collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| attributes_of(*method, source).contains(&"DllImport"))
        .filter_map(|method| method.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .filter(|name| BANNED.contains(name))
        .collect();
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| invocation_targets(*invocation, source, None, &BANNED))
        .filter_map(|invocation| {
            let function = invocation_function(invocation)?;
            imported
                .contains(node_text(function, source))
                .then_some(function)
        })
        .map(|function| {
            let name = node_text(function, source);
            issue(
                language,
                "S3884",
                format!("Refactor the code to remove this use of '{name}'."),
                range_of(function, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3884_flags_co_initialize_security_too() {
        let report = analyze_default(
            "class C\n{\n    [DllImport(\"ole32.dll\")]\n    static extern int CoInitializeSecurity();\n    void Boot()\n    {\n        CoInitializeSecurity();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3884");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
        assert_eq!(
            flagged[0].message,
            "Refactor the code to remove this use of 'CoInitializeSecurity'."
        );
    }

    #[test]
    fn s3884_unrelated_security_calls_stay_unflagged() {
        let report = analyze_default(
            "class C\n{\n    void Boot()\n    {\n        InitializeSecurity();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3884").is_empty());
    }
}
