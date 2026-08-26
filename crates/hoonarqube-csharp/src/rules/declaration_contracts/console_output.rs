use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{expression_name, first_named_child};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S106 — console output is not logging; it bypasses levels,
/// sinks, and correlation.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const CONSOLE_OWNERS: [&str; 3] = ["Console", "Console.Out", "Console.Error"];
    collect_kinds(root, &["member_access_expression"])
        .into_iter()
        .filter(|node| !is_error_tainted(*node))
        .filter(|node| {
            expression_name(*node, source)
                .is_some_and(|name| name == "Write" || name == "WriteLine")
                && first_named_child(*node).is_some_and(|receiver| {
                    let text = node_text(receiver, source).trim();
                    CONSOLE_OWNERS.iter().any(|owner| text.ends_with(owner))
                })
        })
        .map(|node| {
            issue(
                language,
                "S106",
                "Replace this console output with proper logging.",
                range_of(node, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s106_flags_error_and_out_streams_and_plain_write() {
        let report = analyze_default(
            "class C\n{\n    void Talk()\n    {\n        Console.Error.WriteLine(\"boom\");\n        Console.Out.Write(\"partial\");\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S106").len(), 2);
    }

    #[test]
    fn s106_non_console_writers_stay_unflagged() {
        let report = analyze_default(
            "class C\n{\n    void Talk()\n    {\n        Debug.WriteLine(\"trace\");\n        writer.WriteLine(\"entry\");\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S106").is_empty());
    }
}
