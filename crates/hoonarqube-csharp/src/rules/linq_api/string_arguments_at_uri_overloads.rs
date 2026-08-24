use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4005 — pass parsed `System.Uri` values instead of raw
/// strings at dual-overload call sites.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let targets = callee_name(call, source)
            .is_some_and(|name| STRING_URI_OVERLOAD_METHODS.contains(&name));
        if !targets {
            continue;
        }
        let Some(first) = invocation_arguments(call).first().copied() else {
            continue;
        };
        if argument_expression(first).kind() == "string_literal" {
            issues.push(issue(
                language,
                "S4005",
                "Create a 'System.Uri' and pass it to this call.",
                range_of(call),
            ));
        }
    }
    issues
}

/// Client members whose well-known string overloads have `System.Uri`
/// siblings.
const STRING_URI_OVERLOAD_METHODS: [&str; 5] = [
    "DownloadString",
    "UploadString",
    "DownloadData",
    "OpenRead",
    "OpenWrite",
];

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4005_checks_the_first_argument_across_wellknown_targets() {
        let report = analyze_default(
            "class A\n{\n    void M(System.Net.WebClient client)\n    {\n        body = client.UploadString(\"http://example.com\", payload);\n        stream = client.OpenWrite(\"http://example.com\", \"PUT\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4005");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5); // document line 4
        assert_eq!(flagged[1].range.start.line, 6); // document line 5
    }

    #[test]
    fn s4005_ignores_unknown_members_and_nonliteral_first_arguments() {
        let report = analyze_default(
            "class A\n{\n    void M(System.Net.WebClient client)\n    {\n        other = client.UnknownMethod(\"http://example.com\");\n        none = client.DownloadString();\n        stream = client.OpenRead(address);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4005").is_empty());
    }
}
