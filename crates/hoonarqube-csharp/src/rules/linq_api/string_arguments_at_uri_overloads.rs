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
