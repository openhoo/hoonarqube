use super::support::LOG_LEVEL_LIMITS;
use super::support::logging_calls;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::callee_name;
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6664 — chatty methods bury signals; each severity bucket has
/// its own tolerated call count per method body.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        let mut calls: std::collections::BTreeMap<&str, Vec<Node<'_>>> =
            std::collections::BTreeMap::new();
        for call in logging_calls(body, source) {
            if let Some(level) = callee_name(call, source).and_then(log_level_of) {
                calls.entry(level).or_default().push(call);
            }
        }
        for (level, calls) in calls {
            let limit = log_level_limit(level);
            let count = u32::try_from(calls.len()).unwrap_or(u32::MAX);
            if count > limit {
                let display_level = match level {
                    "debug" => "Debug",
                    "information" => "Information",
                    "warning" => "Warning",
                    "error" => "Error",
                    _ => level,
                };
                issues.push(issue(
                    language,
                    "S6664",
                    format!("Reduce the number of {display_level} logging calls within this code block from {count} to the {limit} allowed."),
                    range_of(calls[0], source),
                ));
            }
        }
    }
    issues
}

/// Severity bucket of a logging entry point (`LogDebug` → debug).
fn log_level_of(callee: &str) -> Option<&'static str> {
    match callee {
        "LogTrace" | "LogDebug" => Some("debug"),
        "LogInformation" | "Log" => Some("information"),
        "LogWarning" => Some("warning"),
        "LogError" | "LogCritical" => Some("error"),
        _ => None,
    }
}

/// Tolerated number of `{level}` log calls inside one method body.
fn log_level_limit(level: &str) -> u32 {
    for (name, limit) in LOG_LEVEL_LIMITS {
        if name == level {
            return limit;
        }
    }
    0
}
