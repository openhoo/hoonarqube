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
        let mut counts: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
        for call in logging_calls(body, source) {
            if let Some(level) = callee_name(call, source).and_then(log_level_of) {
                *counts.entry(level).or_insert(0) += 1;
            }
        }
        for (level, count) in counts {
            let limit = log_level_limit(level);
            if count > limit {
                issues.push(issue(
                    language,
                    "S6664",
                    format!("Limit {level}-level logging in this method to {limit} calls."),
                    range_of(method, source),
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
