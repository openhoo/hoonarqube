use crate::CsLanguage;
use crate::cst::{is_error_tainted, issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    LOGGER_CONFIG_ACCESSORS
        .iter()
        .flat_map(|(owner, tails)| banned_member_accesses(root, source, owner, tails))
        .filter(|access| !is_error_tainted(*access))
        .filter(|access| {
            access.parent().is_some_and(|parent| {
                matches!(parent.kind(), "assignment_expression" | "invocation_expression")
            })
        })
        .map(|access| {
            issue(
                language,
                "S4792",
                "Make sure configuring loggers here is intended; logger configuration is security-sensitive.",
                range_of(access),
            )
        })
        .collect()
}

/// csharpsquid:S4792 — configuring loggers is security-sensitive. Subset:
/// log4net/NLog-style configuration entry points (`LogManager.Configuration*`,
/// `XmlConfigurator/DomConfigurator Configure*`) that assign or invoke;
/// plain reads of `Configuration` stay unflagged.
const LOGGER_CONFIG_ACCESSORS: &[(&str, &[&str])] = &[
    ("LogManager", &["Configuration", "ConfigurationRepository"]),
    ("XmlConfigurator", &["Configure", "ConfigureAndWatch"]),
    ("DomConfigurator", &["Configure", "ConfigureAndWatch"]),
];
