use super::magic_numbers::check as check_magic_numbers;
use super::uninvoked_events::check as check_uninvoked_events;
use super::unused_locals::check as check_unused_locals;
use super::unused_method_parameters::check as check_unused_method_parameters;
use super::unused_private_members::check as check_unused_private_members;
use super::unused_usings::check as check_unused_usings;
use crate::CsLanguage;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Gathers every Tier-A10 in-file usage heuristic issue.
pub(crate) fn usage_heuristic_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_unused_usings(root, source, language));
    issues.extend(check_unused_private_members(root, source, language));
    issues.extend(check_unused_locals(root, source, language));
    issues.extend(check_unused_method_parameters(root, source, language));
    issues.extend(check_magic_numbers(root, source, language));
    issues.extend(check_uninvoked_events(root, source, language));
    issues
}
