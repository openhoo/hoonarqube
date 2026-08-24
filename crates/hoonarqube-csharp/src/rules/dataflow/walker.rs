use super::always_false_conditions::check as check_always_false_conditions;
use super::compare_after_assignment::check as check_compare_after_assignment;
use super::condition_true_at_least_once::check as check_condition_true_at_least_once;
use super::const_local_candidates::check as check_const_local_candidates;
use super::counter_direction::check as check_counter_direction;
use super::dead_stores::check as check_dead_stores;
use super::double_dispose::check as check_double_dispose;
use super::dynamic_sql::check as check_dynamic_sql;
use super::empty_collection_access::check as check_empty_collection_access;
use super::gratuitous_boolean_operands::check as check_gratuitous_boolean_operands;
use super::infinite_loops::check as check_infinite_loops;
use super::invariant_stop_conditions::check as check_invariant_stop_conditions;
use super::monitor_release_paths::check as check_monitor_release_paths;
use super::null_dereferences::check as check_null_dereferences;
use super::nullable_value_access::check as check_nullable_value_access;
use super::overflow_prone_calculations::check as check_overflow_prone_calculations;
use super::single_iteration_loops::check as check_single_iteration_loops;
use super::stream_reads_unchecked::check as check_stream_reads_unchecked;
use crate::CsLanguage;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Gathers every Tier-B intra-procedural dataflow/CFG issue.
pub(crate) fn dataflow_cfg_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_invariant_stop_conditions(root, source, language));
    issues.extend(check_single_iteration_loops(root, language));
    issues.extend(check_condition_true_at_least_once(root, source, language));
    issues.extend(check_dead_stores(root, source, language));
    issues.extend(check_dynamic_sql(root, source, language));
    issues.extend(check_infinite_loops(root, source, language));
    issues.extend(check_monitor_release_paths(root, source, language));
    issues.extend(check_counter_direction(root, source, language));
    issues.extend(check_null_dereferences(root, source, language));
    issues.extend(check_always_false_conditions(root, source, language));
    issues.extend(check_gratuitous_boolean_operands(root, language));
    issues.extend(check_stream_reads_unchecked(root, source, language));
    issues.extend(check_const_local_candidates(root, source, language));
    issues.extend(check_compare_after_assignment(root, source, language));
    issues.extend(check_nullable_value_access(root, source, language));
    issues.extend(check_overflow_prone_calculations(root, source, language));
    issues.extend(check_double_dispose(root, source, language));
    issues.extend(check_empty_collection_access(root, source, language));
    issues
}
