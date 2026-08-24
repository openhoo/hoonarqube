use super::abstract_member_mix::check as check_abstract_member_mix;
use super::chains_end_with_else::check as check_chains_end_with_else;
use super::cognitive_complexity::check as check_cognitive_complexity;
use super::condition_only_for_loops::check as check_condition_only_for_loops;
use super::context_parentheses::check as check_context_parentheses;
use super::curly_braces::check as check_curly_braces;
use super::cyclomatic_complexity::check as check_cyclomatic_complexity;
use super::default_clause_position::check as check_default_clause_position;
use super::empty_blocks::check as check_empty_blocks;
use super::empty_cases_before_default::check as check_empty_cases_before_default;
use super::empty_classes_and_records::check as check_empty_classes_and_records;
use super::empty_default_clauses::check as check_empty_default_clauses;
use super::empty_finalizers::check as check_empty_finalizers;
use super::empty_interfaces::check as check_empty_interfaces;
use super::empty_methods::check as check_empty_methods;
use super::empty_namespaces::check as check_empty_namespaces;
use super::empty_statements::check as check_empty_statements;
use super::finalizer_throws::check as check_finalizer_throws;
use super::for_increment_modifies_counter::check as check_for_increment_modifies_counter;
use super::function_lengths::check as check_function_lengths;
use super::logical_operator_counts::check as check_logical_operator_counts;
use super::mergeable_ifs::check as check_mergeable_ifs;
use super::method_parameter_counts::check as check_method_parameter_counts;
use super::multiline_embedded_statements::check as check_multiline_embedded_statements;
use super::nested_code_blocks::check as check_nested_code_blocks;
use super::nested_switches::check as check_nested_switches;
use super::nesting_depth::check as check_nesting_depth;
use super::property_getter_throws::check as check_property_getter_throws;
use super::redundant_parentheses::check as check_redundant_parentheses;
use super::switch_case_counts::check as check_switch_case_counts;
use super::switch_has_default::check as check_switch_has_default;
use super::switch_section_line_spans::check as check_switch_section_line_spans;
use super::switch_section_statement_counts::check as check_switch_section_statement_counts;
use super::trivial_properties::check as check_trivial_properties;
use super::types_outside_namespaces::check as check_types_outside_namespaces;
use super::write_only_properties::check as check_write_only_properties;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Gathers every issue contributed by this rule family.
pub(crate) fn structure_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_curly_braces(root, language));
    issues.extend(check_empty_blocks(root, language));
    issues.extend(check_empty_statements(root, language));
    issues.extend(check_redundant_parentheses(root, language));
    issues.extend(check_context_parentheses(root, language));
    issues.extend(check_mergeable_ifs(root, language));
    issues.extend(check_chains_end_with_else(root, language));
    issues.extend(check_switch_has_default(root, language));
    issues.extend(check_switch_case_counts(root, language));
    issues.extend(check_switch_section_statement_counts(
        root, language, options,
    ));
    issues.extend(check_switch_section_line_spans(root, language, options));
    issues.extend(check_nesting_depth(root, language, options));
    issues.extend(check_nested_code_blocks(root, language));
    issues.extend(check_function_lengths(root, language, options));
    issues.extend(check_method_parameter_counts(root, language, options));
    issues.extend(check_cyclomatic_complexity(root, source, language, options));
    issues.extend(check_cognitive_complexity(root, source, language, options));
    issues.extend(check_logical_operator_counts(
        root, source, language, options,
    ));
    issues.extend(check_empty_methods(root, source, language));
    issues.extend(check_finalizer_throws(root, language));
    issues.extend(check_empty_finalizers(root, language));
    issues.extend(check_property_getter_throws(root, source, language));
    issues.extend(check_write_only_properties(root, source, language));
    issues.extend(check_trivial_properties(root, source, language));
    issues.extend(check_abstract_member_mix(root, source, language));
    issues.extend(check_empty_classes_and_records(root, source, language));
    issues.extend(check_empty_interfaces(root, source, language));
    issues.extend(check_empty_namespaces(root, language));
    issues.extend(check_types_outside_namespaces(root, language));
    issues.extend(check_multiline_embedded_statements(root, language));
    issues.extend(check_nested_switches(root, language));
    issues.extend(check_default_clause_position(root, language));
    issues.extend(check_empty_cases_before_default(root, language));
    issues.extend(check_empty_default_clauses(root, language));
    issues.extend(check_condition_only_for_loops(root, language));
    issues.extend(check_for_increment_modifies_counter(root, source, language));
    issues
}
