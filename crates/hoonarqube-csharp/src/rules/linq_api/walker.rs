use super::accessor_shaped_methods::check as check_accessor_shaped_methods;
use super::anonymous_unsubscriptions::check as check_anonymous_unsubscriptions;
use super::any_instead_of_count::check as check_any_instead_of_count;
use super::composite_format_usage::check as check_composite_format_usage;
use super::concise_declarations::check as check_concise_declarations;
use super::double_element_writes::check as check_double_element_writes;
use super::duplicate_casts::check as check_duplicate_casts;
use super::format_argument_counts::check as check_format_argument_counts;
use super::regular_number_patterns::check as check_regular_number_patterns;
use super::setters_assign_value::check as check_setters_assign_value;
use super::string_arguments_at_uri_overloads::check as check_string_arguments_at_uri_overloads;
use super::trivial_base_forwarding_overrides::check as check_trivial_base_forwarding_overrides;
use super::uri_string_parameters::check as check_uri_string_parameters;
use super::uri_string_properties::check as check_uri_string_properties;
use super::uri_string_returns::check as check_uri_string_returns;
use crate::CsLanguage;
use crate::rules::api_contracts::{
    check_array_arguments_for_params_calls, check_assembly_versions,
    check_collection_property_setters, check_culture_less_comparisons,
    check_culture_less_conversions, check_culture_less_searches, check_datetime_key_members,
    check_debugger_display_references, check_dispose_needs_interface, check_dispose_pattern,
    check_double_reported_catches, check_explicit_rethrows, check_foreach_iteration_casts,
    check_general_exception_catches, check_hardcoded_connection_passwords,
    check_ignored_generic_exceptions, check_indexer_parameter_types, check_literal_assertions,
    check_locks_on_locals, check_locks_on_mutable_fields, check_lowercase_normalization,
    check_mergeable_try_statements, check_null_reference_catches, check_outdated_base_types,
    check_overlapping_optional_overloads, check_public_list_signatures,
    check_pure_debug_assertions, check_readonly_primitive_fields, check_redundant_modifiers,
    check_reserved_exception_throws, check_rethrow_only_catches,
    check_reversed_assertion_arguments, check_strings_matching_parameters, check_task_returns_null,
    check_test_classes_contain_tests, check_test_method_signatures, check_tests_include_assertions,
    check_throws_in_finally, check_transposed_operators, check_unchecked_sums,
    check_unconstrained_assertions, check_utility_class_constructors, check_weak_identity_locks,
    comment_tag_issues,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Gathers the Tier-A15 LINQ/format/API-heuristic slice.
pub(crate) fn linq_api_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_any_instead_of_count(root, source, language));
    issues.extend(check_format_argument_counts(root, source, language));
    issues.extend(check_composite_format_usage(root, source, language));
    issues.extend(check_regular_number_patterns(root, source, language));
    issues.extend(check_double_element_writes(root, source, language));
    issues.extend(check_uri_string_parameters(root, source, language));
    issues.extend(check_uri_string_returns(root, source, language));
    issues.extend(check_uri_string_properties(root, source, language));
    issues.extend(check_string_arguments_at_uri_overloads(
        root, source, language,
    ));
    issues.extend(check_concise_declarations(root, source, language));
    issues.extend(check_anonymous_unsubscriptions(root, source, language));
    issues.extend(check_duplicate_casts(root, source, language));
    issues.extend(check_trivial_base_forwarding_overrides(
        root, source, language,
    ));
    issues.extend(check_setters_assign_value(root, source, language));
    issues.extend(check_accessor_shaped_methods(root, source, language));
    issues.extend(check_lowercase_normalization(root, source, language));
    issues.extend(check_culture_less_conversions(root, source, language));
    issues.extend(check_culture_less_comparisons(root, source, language));
    issues.extend(check_culture_less_searches(root, source, language));
    issues.extend(check_hardcoded_connection_passwords(root, source, language));
    issues.extend(check_weak_identity_locks(root, language));
    issues.extend(check_locks_on_locals(root, source, language));
    issues.extend(check_locks_on_mutable_fields(root, source, language));
    issues.extend(check_datetime_key_members(root, source, language));
    issues.extend(check_outdated_base_types(root, source, language));
    issues.extend(check_tests_include_assertions(root, source, language));
    issues.extend(check_literal_assertions(root, source, language));
    issues.extend(check_unconstrained_assertions(root, source, language));
    issues.extend(check_reversed_assertion_arguments(root, source, language));
    issues.extend(check_test_classes_contain_tests(root, source, language));
    issues.extend(check_task_returns_null(root, source, language));
    issues.extend(check_dispose_pattern(root, source, language));
    issues.extend(check_dispose_needs_interface(root, source, language));
    issues.extend(check_utility_class_constructors(root, source, language));
    issues.extend(check_reserved_exception_throws(root, source, language));
    issues.extend(check_throws_in_finally(root, language));
    issues.extend(check_null_reference_catches(root, source, language));
    issues.extend(check_double_reported_catches(root, source, language));
    issues.extend(check_general_exception_catches(root, source, language));
    issues.extend(check_unchecked_sums(root, source, language));
    issues.extend(check_strings_matching_parameters(root, source, language));
    issues.extend(check_mergeable_try_statements(root, source, language));
    issues.extend(check_redundant_modifiers(root, source, language));
    let (fixmes, todos) = comment_tag_issues(root, source, language);
    issues.extend(fixmes);
    issues.extend(todos);
    issues.extend(check_test_method_signatures(root, source, language));
    issues.extend(check_ignored_generic_exceptions(root, source, language));
    issues.extend(check_rethrow_only_catches(root, language));
    issues.extend(check_transposed_operators(source, language));
    issues.extend(check_foreach_iteration_casts(root, source, language));
    issues.extend(check_pure_debug_assertions(root, source, language));
    issues.extend(check_overlapping_optional_overloads(root, source, language));
    issues.extend(check_explicit_rethrows(root, language));
    issues.extend(check_indexer_parameter_types(root, source, language));
    issues.extend(check_array_arguments_for_params_calls(
        root, source, language,
    ));
    issues.extend(check_readonly_primitive_fields(root, source, language));
    issues.extend(check_assembly_versions(root, source, language));
    issues.extend(check_public_list_signatures(root, source, language));
    issues.extend(check_collection_property_setters(root, source, language));
    issues.extend(check_debugger_display_references(root, source, language));
    issues
}
