use super::array_covariance_assignments::check as check_array_covariance_assignments;
use super::constant_seeded_randoms::check as check_constant_seeded_randoms;
use super::discarded_pure_results::check as check_discarded_pure_results;
use super::equality_on_equals_overriders::check as check_equality_on_equals_overriders;
use super::field_capitalization_collisions::check as check_field_capitalization_collisions;
use super::fields_shadowing_bases::check as check_fields_shadowing_bases;
use super::hand_rolled_ciphers::check as check_hand_rolled_ciphers;
use super::hidden_base_methods::check as check_hidden_base_methods;
use super::integer_division_float_targets::check as check_integer_division_float_targets;
use super::interface_casts_to_concrete::check as check_interface_casts_to_concrete;
use super::interface_member_collisions::check as check_interface_member_collisions;
use super::legacy_non_generic_collections::check as check_legacy_non_generic_collections;
use super::logger_configuration_hotspots::check as check_logger_configuration_hotspots;
use super::optional_arguments_forwarded_to_base::check as check_optional_arguments_forwarded_to_base;
use super::override_default_values_differ::check as check_override_default_values_differ;
use super::override_visibility_decrease::check as check_override_visibility_decrease;
use super::parameter_names_drift_from_base::check as check_parameter_names_drift_from_base;
use super::params_introduced_on_overrides::check as check_params_introduced_on_overrides;
use super::params_missing_on_overrides::check as check_params_missing_on_overrides;
use super::plaintext_password_storage::check as check_plaintext_password_storage;
use super::random_in_security_contexts::check as check_random_in_security_contexts;
use super::recursive_inheritance::check as check_recursive_inheritance;
use super::redundant_casts::check as check_redundant_casts;
use super::redundant_inheritance_entries::check as check_redundant_inheritance_entries;
use super::redundant_null_comparisons::check as check_redundant_null_comparisons;
use super::redundant_to_string_calls::check as check_redundant_to_string_calls;
use super::reference_equality_on_values::check as check_reference_equality_on_values;
use super::self_collection_arguments::check as check_self_collection_arguments;
use super::shared_lock_targets::check as check_shared_lock_targets;
use super::shift_right_operand_kinds::check as check_shift_right_operand_kinds;
use super::static_iv_usage::check as check_static_iv_usage;
use super::static_password_salts::check as check_static_password_salts;
use crate::CsLanguage;
use crate::rules::tier_c_pending::{
    check_ambiguous_params_overload_calls, check_argument_order_mismatches,
    check_calls_to_explicit_interface_implementations, check_default_value_arguments,
    check_disposable_members_without_interface, check_dispose_of_non_members,
    check_durable_entity_interface_restrictions, check_first_or_single_on_known_non_empty,
    check_mixed_responsibility_controllers, check_readonly_generic_field_property_writes,
    check_route_constraint_parameter_types, check_serializable_without_deserialization_validation,
    check_undisposed_disposable_locals, check_unsupported_query_parameter_types,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Gathers every Tier-C FEASIBLE-HEURISTIC issue.
pub(crate) fn tier_c_heuristic_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_redundant_to_string_calls(root, source, language));
    issues.extend(check_redundant_casts(root, source, language));
    issues.extend(check_shift_right_operand_kinds(root, source, language));
    issues.extend(check_integer_division_float_targets(root, source, language));
    issues.extend(check_shared_lock_targets(root, source, language));
    issues.extend(check_self_collection_arguments(root, source, language));
    issues.extend(check_discarded_pure_results(root, source, language));
    issues.extend(check_static_password_salts(root, source, language));
    issues.extend(check_static_iv_usage(root, source, language));
    issues.extend(check_random_in_security_contexts(root, source, language));
    issues.extend(check_hand_rolled_ciphers(root, source, language));
    issues.extend(check_constant_seeded_randoms(root, source, language));
    issues.extend(check_logger_configuration_hotspots(root, source, language));
    issues.extend(check_plaintext_password_storage(root, source, language));
    issues.extend(check_redundant_null_comparisons(root, source, language));
    issues.extend(check_reference_equality_on_values(root, source, language));
    issues.extend(check_legacy_non_generic_collections(root, source, language));
    issues.extend(check_fields_shadowing_bases(root, source, language));
    issues.extend(check_field_capitalization_collisions(
        root, source, language,
    ));
    issues.extend(check_override_default_values_differ(root, source, language));
    issues.extend(check_redundant_inheritance_entries(root, source, language));
    issues.extend(check_recursive_inheritance(root, source, language));
    issues.extend(check_params_missing_on_overrides(root, source, language));
    issues.extend(check_params_introduced_on_overrides(root, source, language));
    issues.extend(check_optional_arguments_forwarded_to_base(
        root, source, language,
    ));
    issues.extend(check_override_visibility_decrease(root, source, language));
    issues.extend(check_hidden_base_methods(root, source, language));
    issues.extend(check_interface_member_collisions(root, source, language));
    issues.extend(check_parameter_names_drift_from_base(
        root, source, language,
    ));
    issues.extend(check_equality_on_equals_overriders(root, source, language));
    issues.extend(check_array_covariance_assignments(root, source, language));
    issues.extend(check_interface_casts_to_concrete(root, source, language));
    issues.extend(check_argument_order_mismatches(root, source, language));
    issues.extend(check_default_value_arguments(root, source, language));
    issues.extend(check_ambiguous_params_overload_calls(
        root, source, language,
    ));
    issues.extend(check_undisposed_disposable_locals(root, source, language));
    issues.extend(check_disposable_members_without_interface(
        root, source, language,
    ));
    issues.extend(check_dispose_of_non_members(root, source, language));
    issues.extend(check_readonly_generic_field_property_writes(
        root, source, language,
    ));
    issues.extend(check_serializable_without_deserialization_validation(
        root, source, language,
    ));
    issues.extend(check_unsupported_query_parameter_types(
        root, source, language,
    ));
    issues.extend(check_route_constraint_parameter_types(
        root, source, language,
    ));
    issues.extend(check_durable_entity_interface_restrictions(
        root, source, language,
    ));
    issues.extend(check_mixed_responsibility_controllers(
        root, source, language,
    ));
    issues.extend(check_first_or_single_on_known_non_empty(
        root, source, language,
    ));
    issues.extend(check_calls_to_explicit_interface_implementations(
        root, source, language,
    ));
    issues
}
