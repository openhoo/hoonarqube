use super::accessor_backing_field_mismatch::check as check_accessor_backing_field_mismatch;
use super::bitwise_non_flags_enums::check as check_bitwise_non_flags_enums;
use super::constructors_calling_overridable_members::check as check_constructors_calling_overridable_members;
use super::delegate_subtraction::check as check_delegate_subtraction;
use super::discarded_return_values::check as check_discarded_return_values;
use super::disposable_types_with_finalizers::check as check_disposable_types_with_finalizers;
use super::explicit_caller_information_arguments::check as check_explicit_caller_information_arguments;
use super::generic_null_comparisons::check as check_generic_null_comparisons;
use super::gettype_on_type_instances::check as check_gettype_on_type_instances;
use super::ignored_initial_values::check as check_ignored_initial_values;
use super::inner_statics_shadowing_outer::check as check_inner_statics_shadowing_outer;
use super::instance_writes_to_static_fields::check as check_instance_writes_to_static_fields;
use super::null_returns_from_collection_members::check as check_null_returns_from_collection_members;
use super::private_methods_called_only_from_nested_types::check as check_private_methods_called_only_from_nested_types;
use super::readonly_field_candidates::check as check_readonly_field_candidates;
use super::single_method_fields::check as check_single_method_fields;
use super::static_candidate_members::check as check_static_candidate_members;
use super::static_initialization_order::check as check_static_initialization_order;
use super::string_uri_overload_delegation::check as check_string_uri_overload_delegation;
use super::this_escaping_constructors::check as check_this_escaping_constructors;
use super::unassigned_private_fields::check as check_unassigned_private_fields;
use super::unconsumed_string_builders::check as check_unconsumed_string_builders;
use super::unreferenced_private_members::check as check_unreferenced_private_members;
use super::unvalidated_public_parameters::check as check_unvalidated_public_parameters;
use super::using_disposable_returned::check as check_using_disposable_returned;
use crate::CsLanguage;
use crate::symbol_table::build_usage_symbols;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Gathers every Tier-B usage-analysis issue from the shared symbol table.
pub(crate) fn usage_analysis_issues<'t>(
    root: Node<'t>,
    source: &'t str,
    language: CsLanguage,
) -> Vec<Issue> {
    let symbols = build_usage_symbols(root, source);
    let mut issues = Vec::new();
    issues.extend(check_unreferenced_private_members(
        source, language, &symbols,
    ));
    issues.extend(check_single_method_fields(source, language, &symbols));
    issues.extend(check_unassigned_private_fields(source, language, &symbols));
    issues.extend(check_readonly_field_candidates(source, language, &symbols));
    issues.extend(check_static_candidate_members(source, language, &symbols));
    issues.extend(check_instance_writes_to_static_fields(
        source, language, &symbols,
    ));
    issues.extend(check_inner_statics_shadowing_outer(language, &symbols));
    issues.extend(check_private_methods_called_only_from_nested_types(
        source, language, &symbols,
    ));
    issues.extend(check_null_returns_from_collection_members(
        root, source, language,
    ));
    issues.extend(check_ignored_initial_values(root, source, language));
    issues.extend(check_constructors_calling_overridable_members(
        root, source, language, &symbols,
    ));
    issues.extend(check_generic_null_comparisons(root, source, language));
    issues.extend(check_using_disposable_returned(root, source, language));
    issues.extend(check_unconsumed_string_builders(
        root, source, language, &symbols,
    ));
    issues.extend(check_delegate_subtraction(root, source, language));
    issues.extend(check_explicit_caller_information_arguments(
        root, source, language,
    ));
    issues.extend(check_static_initialization_order(
        source, language, &symbols,
    ));
    issues.extend(check_bitwise_non_flags_enums(root, source, language));
    issues.extend(check_this_escaping_constructors(root, language));
    issues.extend(check_gettype_on_type_instances(root, source, language));
    issues.extend(check_unvalidated_public_parameters(root, source, language));
    issues.extend(check_string_uri_overload_delegation(root, source, language));
    issues.extend(check_disposable_types_with_finalizers(
        root, source, language,
    ));
    issues.extend(check_accessor_backing_field_mismatch(
        root, source, language,
    ));
    issues.extend(check_discarded_return_values(source, language, &symbols));
    issues
}
