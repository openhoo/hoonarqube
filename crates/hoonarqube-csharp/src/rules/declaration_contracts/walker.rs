use super::any_with_equality_lambda::check as check_any_with_equality_lambda;
use super::assembly_load_from::check as check_assembly_load_from;
use super::base_calls_on_object_types::check as check_base_calls_on_object_types;
use super::base_equals_misuse::check as check_base_equals_misuse;
use super::blocking_on_async::check as check_blocking_on_async;
use super::com_security_invocations::check as check_com_security_invocations;
use super::comparable_contracts::check as check_comparable_contracts;
use super::concurrent_dictionary_delegates::check as check_concurrent_dictionary_delegates;
use super::configure_await_usage::check as check_configure_await_usage;
use super::console_output::check as check_console_output;
use super::coverage_exclusion_reasons::check as check_coverage_exclusion_reasons;
use super::dangerous_get_handle::check as check_dangerous_get_handle;
use super::equality_operator_pairing::check as check_equality_operator_pairing;
use super::equals_hashcode_pairing::check as check_equals_hashcode_pairing;
use super::exception_named_bases::check as check_exception_named_bases;
use super::exit_method_calls::check as check_exit_method_calls;
use super::expected_exception_attributes::check as check_expected_exception_attributes;
use super::formattable_string_flows::check as check_formattable_string_flows;
use super::gc_collect_calls::check as check_gc_collect_calls;
use super::get_executing_assembly::check as check_get_executing_assembly;
use super::gethashcode_mutable_fields::check as check_gethashcode_mutable_fields;
use super::ignored_tests::check as check_ignored_tests;
use super::linqable_loops::check as check_linqable_loops;
use super::obsolete_tracked::check as check_obsolete_tracked;
use super::obsolete_without_reason::check as check_obsolete_without_reason;
use super::operator_equals_on_classes::check as check_operator_equals_on_classes;
use super::operator_named_alternatives::check as check_operator_named_alternatives;
use super::ordering_after_filtering::check as check_ordering_after_filtering;
use super::repeated_orderings::check as check_repeated_orderings;
use super::single_char_overloads::check as check_single_char_overloads;
use super::standard_constructors::check as check_standard_constructors;
use super::string_concatenation_in_loops::check as check_string_concatenation_in_loops;
use super::string_to_array_iteration::check as check_string_to_array_iteration;
use super::structs_implement_iequatable::check as check_structs_implement_iequatable;
use super::suppress_finalize_usage::check as check_suppress_finalize_usage;
use super::suppression_tracked::check as check_suppression_tracked;
use super::thread_sleep_in_tests::check as check_thread_sleep_in_tests;
use super::thread_suspend_resume::check as check_thread_suspend_resume;
use super::throws_from_special_methods::check as check_throws_from_special_methods;
use super::to_string_null_returns::check as check_to_string_null_returns;
use super::typed_equals_needs_iequatable::check as check_typed_equals_needs_iequatable;
use super::where_terminal_chains::check as check_where_terminal_chains;
use super::zero_based_substring::check as check_zero_based_substring;
use crate::CsLanguage;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Gathers every issue contributed by this rule family.
pub(crate) fn contract_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(attribute_contract_issues(root, source, language));
    issues.extend(member_contract_issues(root, source, language));
    issues
}

/// Gathers every Tier-A7 attribute-contract issue.
fn attribute_contract_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_obsolete_tracked(root, source, language));
    issues.extend(check_obsolete_without_reason(root, source, language));
    issues.extend(check_suppression_tracked(root, source, language));
    issues.extend(check_ignored_tests(root, source, language));
    issues.extend(check_expected_exception_attributes(root, source, language));
    issues.extend(check_coverage_exclusion_reasons(root, source, language));
    issues.extend(check_comparable_contracts(root, source, language));
    issues.extend(check_equals_hashcode_pairing(root, source, language));
    issues.extend(check_exception_named_bases(root, source, language));
    issues.extend(check_standard_constructors(root, source, language));
    issues.extend(check_operator_equals_on_classes(root, source, language));
    issues.extend(check_equality_operator_pairing(root, source, language));
    issues.extend(check_operator_named_alternatives(root, source, language));
    issues.extend(check_throws_from_special_methods(root, source, language));
    issues.extend(check_to_string_null_returns(root, source, language));
    issues.extend(check_gethashcode_mutable_fields(root, source, language));
    issues.extend(check_base_equals_misuse(root, source, language));
    issues.extend(check_base_calls_on_object_types(root, source, language));
    issues.extend(check_typed_equals_needs_iequatable(root, source, language));
    issues.extend(check_structs_implement_iequatable(root, source, language));
    issues.extend(check_suppress_finalize_usage(root, source, language));
    issues
}

/// Gathers every Tier-A8 member-contract issue.
fn member_contract_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_gc_collect_calls(root, source, language));
    issues.extend(check_exit_method_calls(root, source, language));
    issues.extend(check_console_output(root, source, language));
    issues.extend(check_thread_sleep_in_tests(root, source, language));
    issues.extend(check_thread_suspend_resume(root, source, language));
    issues.extend(check_dangerous_get_handle(root, source, language));
    issues.extend(check_com_security_invocations(root, source, language));
    issues.extend(check_assembly_load_from(root, source, language));
    issues.extend(check_get_executing_assembly(root, source, language));
    issues.extend(check_configure_await_usage(root, source, language));
    issues.extend(check_blocking_on_async(root, source, language));
    issues.extend(check_repeated_orderings(root, source, language));
    issues.extend(check_where_terminal_chains(root, source, language));
    issues.extend(check_linqable_loops(root, source, language));
    issues.extend(check_zero_based_substring(root, source, language));
    issues.extend(check_single_char_overloads(root, source, language));
    issues.extend(check_any_with_equality_lambda(root, source, language));
    issues.extend(check_concurrent_dictionary_delegates(
        root, source, language,
    ));
    issues.extend(check_formattable_string_flows(root, source, language));
    issues.extend(check_ordering_after_filtering(root, source, language));
    issues.extend(check_string_to_array_iteration(root, source, language));
    issues.extend(check_string_concatenation_in_loops(root, source, language));
    issues
}
