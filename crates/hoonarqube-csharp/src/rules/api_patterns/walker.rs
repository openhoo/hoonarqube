use super::async_parameter_validation::check as check_async_parameter_validation;
use super::cookie_security_flags::check as check_cookie_security_flags;
use super::copying_property_getters::check as check_copying_property_getters;
use super::culture_less_convert_calls::check as check_culture_less_convert_calls;
use super::datetime_into_datetimeoffset::check as check_datetime_into_datetimeoffset;
use super::discarded_async_calls::check as check_discarded_async_calls;
use super::discarded_signature_checks::check as check_discarded_signature_checks;
use super::exported_contracts_implemented::check as check_exported_contracts_implemented;
use super::extension_methods_next_to_extended_types::check as check_extension_methods_next_to_extended_types;
use super::hardcoded_jwt_signing_keys::check as check_hardcoded_jwt_signing_keys;
use super::iserializable_contract::check as check_iserializable_contract;
use super::iterator_parameter_validation::check as check_iterator_parameter_validation;
use super::literals_in_localizable_members::check as check_literals_in_localizable_members;
use super::local_time_instants::check as check_local_time_instants;
use super::misplaced_log_exceptions::check as check_misplaced_log_exceptions;
use super::monitor_released_outside_method::check as check_monitor_released_outside_method;
use super::path_resolved_commands::check as check_path_resolved_commands;
use super::permissive_certificate_callbacks::check as check_permissive_certificate_callbacks;
use super::query_binding_without_route::check as check_query_binding_without_route;
use super::reader_writer_lock_modes::check as check_reader_writer_lock_modes;
use super::reflection_accessibility_escalation::check as check_reflection_accessibility_escalation;
use super::shared_parts_created_directly::check as check_shared_parts_created_directly;
use super::short_circuit_logic::check as check_short_circuit_logic;
use super::unauthenticated_ldap_connections::check as check_unauthenticated_ldap_connections;
use super::under_posting_value_type_inputs::check as check_under_posting_value_type_inputs;
use super::unpaired_delegate_begin_invoke::check as check_unpaired_delegate_begin_invoke;
use super::value_task_consumed_once::check as check_value_task_consumed_once;
use super::world_writable_file_modes::check as check_world_writable_file_modes;
use super::xxe_vulnerable_parsers::check as check_xxe_vulnerable_parsers;
use crate::CsLanguage;
use crate::rules::linq_api::check_linq_receivers;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Gathers every Tier-B framework/API pattern-match issue.
pub(crate) fn framework_api_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_cookie_security_flags(root, source, language));
    issues.extend(check_short_circuit_logic(root, source, language));
    issues.extend(check_world_writable_file_modes(root, source, language));
    issues.extend(check_xxe_vulnerable_parsers(root, source, language));
    issues.extend(check_reflection_accessibility_escalation(
        root, source, language,
    ));
    issues.extend(check_iserializable_contract(root, source, language));
    issues.extend(check_path_resolved_commands(root, source, language));
    issues.extend(check_exported_contracts_implemented(root, source, language));
    issues.extend(check_shared_parts_created_directly(root, source, language));
    issues.extend(check_unauthenticated_ldap_connections(
        root, source, language,
    ));
    issues.extend(check_iterator_parameter_validation(root, source, language));
    issues.extend(check_async_parameter_validation(root, source, language));
    issues.extend(check_local_time_instants(root, source, language));
    issues.extend(check_datetime_into_datetimeoffset(root, source, language));
    issues.extend(check_literals_in_localizable_members(
        root, source, language,
    ));
    issues.extend(check_culture_less_convert_calls(root, source, language));
    issues.extend(check_extension_methods_next_to_extended_types(
        root, source, language,
    ));
    issues.extend(check_reader_writer_lock_modes(root, source, language));
    issues.extend(check_monitor_released_outside_method(
        root, source, language,
    ));
    issues.extend(check_unpaired_delegate_begin_invoke(root, source, language));
    issues.extend(check_permissive_certificate_callbacks(
        root, source, language,
    ));
    issues.extend(check_value_task_consumed_once(root, source, language));
    issues.extend(check_discarded_signature_checks(root, source, language));
    issues.extend(check_misplaced_log_exceptions(root, source, language));
    issues.extend(check_hardcoded_jwt_signing_keys(root, source, language));
    issues.extend(check_query_binding_without_route(root, source, language));
    issues.extend(check_under_posting_value_type_inputs(
        root, source, language,
    ));
    issues.extend(check_discarded_async_calls(root, source, language));
    issues.extend(check_copying_property_getters(root, source, language));
    issues.extend(check_linq_receivers(root, source, language));
    issues
}
