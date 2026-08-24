use super::action_routes_not_rooted::check as check_action_routes_not_rooted;
use super::actions_annotated_with_verbs::check as check_actions_annotated_with_verbs;
use super::api_controllers_derive_base::check as check_api_controllers_derive_base;
use super::azure_catches_log_failures::check as check_azure_catches_log_failures;
use super::azure_clients_created_per_invocation::check as check_azure_clients_created_per_invocation;
use super::azure_function_instance_state::check as check_azure_function_instance_state;
use super::azure_functions_catch_failures::check as check_azure_functions_catch_failures;
use super::azure_functions_do_not_block::check as check_azure_functions_do_not_block;
use super::controller_level_route_present::check as check_controller_level_route_present;
use super::culture_less_date_parsing::check as check_culture_less_date_parsing;
use super::datetime_kind_specified::check as check_datetime_kind_specified;
use super::datetime_now_for_timing::check as check_datetime_now_for_timing;
use super::direct_datetime_usage::check as check_direct_datetime_usage;
use super::find_system_time_zone_without_converter::check as check_find_system_time_zone_without_converter;
use super::hardcoded_date_formats::check as check_hardcoded_date_formats;
use super::http_clients_via_factory::check as check_http_clients_via_factory;
use super::js_invokable_methods_public::check as check_js_invokable_methods_public;
use super::model_binding_over_raw_request_reads::check as check_model_binding_over_raw_request_reads;
use super::model_state_checked_for_models::check as check_model_state_checked_for_models;
use super::produces_response_type_annotated::check as check_produces_response_type_annotated;
use super::route_templates_use_forward_slashes::check as check_route_templates_use_forward_slashes;
use super::unix_epoch_literal::check as check_unix_epoch_literal;
use crate::CsLanguage;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Placeholder gathering point for the remaining Tier-A13 date/time and
/// ASP.NET heuristics; populated group by group.
pub(crate) fn datetime_aspnet_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_direct_datetime_usage(root, source, language));
    issues.extend(check_datetime_now_for_timing(root, source, language));
    issues.extend(check_datetime_kind_specified(root, source, language));
    issues.extend(check_unix_epoch_literal(root, source, language));
    issues.extend(check_find_system_time_zone_without_converter(
        root, source, language,
    ));
    issues.extend(check_culture_less_date_parsing(root, source, language));
    issues.extend(check_hardcoded_date_formats(root, source, language));
    issues.extend(check_azure_function_instance_state(root, source, language));
    issues.extend(check_azure_functions_catch_failures(root, source, language));
    issues.extend(check_azure_functions_do_not_block(root, source, language));
    issues.extend(check_azure_catches_log_failures(root, source, language));
    issues.extend(check_azure_clients_created_per_invocation(
        root, source, language,
    ));
    issues.extend(check_js_invokable_methods_public(root, source, language));
    issues.extend(check_route_templates_use_forward_slashes(
        root, source, language,
    ));
    issues.extend(check_action_routes_not_rooted(root, source, language));
    issues.extend(check_model_binding_over_raw_request_reads(
        root, source, language,
    ));
    issues.extend(check_controller_level_route_present(root, source, language));
    issues.extend(check_api_controllers_derive_base(root, source, language));
    issues.extend(check_http_clients_via_factory(root, source, language));
    issues.extend(check_actions_annotated_with_verbs(root, source, language));
    issues.extend(check_model_state_checked_for_models(root, source, language));
    issues.extend(check_produces_response_type_annotated(
        root, source, language,
    ));
    issues
}
