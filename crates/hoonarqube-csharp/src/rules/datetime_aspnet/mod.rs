//! Date/time and Azure/ASP.NET textual heuristics (Tier A13).
//! A13 — date/time & Azure/ASP.NET textual heuristics

pub(crate) mod action_routes_not_rooted;
pub(crate) mod actions_annotated_with_verbs;
pub(crate) mod api_controllers_derive_base;
pub(crate) mod azure_catches_log_failures;
pub(crate) mod azure_clients_created_per_invocation;
pub(crate) mod azure_function_instance_state;
pub(crate) mod azure_functions_catch_failures;
pub(crate) mod azure_functions_do_not_block;
pub(crate) mod controller_level_route_present;
pub(crate) mod culture_less_date_parsing;
pub(crate) mod datetime_kind_specified;
pub(crate) mod datetime_now_for_timing;
pub(crate) mod direct_datetime_usage;
pub(crate) mod find_system_time_zone_without_converter;
pub(crate) mod hardcoded_date_formats;
pub(crate) mod http_clients_via_factory;
pub(crate) mod js_invokable_methods_public;
pub(crate) mod model_binding_over_raw_request_reads;
pub(crate) mod model_state_checked_for_models;
pub(crate) mod produces_response_type_annotated;
pub(crate) mod route_templates_use_forward_slashes;
mod support;
pub(crate) mod unix_epoch_literal;
mod walker;

pub(crate) use walker::datetime_aspnet_issues;
