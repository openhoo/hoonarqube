//! Designed-not-landed and not-started keys (Tier C).
//! Tier C — designed-not-landed keys
//! S2234, S3254, S3220, S2930, S2931, S2952, and S2934 — each an explicitly
//! documented single-file heuristic subset, true-positive by construction
//! over the file-local declaration tables.

pub(crate) mod ambiguous_params_overload_calls;
pub(crate) mod argument_order_mismatches;
pub(crate) mod calls_to_explicit_interface_implementations;
pub(crate) mod default_value_arguments;
pub(crate) mod disposable_members_without_interface;
pub(crate) mod dispose_of_non_members;
pub(crate) mod durable_entity_interface_restrictions;
pub(crate) mod first_or_single_on_known_non_empty;
pub(crate) mod mixed_responsibility_controllers;
pub(crate) mod readonly_generic_field_property_writes;
pub(crate) mod route_constraint_parameter_types;
pub(crate) mod serializable_without_deserialization_validation;
mod support;
pub(crate) mod undisposed_disposable_locals;
pub(crate) mod unsupported_query_parameter_types;

pub(crate) use ambiguous_params_overload_calls::check as check_ambiguous_params_overload_calls;
pub(crate) use argument_order_mismatches::check as check_argument_order_mismatches;
pub(crate) use calls_to_explicit_interface_implementations::check as check_calls_to_explicit_interface_implementations;
pub(crate) use default_value_arguments::check as check_default_value_arguments;
pub(crate) use disposable_members_without_interface::check as check_disposable_members_without_interface;
pub(crate) use dispose_of_non_members::check as check_dispose_of_non_members;
pub(crate) use durable_entity_interface_restrictions::check as check_durable_entity_interface_restrictions;
pub(crate) use first_or_single_on_known_non_empty::check as check_first_or_single_on_known_non_empty;
pub(crate) use mixed_responsibility_controllers::check as check_mixed_responsibility_controllers;
pub(crate) use readonly_generic_field_property_writes::check as check_readonly_generic_field_property_writes;
pub(crate) use route_constraint_parameter_types::check as check_route_constraint_parameter_types;
pub(crate) use serializable_without_deserialization_validation::check as check_serializable_without_deserialization_validation;
pub(crate) use undisposed_disposable_locals::check as check_undisposed_disposable_locals;
pub(crate) use unsupported_query_parameter_types::check as check_unsupported_query_parameter_types;
