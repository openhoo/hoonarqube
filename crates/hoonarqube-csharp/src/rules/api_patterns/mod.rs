//! Framework/API pattern matching with small dataflow (Tier B).
//! Tier B — needs framework/API pattern matching with small dataflow
//! These rules match known .NET API shapes and follow values one or two
//! statements at most. Each detector documents its bound; anything that
//! needs a real type system (overload resolution, inheritance-wide
//! search) is approximated by name and flagged conservatively.

pub(crate) mod async_parameter_validation;
pub(crate) mod cookie_security_flags;
pub(crate) mod copying_property_getters;
pub(crate) mod culture_less_convert_calls;
pub(crate) mod datetime_into_datetimeoffset;
pub(crate) mod discarded_async_calls;
pub(crate) mod discarded_signature_checks;
pub(crate) mod exported_contracts_implemented;
pub(crate) mod extension_methods_next_to_extended_types;
pub(crate) mod hardcoded_jwt_signing_keys;
pub(crate) mod iserializable_contract;
pub(crate) mod iterator_parameter_validation;
pub(crate) mod literals_in_localizable_members;
pub(crate) mod local_time_instants;
pub(crate) mod misplaced_log_exceptions;
pub(crate) mod monitor_released_outside_method;
pub(crate) mod path_resolved_commands;
pub(crate) mod permissive_certificate_callbacks;
pub(crate) mod query_binding_without_route;
pub(crate) mod reader_writer_lock_modes;
pub(crate) mod reflection_accessibility_escalation;
pub(crate) mod shared_parts_created_directly;
pub(crate) mod short_circuit_logic;
mod support;
pub(crate) mod unauthenticated_ldap_connections;
pub(crate) mod under_posting_value_type_inputs;
pub(crate) mod unpaired_delegate_begin_invoke;
pub(crate) mod value_task_consumed_once;
mod walker;
pub(crate) mod world_writable_file_modes;
pub(crate) mod xxe_vulnerable_parsers;

pub(crate) use walker::framework_api_issues;
