//! Security textual deny/require lists (Tier A12).
//! A12 — security textual deny/require lists

pub(crate) mod antiforgery_disabled;
pub(crate) mod argument_exception_param_names;
pub(crate) mod clear_text_protocols;
pub(crate) mod conflicting_transparency_attributes;
pub(crate) mod constructor_argument_names;
pub(crate) mod cryptographic_keys_robust;
pub(crate) mod debugging_left_enabled;
pub(crate) mod empty_guid_creations;
pub(crate) mod insecure_cipher_modes;
pub(crate) mod jwt_strong_algorithms;
pub(crate) mod one_way_contracts_return_void;
pub(crate) mod operation_contract_pairing;
pub(crate) mod optional_fields_have_deserialization_hooks;
pub(crate) mod part_creation_policy_needs_export;
pub(crate) mod permissive_cors;
pub(crate) mod permissive_csp;
pub(crate) mod predictable_temp_files;
pub(crate) mod publicly_writable_temp_paths;
pub(crate) mod pure_methods_return_values;
pub(crate) mod request_size_limits;
pub(crate) mod request_validation_disabled;
pub(crate) mod robust_ciphers_required;
pub(crate) mod serialization_constructors_secured;
pub(crate) mod serialization_event_handler_shapes;
mod support;
pub(crate) mod unbounded_archive_extraction;
pub(crate) mod unrestricted_deserialization;
mod walker;
pub(crate) mod weak_hash_algorithms;
pub(crate) mod weak_ssl_protocols;
pub(crate) mod winforms_entry_points;

pub(crate) use support::attributed_declaration;
pub(crate) use support::call_argument_nodes;
pub(crate) use support::identifier_usages;
pub(crate) use support::return_type_text;
pub(crate) use walker::security_deny_list_issues;
