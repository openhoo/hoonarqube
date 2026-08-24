//! Field, static, and threading declaration contracts (Tier A11).
//! A11 — field/static/threading declaration contracts

pub(crate) mod assembly_annotations;
pub(crate) mod attribute_classes_constrained;
pub(crate) mod custom_event_handler_delegates;
pub(crate) mod default_field_initializers;
pub(crate) mod event_delegate_return_types;
pub(crate) mod event_payload_types;
pub(crate) mod extension_methods_on_object;
pub(crate) mod flags_enums_used_bitwise;
pub(crate) mod flags_members_explicit_values;
pub(crate) mod flags_zero_member_named_none;
pub(crate) mod partial_methods_implemented;
pub(crate) mod redundant_constructors;
pub(crate) mod reserved_enum_members;
pub(crate) mod static_fields_in_generic_types;
pub(crate) mod static_fields_initialized_inline;
pub(crate) mod static_fields_updated_in_constructors;
pub(crate) mod static_readonly_literals;
mod support;
pub(crate) mod thread_static_initializers;
pub(crate) mod thread_static_needs_static;
mod walker;

pub(crate) use support::assembly_attribute_names;
pub(crate) use support::file_level_issue;
pub(crate) use support::is_literal_node;
pub(crate) use walker::declaration_contract_issues;
