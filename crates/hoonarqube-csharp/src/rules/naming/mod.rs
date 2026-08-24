//! Naming conventions (Tier A2).
//! A2 — naming conventions

pub(crate) mod async_naming;
pub(crate) mod enum_names;
pub(crate) mod enum_suffixes;
pub(crate) mod exception_like_suffixes;
pub(crate) mod getter_named_methods;
pub(crate) mod logger_member_names;
pub(crate) mod method_property_names;
pub(crate) mod overloads_grouped;
pub(crate) mod parameter_shadows_method;
mod support;
pub(crate) mod type_name_matches_namespace;
pub(crate) mod type_names;
mod walker;

pub(crate) use support::TYPE_DECLARATION_KINDS;
pub(crate) use support::declaration_kind_word;
pub(crate) use support::enum_has_flags_attribute;
pub(crate) use support::has_explicit_interface_specifier;
pub(crate) use support::type_members;
pub(crate) use walker::naming_issues;
