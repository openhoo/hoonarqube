//! File-scoped rules fed by the symbol table (Tier B).

pub(crate) mod accessor_backing_field_mismatch;
pub(crate) mod bitwise_non_flags_enums;
pub(crate) mod constructors_calling_overridable_members;
pub(crate) mod delegate_subtraction;
pub(crate) mod discarded_return_values;
pub(crate) mod disposable_types_with_finalizers;
pub(crate) mod explicit_caller_information_arguments;
pub(crate) mod generic_null_comparisons;
pub(crate) mod gettype_on_type_instances;
pub(crate) mod ignored_initial_values;
pub(crate) mod inner_statics_shadowing_outer;
pub(crate) mod instance_writes_to_static_fields;
pub(crate) mod null_returns_from_collection_members;
pub(crate) mod private_methods_called_only_from_nested_types;
pub(crate) mod readonly_field_candidates;
pub(crate) mod single_method_fields;
pub(crate) mod static_candidate_members;
pub(crate) mod static_initialization_order;
pub(crate) mod string_uri_overload_delegation;
mod support;
pub(crate) mod this_escaping_constructors;
pub(crate) mod unassigned_private_fields;
pub(crate) mod unconsumed_string_builders;
pub(crate) mod unreferenced_private_members;
pub(crate) mod unvalidated_public_parameters;
pub(crate) mod using_disposable_returned;
mod walker;

pub(crate) use support::unconstrained_generic_parameters;
pub(crate) use walker::usage_analysis_issues;
