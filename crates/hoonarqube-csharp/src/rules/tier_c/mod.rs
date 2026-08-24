//! Feasible-heuristic structural keys (Tier C).
//! Tier C — FEASIBLE-HEURISTIC structural keys
//! Every rule below implements an explicitly documented single-file heuristic
//! subset of its RSPEC contract. Anything needing cross-file resolution or a
//! semantic model stays uncovered on purpose; nothing here approximates an
//! unsound guess as a finding.

pub(crate) mod array_covariance_assignments;
pub(crate) mod constant_seeded_randoms;
pub(crate) mod discarded_pure_results;
pub(crate) mod equality_on_equals_overriders;
pub(crate) mod field_capitalization_collisions;
pub(crate) mod fields_shadowing_bases;
pub(crate) mod hand_rolled_ciphers;
pub(crate) mod hidden_base_methods;
pub(crate) mod integer_division_float_targets;
pub(crate) mod interface_casts_to_concrete;
pub(crate) mod interface_member_collisions;
pub(crate) mod legacy_non_generic_collections;
pub(crate) mod logger_configuration_hotspots;
pub(crate) mod optional_arguments_forwarded_to_base;
pub(crate) mod override_default_values_differ;
pub(crate) mod override_visibility_decrease;
pub(crate) mod parameter_names_drift_from_base;
pub(crate) mod params_introduced_on_overrides;
pub(crate) mod params_missing_on_overrides;
pub(crate) mod plaintext_password_storage;
pub(crate) mod random_in_security_contexts;
pub(crate) mod recursive_inheritance;
pub(crate) mod redundant_casts;
pub(crate) mod redundant_inheritance_entries;
pub(crate) mod redundant_null_comparisons;
pub(crate) mod redundant_to_string_calls;
pub(crate) mod reference_equality_on_values;
pub(crate) mod self_collection_arguments;
pub(crate) mod shared_lock_targets;
pub(crate) mod shift_right_operand_kinds;
pub(crate) mod static_iv_usage;
pub(crate) mod static_password_salts;
mod support;
mod walker;

pub(crate) use support::local_inheritance_graph;
pub(crate) use support::parameter_units;
pub(crate) use walker::tier_c_heuristic_issues;
