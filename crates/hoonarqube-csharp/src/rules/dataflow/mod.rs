//! Intra-procedural dataflow/CFG approximations (Tier B).
//! Every pass below approximates a path-sensitive analysis with
//! statement-level reasoning and states its bound explicitly:
//! straight-line sequences inside one block, unconditional statements
//! only, and textual guard recognition. Passes prefer missing a finding
//! over reporting a wrong one — genuine path sensitivity is out of scope
//! here, so branch-dependent facts (a store dying on one path only, a
//! lock released on the exceptional path alone) are never reported.

pub(crate) mod always_false_conditions;
pub(crate) mod compare_after_assignment;
pub(crate) mod condition_true_at_least_once;
pub(crate) mod const_local_candidates;
pub(crate) mod counter_direction;
pub(crate) mod dead_stores;
pub(crate) mod double_dispose;
pub(crate) mod dynamic_sql;
pub(crate) mod empty_collection_access;
pub(crate) mod gratuitous_boolean_operands;
pub(crate) mod infinite_loops;
pub(crate) mod invariant_stop_conditions;
pub(crate) mod monitor_release_paths;
pub(crate) mod null_dereferences;
pub(crate) mod nullable_value_access;
pub(crate) mod overflow_prone_calculations;
pub(crate) mod single_iteration_loops;
pub(crate) mod stream_reads_unchecked;
mod support;
mod walker;

pub(crate) use monitor_release_paths::monitor_operations;
pub(crate) use support::WriteKind;
pub(crate) use support::callable_blocks;
pub(crate) use support::identifier_write;
pub(crate) use support::unary_operator;
pub(crate) use walker::dataflow_cfg_issues;
