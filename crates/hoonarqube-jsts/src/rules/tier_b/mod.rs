// Family 'tier_b' (generated).
pub(crate) mod collectors;
pub(crate) mod s1068_s6441_s6767_finish_class_frame;
pub(crate) mod s1117_tb_shadowing;
pub(crate) mod s1128_tb_unused_imports;
pub(crate) mod s1172_tb_unused_parameters;
pub(crate) mod s1481_tb_unused_locals;
pub(crate) mod s1526_tb_var_hoisting_order;
pub(crate) mod s1537_tb_trailing_commas;
pub(crate) mod s2077_tb_sql_injection;
pub(crate) mod s2259_tb_null_accesses;
pub(crate) mod s2392_tb_block_leaks;
pub(crate) mod s2589_tb_constant_conditions;
pub(crate) mod s2703_tb_implicit_globals;
pub(crate) mod s2814_tb_duplicates;
pub(crate) mod s2870_tb_delete_array_element;
pub(crate) mod s2933_tb_readonly_candidate_fields;
pub(crate) mod s2999_tb_constructor_resolution;
pub(crate) mod s3353_tb_let_to_const;
pub(crate) mod s3500_tb_const_reassigned;
pub(crate) mod s3686_tb_mixed_construction;
pub(crate) mod s3827_tb_use_before_declaration;
pub(crate) mod s4030_tb_useless_collections;
pub(crate) mod s4043_tb_in_place_captures;
pub(crate) mod s4143_tb_map_round_trips;
pub(crate) mod s4623_tb_explicit_undefined;
pub(crate) mod s4784_tb_dynamic_regexps;
pub(crate) mod s5443_tb_permissive_file_access;
pub(crate) mod s5725_tb_shell_commands;
pub(crate) mod s5860_tb_named_groups;
pub(crate) mod s5876_tb_session_regeneration;
pub(crate) mod s6486_tb_unstable_keys;
pub(crate) mod s6522_tb_import_reassigned;
pub(crate) mod s6544_tb_promise_chains;
pub(crate) mod s930_tb_arity;
pub(crate) mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs this combined walker family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
