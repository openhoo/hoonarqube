// Family 'tier_b' (generated).
pub(crate) mod collectors;
mod s1068_s6441_s6767_finish_class_frame;
mod s1117_tb_shadowing;
mod s1128_tb_unused_imports;
mod s1172_tb_unused_parameters;
mod s1481_tb_unused_locals;
mod s1526_tb_var_hoisting_order;
mod s1537_tb_trailing_commas;
mod s2077_tb_sql_injection;
mod s2259_tb_null_accesses;
mod s2392_tb_block_leaks;
mod s2589_tb_constant_conditions;
mod s2703_tb_implicit_globals;
mod s2814_tb_duplicates;
mod s2870_tb_delete_array_element;
mod s2933_tb_readonly_candidate_fields;
mod s2999_tb_constructor_resolution;
mod s3353_tb_let_to_const;
mod s3500_tb_const_reassigned;
mod s3686_tb_mixed_construction;
mod s3827_tb_use_before_declaration;
mod s4030_tb_useless_collections;
mod s4043_tb_in_place_captures;
mod s4143_tb_map_round_trips;
mod s4623_tb_explicit_undefined;
mod s4784_tb_dynamic_regexps;
mod s5443_tb_permissive_file_access;
mod s5725_tb_shell_commands;
mod s5860_tb_named_groups;
mod s5876_tb_session_regeneration;
mod s6486_tb_unstable_keys;
mod s6522_tb_import_reassigned;
mod s6544_tb_promise_chains;
mod s930_tb_arity;
mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs this combined walker family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
