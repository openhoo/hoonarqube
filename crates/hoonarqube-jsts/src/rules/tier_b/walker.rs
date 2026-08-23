// Family walker for 'tier_b' (generated).
use super::s930_tb_arity::check_tb_arity;
use super::s1117_tb_shadowing::check_tb_shadowing;
use super::s1128_tb_unused_imports::check_tb_unused_imports;
use super::s1172_tb_unused_parameters::check_tb_unused_parameters;
use super::s1481_tb_unused_locals::check_tb_unused_locals;
use super::s1526_tb_var_hoisting_order::check_tb_var_hoisting_order;
use super::s1537_tb_trailing_commas::check_tb_trailing_commas;
use super::s2077_tb_sql_injection::check_tb_sql_injection;
use super::s2259_tb_null_accesses::check_tb_null_accesses;
use super::s2392_tb_block_leaks::check_tb_block_leaks;
use super::s2589_tb_constant_conditions::check_tb_constant_conditions;
use super::s2703_tb_implicit_globals::check_tb_implicit_globals;
use super::s2814_tb_duplicates::check_tb_duplicates;
use super::s2870_tb_delete_array_element::check_tb_delete_array_element;
use super::s2933_tb_readonly_candidate_fields::check_tb_readonly_candidate_fields;
use super::s2999_tb_constructor_resolution::check_tb_constructor_resolution;
use super::s3353_tb_let_to_const::check_tb_let_to_const;
use super::s3500_tb_const_reassigned::check_tb_const_reassigned;
use super::s3686_tb_mixed_construction::check_tb_mixed_construction;
use super::s3827_tb_use_before_declaration::check_tb_use_before_declaration;
use super::s4030_tb_useless_collections::check_tb_useless_collections;
use super::s4043_tb_in_place_captures::check_tb_in_place_captures;
use super::s4143_tb_map_round_trips::check_tb_map_round_trips;
use super::s4623_tb_explicit_undefined::check_tb_explicit_undefined;
use super::s4784_tb_dynamic_regexps::check_tb_dynamic_regexps;
use super::s5443_tb_permissive_file_access::check_tb_permissive_file_access;
use super::s5725_tb_shell_commands::check_tb_shell_commands;
use super::s5860_tb_named_groups::check_tb_named_groups;
use super::s5876_tb_session_regeneration::check_tb_session_regeneration;
use super::s6486_tb_unstable_keys::check_tb_unstable_keys;
use super::s6522_tb_import_reassigned::check_tb_import_reassigned;
use super::s6544_tb_promise_chains::check_tb_promise_chains;
use crate::context::AnalysisContext;
use crate::engine::scope_model::{TbFlow, TbHalt, build_tb_model};
use crate::support::{IssueSink, LineIndex};
use crate::{ClassRuleCollector, JstsLanguage};
use hoonarqube_ir::Issue;
use oxc_ast_visit::Visit;
use std::collections::HashMap;

/// All Tier-B checks that run over the scope model.
pub(crate) fn check_tier_b_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut sink = IssueSink {
        index,
        language,
        issues: Vec::new(),
    };
    let model = build_tb_model(program);
    check_tb_shadowing(&model, &mut sink);
    check_tb_unused_imports(&model, &mut sink);
    check_tb_unused_locals(&model, &mut sink);
    check_tb_unused_parameters(&model, &mut sink);
    check_tb_implicit_globals(&model, &mut sink);
    check_tb_duplicates(&model, &mut sink);
    check_tb_const_reassigned(&model, &mut sink);
    check_tb_use_before_declaration(&model, &mut sink);
    check_tb_import_reassigned(&model, &mut sink);
    check_tb_var_hoisting_order(&model, &mut sink);
    check_tb_block_leaks(&model, &mut sink);
    let undefined_shadowed = model
        .bindings
        .iter()
        .any(|binding| binding.name == "undefined");
    check_tb_let_to_const(&model, program, &mut sink);
    check_tb_flow_rules(program, source, &mut sink);
    check_tb_null_accesses(program, &mut sink, undefined_shadowed);
    check_tb_constant_conditions(program, &mut sink);
    check_tb_arity(&model, &mut sink);
    check_tb_constructor_resolution(&model, &mut sink);
    check_tb_mixed_construction(&model, &mut sink);
    check_tb_delete_array_element(&model, &mut sink);
    check_tb_explicit_undefined(&model, &mut sink);
    check_tb_class_rules(program, &mut sink);
    check_tb_sql_injection(program, &mut sink);
    check_tb_useless_collections(program, &mut sink);
    check_tb_in_place_captures(program, &mut sink);
    check_tb_map_round_trips(program, source, &mut sink);
    check_tb_permissive_file_access(program, &mut sink);
    check_tb_readonly_candidate_fields(program, &mut sink);
    check_tb_dynamic_regexps(program, &mut sink);
    check_tb_session_regeneration(program, source, &mut sink);
    check_tb_unstable_keys(program, &mut sink);
    check_tb_promise_chains(program, &mut sink);
    check_tb_trailing_commas(program, source, index, &mut sink);
    check_tb_shell_commands(program, &mut sink);
    check_tb_named_groups(program, &mut sink);
    sink.issues
}

/// `S1854` / `S2123` / `S1226` / `S4165` over the straight-line tracker.
pub(crate) fn check_tb_flow_rules<'p>(
    program: &'p oxc_ast::ast::Program<'p>,
    source: &str,
    sink: &mut IssueSink<'_>,
) {
    let mut flow = TbFlow {
        source,
        sink,
        env: HashMap::new(),
        status: TbHalt::Live,
        depth: 0,
        mutable_decl: false,
    };
    flow.visit_program(program);
}

/// S1068 + S6441 + S6767 entry point; findings land directly in `sink`.
pub(crate) fn check_tb_class_rules<'a>(
    program: &'a oxc_ast::ast::Program<'a>,
    sink: &mut IssueSink<'a>,
) {
    let mut collector = ClassRuleCollector {
        sink: IssueSink {
            index: sink.index,
            language: sink.language,
            issues: Vec::new(),
        },
        frames: Vec::new(),
        used_properties: Vec::new(),
        props_accessed: Vec::new(),
    };
    collector.visit_program(program);
    sink.issues.append(&mut collector.sink.issues);
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_tier_b_rules(ctx.program, ctx.source, ctx.index, ctx.language)
}
