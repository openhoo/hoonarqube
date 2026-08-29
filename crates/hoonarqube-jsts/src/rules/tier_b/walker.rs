// Family walker for 'tier_b' (generated).
use super::collectors::ClassRuleCollector;
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
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::engine::scope_model::{TbFlow, TbHalt, build_tb_model};
use crate::support::{IssueSink, LineIndex, ScannedComment};
use hoonarqube_ir::Issue;
use oxc_ast_visit::Visit;
use std::collections::HashMap;

/// All Tier-B checks that run over the scope model.
fn check_tier_b_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
    comments: &[ScannedComment],
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
    check_tb_trailing_commas(program, source, index, comments, &mut sink);
    check_tb_shell_commands(program, &mut sink);
    check_tb_named_groups(program, &mut sink);
    sink.issues
}

/// `S1854` / `S2123` / `S1226` / `S4165` over the straight-line tracker.
fn check_tb_flow_rules<'p>(
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
        decl_kind: oxc_ast::ast::VariableDeclarationKind::Let,
        target_write_depth: 0,
    };
    flow.visit_program(program);
}

/// S1068 + S6441 + S6767 entry point; findings land directly in `sink`.
fn check_tb_class_rules<'a>(program: &'a oxc_ast::ast::Program<'a>, sink: &mut IssueSink<'a>) {
    let mut collector = ClassRuleCollector {
        sink: IssueSink {
            index: sink.index,
            language: sink.language,
            issues: Vec::new(),
        },
        frames: Vec::new(),
        finished_frames: Vec::new(),
        next_frame_id: 0,
        used_properties: Vec::new(),
        props_accessed: Vec::new(),
    };
    collector.visit_program(program);
    // All classes are finished only after the whole program was visited so
    // that usages appearing after a class declaration (`const a = new A();`
    // `a.go();`) are already attributed when the frame is judged.
    let frames = std::mem::take(&mut collector.finished_frames);
    for frame in &frames {
        collector.finish_class_frame(frame);
    }
    sink.issues.append(&mut collector.sink.issues);
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_tier_b_rules(
        ctx.program,
        ctx.source,
        ctx.index,
        ctx.language,
        &ctx.comments,
    )
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn dead_store_flagged_but_conditional_overwrite_kept_clean() {
        let flagged = js("function f() {\n  let x = compute();\n  x = 2;\n  return x;\n}\nf();\n");
        assert_eq!(filtered(&flagged, "S1854").len(), 1);
        let clean = js("function f() {\n  let x = compute();\n  return x;\n}\nf();\n");
        assert_eq!(filtered(&clean, "S1854").len(), 0);
        let conditional = js(
            "function g(c) {\n  let x = a();\n  if (c) {\n    x = b();\n  }\n  return x;\n}\ng(true);\n",
        );
        assert_eq!(filtered(&conditional, "S1854").len(), 0);
    }

    #[test]
    fn var_redeclaration_writes_but_let_shadowing_stays_silent() {
        // A `var` redeclaration overwrites the existing function-scoped
        // binding, so the initial value is a dead store. A block-scoped
        // `let` with the same name is a fresh entry, not an overwrite.
        let flagged =
            js("function f() {\n  var x = compute();\n  var x = 2;\n  return x;\n}\nf();\n");
        assert_eq!(filtered(&flagged, "S1854").len(), 1);
        let shadow = js(
            "function g() {\n  let y = compute();\n  {\n    let y = 2;\n    use(y);\n  }\n  return y;\n}\ng();\n",
        );
        assert_eq!(filtered(&shadow, "S1854").len(), 0);
    }

    #[test]
    fn dead_store_survives_branches_only_when_both_paths_agree() {
        let source = js(
            "function f(c) {\n  let x = a();\n  if (c) {\n    x = b();\n  } else {\n    x = b();\n  }\n  return x;\n}\nf(1);\n",
        );
        // The two overwrites live at different offsets, so the value may be
        // read from either path: nothing is reported.
        assert_eq!(filtered(&source, "S1854").len(), 0);
    }

    #[test]
    fn misleading_self_increment_flagged() {
        let flagged = js("function f() {\n  let i = 0;\n  i = i++;\n  return i;\n}\nf();\n");
        assert_eq!(filtered(&flagged, "S2123").len(), 1);
        assert_eq!(filtered(&flagged, "S1854").len(), 0);
        let clean = js("let i = 0;\ni += 1;\nuse(i);\n");
        assert_eq!(filtered(&clean, "S2123").len(), 0);
    }

    #[test]
    fn initial_value_overwrite_flagged_for_params_and_catch() {
        let param = js("function f(a) {\n  a = 1;\n  return a;\n}\nf(2);\n");
        assert_eq!(filtered(&param, "S1226").len(), 1);
        let caught =
            js("try {\n  risky();\n} catch (error) {\n  error = null;\n  log(error);\n}\n");
        assert_eq!(filtered(&caught, "S1226").len(), 1);
        let clean = js("function f(c) {\n  if (c) {\n    c = 1;\n  }\n  return c;\n}\nf(2);\n");
        assert_eq!(filtered(&clean, "S1226").len(), 0);
    }

    #[test]
    fn identical_repeated_write_prefers_redundant_assignment_key() {
        let flagged = js(
            "function f() {\n  let size = width();\n  size = width();\n  return size;\n}\nf();\n",
        );
        assert_eq!(filtered(&flagged, "S4165").len(), 1);
        assert_eq!(filtered(&flagged, "S1854").len(), 0);
    }

    #[test]
    fn flow_tracks_reads_uninitialized_declarations_and_nested_function_depth() {
        let read_before_overwrite =
            js("function f() {\n  let x = a();\n  use(x);\n  x = b();\n  return x;\n}\nf();\n");
        assert_eq!(filtered(&read_before_overwrite, "S1854").len(), 0);

        for source in [
            "function f() { let x; x = value(); return x; }\nf();\n",
            "function f() { var x = value(); var x; return x; }\nf();\n",
        ] {
            assert_eq!(filtered(&js(source), "S1854").len(), 0);
        }

        let nested = js(
            "if (condition) {\n  function f() { let x = a(); x = b(); return x; }\n  use(f);\n}\n",
        );
        assert_eq!(filtered(&nested, "S1854").len(), 1);

        let logical =
            js("function f(c) { let x = a(); c && use(x); x = b(); return x; }\nf(true);\n");
        assert_eq!(filtered(&logical, "S1854").len(), 0);

        let member_target =
            js("function f() { let x = a(); object[x] = (x = b()); return x; }\nf();\n");
        assert_eq!(filtered(&member_target, "S1854").len(), 0);

        let destructuring_target =
            js("function f() { let x = a(); [x] = items; return x; }\nf();\n");
        assert_eq!(filtered(&destructuring_target, "S1854").len(), 1);

        let destructuring_default =
            js("function f() { let x = a(); [x = use(x)] = []; x = b(); return x; }\nf();\n");
        assert_eq!(filtered(&destructuring_default, "S1854").len(), 1);
    }

    #[test]
    fn single_line_trailing_commas_flagged_but_multiline_kept() {
        let flagged = js("const colors = ['red', 'blue',];\nconst pair = {a: 1, b: 2,};\n");
        assert_eq!(filtered(&flagged, "S1537").len(), 2);
        assert_eq!(filtered(&flagged, "S3723").len(), 0);
        let clean_single = js("const colors = ['red', 'blue'];\n");
        assert_eq!(filtered(&clean_single, "S1537").len(), 0);
    }

    #[test]
    fn multiline_lists_require_trailing_commas() {
        let flagged =
            js("const sizes = [\n  'small',\n  'medium'\n];\nfunction tune(\n  a,\n  b\n) {}\n");
        assert_eq!(filtered(&flagged, "S3723").len(), 2);
        assert_eq!(filtered(&flagged, "S1537").len(), 0);
        let clean_multi = js("const sizes = [\n  'small',\n  'medium',\n];\n");
        assert_eq!(filtered(&clean_multi, "S3723").len(), 0);
    }

    #[test]
    fn call_and_new_argument_lists_follow_the_same_comma_contract() {
        let flagged = js("send(a, b,);\nnew Widget(x, y\n);\n");
        assert_eq!(filtered(&flagged, "S1537").len(), 1);
        assert_eq!(filtered(&flagged, "S3723").len(), 1);
    }

    #[test]
    fn destructuring_import_and_type_lists_follow_the_same_comma_contract() {
        let flagged = js(
            "const [a, b,] = arr;\nconst {c, d,} = obj;\nimport { e, f, } from 'm';\nexport { g, h, };\n",
        );
        assert_eq!(filtered(&flagged, "S1537").len(), 4);
        assert_eq!(filtered(&flagged, "S3723").len(), 0);
        let clean = js(
            "const [a, b] = arr;\nconst {c, d} = obj;\nimport { e, f } from 'm';\nexport { g, h };\n",
        );
        assert_eq!(filtered(&clean, "S1537").len(), 0);
        let multiline = ts("function tune<\n  T,\n  U\n>() {}\nconst {\n  a,\n  b\n} = obj;\n");
        assert_eq!(filtered(&multiline, "S3723").len(), 2);
        assert_eq!(filtered(&multiline, "S1537").len(), 0);
    }

    #[test]
    fn short_circuit_rhs_and_shadowing_declarations_stay_clean() {
        let logical = js(
            "function f(cond) {\n  let x = compute();\n  cond && (x = 1);\n  return x;\n}\nf(false);\n",
        );
        assert_eq!(filtered(&logical, "S1854").len(), 0);
        let nullish = js("function g(a) {\n  cond ?? (a = 1);\n  return a;\n}\ng(0);\n");
        assert_eq!(filtered(&nullish, "S1226").len(), 0);
        let control = js("function f() {\n  let x = compute();\n  x = 1;\n  return x;\n}\nf();\n");
        assert_eq!(filtered(&control, "S1854").len(), 1);

        let shadowed = js(
            "function f() {\n  let x = compute();\n  {\n    let x = 2;\n  }\n  return x;\n}\nf();\n",
        );
        assert_eq!(filtered(&shadowed, "S1854").len(), 0);
        let param_shadow = js("function f(p) {\n  {\n    let p = 2;\n  }\n  return p;\n}\nf(1);\n");
        assert_eq!(filtered(&param_shadow, "S1226").len(), 0);
    }

    #[test]
    fn var_redeclaration_reports_write_to_function_scoped_binding() {
        // The second `var x` rewrites the function-scoped binding, so the
        // unread first initialization is a dead store.
        let redeclared =
            js("function f() {\n  var x = compute();\n  var x = 2;\n  return x;\n}\nf();\n");
        assert_eq!(filtered(&redeclared, "S1854").len(), 1);

        // Redeclaring a parameter reports the overwritten incoming value.
        let param_redeclared = js("function f(p) {\n  var p = 2;\n  return p;\n}\nf(1);\n");
        assert_eq!(filtered(&param_redeclared, "S1226").len(), 1);

        // Block-scoped shadowing of the same name stays silent.
        let let_shadow = js(
            "function f() {\n  var x = compute();\n  {\n    let x = 2;\n  }\n  return x;\n}\nf();\n",
        );
        assert_eq!(filtered(&let_shadow, "S1854").len(), 0);
    }
}
