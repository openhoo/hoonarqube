// Family walker for 'batch2d' (generated).
use super::collectors::{
    ClassAccessorCollector, DuplicationCollector, FunctionMetricsCollector,
    KeywordPlacementCollector, PromiseFlowCollector,
};
use super::s3512_es_idioms::check_es_idioms;
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::engine::scope_model::collect_array_binding_names;
use crate::support::{IssueSink, LineIndex};
use hoonarqube_ir::Issue;
use oxc_ast_visit::Visit;

/// All Batch2d checks in one place: the control-flow remainder groups D/E
/// (`S3776`, `S3796`, `S3801`, `S3854`, `S3972`, `S3973`, `S4275`,
/// `S4619`, `S4634`, `S4822`, `S6635`, `S6671`, `S6861`, `S1067`,
/// `S1534`, `S1536`, `S1541`) and the ES2015+ idiom section (`S3358`,
/// `S3498`, `S3499`, `S3512`, `S3513`, `S3514`, `S3523`, `S4158`,
/// `S6582`, `S6594`).
fn check_batch2d_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut issues = check_function_metrics(program, index, language);
    issues.extend(check_class_accessors(program, index, language));
    issues.extend(check_keyword_placement(program, source, index, language));
    issues.extend(check_promise_flows(program, index, language));
    issues.extend(check_duplications(program, index, language));
    issues.extend(check_es_idioms(program, index, language));
    issues
}

fn check_function_metrics(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = FunctionMetricsCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

fn check_class_accessors(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = ClassAccessorCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

fn check_keyword_placement(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = KeywordPlacementCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        index,
    };
    collector.visit_program(program);
    collector.sink.issues
}

fn check_promise_flows(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = PromiseFlowCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        array_bindings: collect_array_binding_names(program),
    };
    collector.visit_program(program);
    collector.sink.issues
}

fn check_duplications(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = DuplicationCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        function_spans: Vec::new(),
    };
    collector.visit_program(program);
    collector.sink.issues
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_batch2d_rules(ctx.program, ctx.source, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn cognitive_complexity_threshold_and_nesting_weights() {
        // Five chained ifs: 1+2+3+4+5 = 15, exactly at the threshold: clean.
        let at_limit = js_keys(
            "function f(a) {\n  if (a) {\n    if (a) {\n      if (a) {\n        if (a) {\n          if (a) {}\n        }\n      }\n    }\n  }\n}\n",
        );
        assert_eq!(count_key(&at_limit, "javascript:S3776"), 0);

        // One more nesting level: 21 > 15.
        let over = js_keys(
            "function f(a) {\n  if (a) {\n    if (a) {\n      if (a) {\n        if (a) {\n          if (a) {\n            while (a) {}\n          }\n        }\n      }\n    }\n  }\n}\n",
        );
        assert_eq!(count_key(&over, "javascript:S3776"), 1);
        assert_eq!(
            over.iter()
                .find(|(key, _)| key == "javascript:S3776")
                .map(|(_, line)| *line),
            Some(1)
        );

        // Logical operator sequences: same chain counts once, a switch
        // counts again; nested functions are measured separately.
        let logicals = js_keys("function f(a, b) {\n  if (a && b && a && b || b) {}\n}\n");
        assert_eq!(count_key(&logicals, "javascript:S3776"), 0);
    }

    #[test]
    fn cyclomatic_complexity_boundary_is_ten() {
        let source = |count: usize| {
            let mut text = String::from("function f(a) {\n");
            for _ in 0..count {
                text.push_str("  if (a) {}\n");
            }
            text.push_str("}\n");
            js_keys(&text)
        };
        // 9 ifs + base 1 = 10: clean. 10 ifs = 11: flagged.
        assert_eq!(count_key(&source(9), "javascript:S1541"), 0);
        assert_eq!(count_key(&source(10), "javascript:S1541"), 1);
    }

    #[test]
    fn ternary_tests_are_not_visited_twice_for_complexity() {
        let source = "function f(a, b) {\n  (a && b) ? 1 : 2;\n  (a && b) ? 1 : 2;\n  (a && b) ? 1 : 2;\n  (a && b) ? 1 : 2;\n}\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S1541"), 0);
    }

    #[test]
    fn same_operator_boolean_chains_count_every_operator_for_cyclomatic() {
        // Ten `&&` links plus the base point: true complexity 11 > 10.
        let chained = js_keys(
            "function f(a){ return a && a.b && a.c && a.d && a.e && a.f && a.g && a.h && a.i && a.j && a.k; }\n",
        );
        assert_eq!(count_key(&chained, "javascript:S1541"), 1);

        // Cognitive complexity still weighs one identical-operator sequence
        // of the same operator once, so the same function stays clean.
        assert_eq!(count_key(&chained, "javascript:S3776"), 0);

        // Nullish coalescing chains are logical operators too.
        let nullish = js_keys(
            "function g(a){ return a ?? a.b ?? a.c ?? a.d ?? a.e ?? a.f ?? a.g ?? a.h ?? a.i ?? a.j ?? a.k; }\n",
        );
        assert_eq!(count_key(&nullish, "javascript:S1541"), 1);
    }

    #[test]
    fn switch_complexity_counts_case_clauses_only() {
        let source = |cases: usize| {
            let mut text = String::from("function f(x) {\n  switch (x) {\n");
            for i in 0..cases {
                text.push_str("    case ");
                text.push_str(&i.to_string());
                text.push_str(":\n      break;\n");
            }
            text.push_str("  }\n}\n");
            js_keys(&text)
        };
        // Nine case clauses + base 1 = 10: clean. The switch head itself
        // adds no decision point beyond its case clauses.
        assert_eq!(count_key(&source(9), "javascript:S1541"), 0);
        assert_eq!(count_key(&source(10), "javascript:S1541"), 1);
    }

    #[test]
    fn mixed_return_styles_are_flagged() {
        let mixed = js_keys("function f(c) {\n  if (c) {\n    return 1;\n  }\n  return;\n}\n");
        assert_eq!(count_key(&mixed, "javascript:S3801"), 1);

        // Valued returns plus an implicit fall-off end.
        let falls_off = js_keys("function g(c) {\n  if (c) {\n    return 1;\n  }\n}\n");
        assert_eq!(count_key(&falls_off, "javascript:S3801"), 1);

        let consistent =
            js_keys("function h(c) {\n  if (c) {\n    return 1;\n  }\n  return 2;\n}\n");
        assert_eq!(count_key(&consistent, "javascript:S3801"), 0);

        // Constructors, accessors, and generators are exempt.
        let exempt = js_keys(
            "class C {\n  constructor(c) {\n    if (c) {\n      return 1;\n    }\n  }\n  get v() {\n    return 2;\n  }\n}\nfunction* gen(c) {\n  if (c) {\n    return 1;\n  }\n  yield 2;\n}\n",
        );
        assert_eq!(count_key(&exempt, "javascript:S3801"), 0);
    }

    #[test]
    fn array_callbacks_without_returns_flagged_javascript_only() {
        let flagged = js_keys("[1].map(function f(x) {\n  g(x);\n});\n");
        assert_eq!(count_key(&flagged, "javascript:S3796"), 1);

        let block_arrow = js_keys("[1].filter(x => {\n  g(x);\n});\n");
        assert_eq!(count_key(&block_arrow, "javascript:S3796"), 1);

        // Expression-bodied arrows and valued callbacks are clean; forEach
        // callbacks legitimately return nothing and are never flagged.
        let clean = js_keys(
            "[1].map(x => x * 2);\n[1].every(function (x) {\n  return x > 0;\n});\n[1].forEach(function (x) {\n  g(x);\n});\n",
        );
        assert_eq!(count_key(&clean, "javascript:S3796"), 0);

        // A return inside a nested function does not count for the callback.
        let nested = js_keys(
            "[1].map(function (x) {\n  setTimeout(function () {\n    return 5;\n  });\n});\n",
        );
        assert_eq!(count_key(&nested, "javascript:S3796"), 1);

        let typescript = findings(
            "[1].map(function f(x) {\n  g(x);\n});\n",
            JstsLanguage::TypeScript,
        );
        assert_eq!(count_key(&typescript, "typescript:S3796"), 0);
    }

    #[test]
    fn constructor_super_call_defects_are_flagged() {
        // Missing super() with a base class.
        let missing = js_keys("class A extends B {\n  constructor() {\n    this.x = 1;\n  }\n}\n");
        assert_eq!(count_key(&missing, "javascript:S3854"), 2);

        // Duplicate super() calls.
        let duplicated =
            js_keys("class A extends B {\n  constructor() {\n    super();\n    super();\n  }\n}\n");
        assert_eq!(count_key(&duplicated, "javascript:S3854"), 1);

        // Conditional super() must move to the top.
        let conditional = js_keys(
            "class A extends B {\n  constructor(c) {\n    if (c) {\n      super();\n    }\n  }\n}\n",
        );
        assert_eq!(count_key(&conditional, "javascript:S3854"), 1);

        // Well-formed constructor: clean, and classes without heritage are
        // never flagged for a missing super().
        let clean = js_keys(
            "class A extends B {\n  constructor() {\n    super();\n    this.x = 1;\n  }\n}\nclass C {\n  constructor() {\n    this.x = 1;\n  }\n}\n",
        );
        assert_eq!(count_key(&clean, "javascript:S3854"), 0);
    }

    #[test]
    fn constructors_returning_values_are_flagged() {
        let flagged =
            js_keys("class A {\n  constructor() {\n    if (x) {\n      return 1;\n    }\n  }\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S6635"), 1);

        let bare_return = js_keys("class A {\n  constructor() {\n    return;\n  }\n}\n");
        assert_eq!(count_key(&bare_return, "javascript:S6635"), 0);
    }

    #[test]
    fn accessors_must_touch_their_named_field() {
        let getter_bad = js_keys(
            "class C {\n  get size() {\n    return this.length;\n  }\n}\nconst o = {\n  get count() {\n    return 1;\n  },\n};\n",
        );
        assert_eq!(count_key(&getter_bad, "javascript:S4275"), 2);

        let setter_bad =
            js_keys("class C {\n  set size(value) {\n    this.length = value;\n  }\n}\n");
        assert_eq!(count_key(&setter_bad, "javascript:S4275"), 1);

        let clean = js_keys(
            "class C {\n  get size() {\n    return this.size;\n  }\n  set size(value) {\n    this.size = value;\n  }\n}\n",
        );
        assert_eq!(count_key(&clean, "javascript:S4275"), 0);
    }

    #[test]
    fn else_catch_finally_keywords_must_sit_on_their_own_line() {
        let same_line_else = js_keys("if (a) {\n  b();\n} else {\n  c();\n}\n");
        assert_eq!(count_key(&same_line_else, "javascript:S3972"), 1);

        let same_line_catch =
            js_keys("try {\n  a();\n} catch (e) {\n  b(e);\n} finally {\n  c();\n}\n");
        assert_eq!(count_key(&same_line_catch, "javascript:S3972"), 2);

        let separated = js_keys(
            "if (a) {\n  b();\n}\nelse\n{\n  c();\n}\ntry {\n  a();\n}\ncatch (e) {\n  b(e);\n}\nfinally {\n  c();\n}\n",
        );
        assert_eq!(count_key(&separated, "javascript:S3972"), 0);
    }

    #[test]
    fn unbraced_bodies_must_be_indented_deeper() {
        let flagged = js_keys("function f() {\n  while (a)\n  b();\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S3973"), 1);

        // Same-line bodies and properly indented bodies are clean.
        let clean = js_keys("function f() {\n  if (a) b();\n  if (a)\n    c();\n}\n");
        assert_eq!(count_key(&clean, "javascript:S3973"), 0);
    }

    #[test]
    fn membership_in_operator_on_arrays_is_flagged() {
        let literal_rhs = js_keys("const ok = 'a' in obj;\nconst bad = 'a' in [1, 2];\n");
        assert_eq!(count_key(&literal_rhs, "javascript:S4619"), 1);

        let binding_rhs =
            js_keys("const xs = [];\nif ('a' in xs) {\n  g();\n}\nconst fine = k2 in obj;\n");
        assert_eq!(count_key(&binding_rhs, "javascript:S4619"), 1);
        // Object right-hand sides are untouched; only arrays flag.
    }

    #[test]
    fn immediately_settled_promise_executors_are_flagged() {
        let flagged = js_keys("new Promise(resolve => resolve(42));\n");
        assert_eq!(count_key(&flagged, "javascript:S4634"), 1);

        let async_work =
            js_keys("new Promise(resolve => {\n  setTimeout(() => resolve(42), 10);\n});\n");
        assert_eq!(count_key(&async_work, "javascript:S4634"), 0);
    }

    #[test]
    fn rejecting_literal_values_is_flagged() {
        let flagged = js_keys("Promise.reject('boom');\nfunction f(reject) {\n  reject(7);\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S6671"), 2);

        let clean = js_keys("Promise.reject(new Error('boom'));\n");
        assert_eq!(count_key(&clean, "javascript:S6671"), 0);
    }

    #[test]
    fn unawaited_promise_calls_inside_try_are_flagged() {
        let flagged = js_keys(
            "try {\n  fetch(url);\n  client.then(r => r.json());\n  await fetch(other);\n} catch (e) {\n  log(e);\n}\n",
        );
        assert_eq!(count_key(&flagged, "javascript:S4822"), 2);

        let awaited_only = js_keys("try {\n  await fetch(url);\n} catch (e) {\n  log(e);\n}\n");
        assert_eq!(count_key(&awaited_only, "javascript:S4822"), 0);
    }

    #[test]
    fn duplicated_object_and_class_keys_are_flagged() {
        let object = js_keys("const o = {\n  a: 1,\n  b: 2,\n  'a': 3,\n};\n");
        assert_eq!(count_key(&object, "javascript:S1534"), 1);

        // Getter plus setter of one name pair up; two getters collide.
        let class_dupes = js_keys(
            "class C {\n  m() {}\n  m() {}\n  get p() {}\n  set p(v) {}\n  get q() {}\n  get q() {}\n}\n",
        );
        assert_eq!(count_key(&class_dupes, "javascript:S1534"), 2);

        let clean = js_keys("const o = { a: 1, b: 2 };\nclass D {\n  x() {}\n  y() {}\n}\n");
        assert_eq!(count_key(&clean, "javascript:S1534"), 0);
    }

    #[test]
    fn duplicated_function_parameters_are_javascript_only() {
        let flagged = js_keys("function f(a, b, a) {\n  return a + b;\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S1536"), 1);

        let clean = js_keys("function f(a, b, c) {\n  return a + b;\n}\n");
        assert_eq!(count_key(&clean, "javascript:S1536"), 0);

        let typescript = findings(
            "function f(a, b, a) {\n  return a + b;\n}\n",
            JstsLanguage::TypeScript,
        );
        assert_eq!(count_key(&typescript, "typescript:S1536"), 0);
    }

    #[test]
    fn mutable_exports_are_flagged() {
        let flagged = js_keys("export let counter = 1;\nexport var legacy = 2;\n");
        assert_eq!(count_key(&flagged, "javascript:S6861"), 2);

        let clean = js_keys("export const stable = 1;\nconst renamed = 2;\nexport { renamed };\n");
        assert_eq!(count_key(&clean, "javascript:S6861"), 0);
    }

    #[test]
    fn condition_operator_limit_is_three() {
        let at_limit = js_keys("if (a && b && c && d) {\n  g();\n}\n");
        assert_eq!(count_key(&at_limit, "javascript:S1067"), 0);

        let over = js_keys("while (a && !b && c || d) {\n  g();\n}\n");
        assert_eq!(count_key(&over, "javascript:S1067"), 1);

        // Conditions inside nested functions are their own units and are
        // still examined when reached.
        let nested = js_keys("const g = () => {\n  if (a && b && c && d && e) {}\n};\n");
        assert_eq!(count_key(&nested, "javascript:S1067"), 1);
    }

    #[test]
    fn nested_ternaries_are_flagged_in_both_branches() {
        let flagged =
            js_keys("const a = cond ? (x ? 1 : 2) : 3;\nconst b = cond ? 1 : (y ? 2 : 3);\n");
        assert_eq!(count_key(&flagged, "javascript:S3358"), 2);

        let clean = js_keys("const ok = cond ? 1 : 2;\n");
        assert_eq!(count_key(&clean, "javascript:S3358"), 0);
    }

    #[test]
    fn shorthand_property_rules_flag_order_and_redundancy() {
        // `{ a: a }` should be shorthand.
        let redundant = js_keys("const o = { a: a };\n");
        assert_eq!(count_key(&redundant, "javascript:S3498"), 1);

        // Shorthand after non-shorthand is out of order; different names are
        // never flagged.
        let ordering = js_keys("const p = { a: 1, b, c: c };\n");
        assert_eq!(count_key(&ordering, "javascript:S3499"), 1);
        assert_eq!(count_key(&ordering, "javascript:S3498"), 1);

        let clean = js_keys("const q = { b, a: 1 };\n");
        assert_eq!(count_key(&clean, "javascript:S3499"), 0);
        assert_eq!(count_key(&clean, "javascript:S3498"), 0);
    }

    #[test]
    fn arguments_reads_are_flagged_unless_shadowed() {
        let flagged = js_keys("function f() {\n  return arguments.length;\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S3513"), 1);

        // A parameter named `arguments` shadows the built-in for its scope.
        let shadowed = js_keys("function g(arguments) {\n  return arguments.length;\n}\n");
        assert_eq!(count_key(&shadowed, "javascript:S3513"), 0);
    }

    #[test]
    fn temp_variable_swaps_suggest_destructuring() {
        let flagged = js_keys("let t = a;\na = b;\nb = t;\n");
        assert_eq!(count_key(&flagged, "javascript:S3514"), 1);

        // Unrelated statement sequences stay untouched.
        let clean = js_keys("let u = a;\nwork(u);\nreturn u;\n");
        assert_eq!(count_key(&clean, "javascript:S3514"), 0);
    }

    #[test]
    fn function_constructor_is_javascript_only() {
        let flagged = js_keys("const f = new Function('a', 'return a');\n");
        assert_eq!(count_key(&flagged, "javascript:S3523"), 1);

        let typescript = findings(
            "const f = new Function('a', 'return a');\n",
            JstsLanguage::TypeScript,
        );
        assert_eq!(count_key(&typescript, "typescript:S3523"), 0);
    }

    #[test]
    fn operations_on_empty_array_literals_are_flagged() {
        let member = js_keys("const n = [].length;\n[].forEach(g);\n");
        assert_eq!(count_key(&member, "javascript:S4158"), 2);

        let populated = js_keys("const m = [1].length;\n");
        assert_eq!(count_key(&populated, "javascript:S4158"), 0);
    }

    #[test]
    fn null_guards_rewrite_to_optional_chaining() {
        let flagged =
            js_keys("if (a !== null && a.b) {\n  g();\n}\nconst v = a !== undefined && a.b();\n");
        assert_eq!(count_key(&flagged, "javascript:S6582"), 2);

        // Guards whose right side does not use the guarded identifier, or
        // that already use optional chaining semantics on other roots, are
        // left alone.
        let unrelated = js_keys("if (a !== null && b.c) {\n  g();\n}\n");
        assert_eq!(count_key(&unrelated, "javascript:S6582"), 0);
    }

    #[test]
    fn truthy_and_multi_clause_guards_rewrite_to_optional_chaining() {
        // Plain truthy guard, the rule's headline form.
        let truthy = js_keys("if (a && a.b) {\n  g();\n}\n");
        assert_eq!(count_key(&truthy, "javascript:S6582"), 1);

        // Multi-clause guard resolves the same root and reports exactly
        // once, at the outermost chain span.
        let multi = js_keys("if (x !== null && x !== undefined && x.member) {\n  g();\n}\n");
        assert_eq!(count_key(&multi, "javascript:S6582"), 1);

        // A truthy chain whose right side never touches the guard stays clean.
        let clean = js_keys("if (a && b.c) {\n  g();\n}\n");
        assert_eq!(count_key(&clean, "javascript:S6582"), 0);
    }

    #[test]
    fn match_with_global_regex_prefers_match_all() {
        let flagged = js_keys("const hits = text.match(/ab/g);\n");
        assert_eq!(count_key(&flagged, "javascript:S6594"), 1);

        let no_global = js_keys("const one = text.match(/ab/);\n");
        assert_eq!(count_key(&no_global, "javascript:S6594"), 0);
    }
}
