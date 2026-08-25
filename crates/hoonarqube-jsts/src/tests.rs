use crate::test_support::*;
#[test]
fn extensions_map_to_languages() {
    assert_eq!(language_for_extension("js"), Some(Language::JavaScript));
    assert_eq!(language_for_extension("jsx"), Some(Language::JavaScript));
    assert_eq!(language_for_extension("mjs"), Some(Language::JavaScript));
    assert_eq!(language_for_extension("cjs"), Some(Language::JavaScript));
    assert_eq!(language_for_extension("ts"), Some(Language::TypeScript));
    assert_eq!(language_for_extension("tsx"), Some(Language::TypeScript));
    assert_eq!(language_for_extension("mts"), Some(Language::TypeScript));
    assert_eq!(language_for_extension("cts"), Some(Language::TypeScript));
    assert_eq!(language_for_extension("py"), Some(Language::Python));
}

#[test]
fn issues_are_sorted_by_position() {
    let source = "\
eval('a');
let b = x; let c = y;
";
    let report = js(source);
    let starts: Vec<_> = report
        .issues
        .iter()
        .map(|issue| {
            (
                issue.range.start.line,
                issue.range.start.column,
                issue.rule_key.clone(),
            )
        })
        .collect();
    assert_eq!(
        starts,
        vec![
            (1_u32, 0_u32, "javascript:S1523".to_string()),
            (2_u32, 11_u32, "javascript:S122".to_string()),
        ]
    );
}

#[test]
fn eval_usage_is_flagged_at_callee_span_across_the_tree() {
    let source = "\
eval('x');
const f = new Function('return 1');
foo(eval(nested));
window.eval('not plain identifier');
new window.Function('also ignored');

";
    let report = js(source);
    assert_eq!(
        report.issues,
        vec![
            issue(
                "javascript:S1523",
                "Remove this usage of 'eval'.",
                (1, 0),
                (1, 4),
            ),
            issue(
                "javascript:S1523",
                "Remove this usage of 'Function'.",
                (2, 14),
                (2, 22),
            ),
            issue(
                "javascript:S3523",
                "Remove this use of the \"Function\" constructor.",
                (2, 14),
                (2, 22),
            ),
            issue(
                "javascript:S1523",
                "Remove this usage of 'eval'.",
                (3, 4),
                (3, 8),
            ),
            issue(
                "javascript:S1848",
                "Use this object instantiation or remove it.",
                (5, 0),
                (5, 35),
            ),
        ]
    );
}

#[test]
fn typescript_input_parses_and_carries_typescript_prefix() {
    // `const X: number = 1;` would now legitimately raise `S3257`
    // (primitive annotation with initializer), so the smoke input keeps
    // its annotation without an initializer.
    let report = ts("let x: number;\ninterface Y { z: string; w: number }\n");
    assert_eq!(report.language, "typescript");
    assert!(report.issues.is_empty());
}

#[test]
fn jsx_input_parses_cleanly() {
    let report = analyze(
        PathBuf::from("test.jsx"),
        "const el = <div className=\"a\">hi</div>;\n",
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
    );
    assert!(report.issues.is_empty());
}

#[test]
fn broken_source_neither_panics_nor_emits_parse_errors() {
    let report = js("function {(:\n    ???\n");
    // No catalog-backed parse-error rule exists for js/ts; the analyzer
    // reports the file with zero issues instead of failing the run.
    assert!(report.issues.is_empty());
}

#[test]
fn comment_lines_are_counted_separately_from_code() {
    let report = ts("// leading note\nconst X: number = 1;\n/* block\nstill block */\n");
    assert_eq!(report.metrics.lines, 4);
    assert_eq!(report.metrics.code_lines, 1);
    assert_eq!(report.metrics.comment_lines, 3);
}

#[test]
fn comment_on_code_line_counts_as_code_only() {
    let report = js("let a = 1; // trailing\n");
    assert_eq!(report.metrics.code_lines, 1);
    assert_eq!(report.metrics.comment_lines, 0);
}

#[test]
fn scanner_ignores_comment_lookalikes_in_strings_templates_regexes() {
    let source = concat!(
        "const a = \"http://not-a-comment\";\n",
        "const b = `template // text ${x + 1} done`;\n",
        "const c = /regex\\/with\\/slashes/;\n",
        "const d = a / b;\n",
    );
    let report = js(source);
    assert_eq!(report.metrics.comment_lines, 0);
    assert_eq!(report.metrics.code_lines, 4);
}

#[test]
fn scanner_finds_comments_around_regex_and_division() {
    // Own-line comments survive; the regex and division on code lines
    // must not swallow or fabricate comment rows.
    let source = concat!(
        "// header\n",
        "function f() {\n",
        "  return /x/g.test(s);\n",
        "}\n",
        "// footer\n",
        "let d = a / b;\n",
    );
    let report = js(source);
    assert_eq!(report.metrics.comment_lines, 2);
    assert_eq!(report.metrics.code_lines, 4);
}

// ---- Batch-1 rule fixtures ----

// ===== Batch2a naming/format rule tests =====

// ===== Batch2a structural duplicate/identity rule tests =====

#[test]
fn text_scans_flag_tabs_trailing_whitespace_and_missing_newline() {
    let flagged = js_keys("const\t a = 1;  \nlet x;");
    assert_eq!(count_key(&flagged, "javascript:S105"), 1);
    assert_eq!(count_key(&flagged, "javascript:S1131"), 1);
    assert_eq!(count_key(&flagged, "javascript:S113"), 1);

    let clean = js_keys("const a = 1;\nlet x;\n");
    assert_eq!(count_key(&clean, "javascript:S105"), 0);
    assert_eq!(count_key(&clean, "javascript:S1131"), 0);
    assert_eq!(count_key(&clean, "javascript:S113"), 0);
}

#[test]
fn loc_and_function_length_boundaries_honor_rule_options() {
    let strict = RuleOptions {
        maximum_lines_of_code: 3,
        maximum_function_lines: 2,
        ..RuleOptions::default()
    };
    let report = js_with_rules("a();\nb();\nc();\nd();\n", &strict);
    assert_eq!(count_key(&report_keys(&report), "javascript:S104"), 1);

    let long_function = "function f() {\n  a();\n  b();\n  c();\n}\n";
    let flagged = js_with_rules(long_function, &strict);
    assert_eq!(count_key(&report_keys(&flagged), "javascript:S138"), 1);

    let relaxed = RuleOptions {
        maximum_lines_of_code: 1000,
        maximum_function_lines: 200,
        ..RuleOptions::default()
    };
    let clean = js_with_rules(long_function, &relaxed);
    assert_eq!(count_key(&report_keys(&clean), "javascript:S138"), 0);
}

#[test]
fn comment_tag_and_suppression_rules_fire_once_per_comment() {
    let flagged = js_keys("// FIXME later\n// TODO task\n// NOSONAR\n");
    assert_eq!(count_key(&flagged, "javascript:S1134"), 1);
    assert_eq!(count_key(&flagged, "javascript:S1135"), 1);
    assert_eq!(count_key(&flagged, "javascript:S1291"), 1);

    let clean = js_keys("// a note\n/* another */\n");
    assert_eq!(count_key(&clean, "javascript:S1134"), 0);
    assert_eq!(count_key(&clean, "javascript:S1135"), 0);
    assert_eq!(count_key(&clean, "javascript:S1291"), 0);
}

#[test]
fn javascript_only_rules_do_not_fire_for_typescript() {
    let source = "with (o) {}\nalert('hi');\nlegacy = require('m');\n";
    let typescript = findings(source, JstsLanguage::TypeScript);
    assert_eq!(count_key(&typescript, "typescript:S1321"), 0);
    assert_eq!(count_key(&typescript, "typescript:S1442"), 0);
    assert_eq!(count_key(&typescript, "typescript:S3533"), 0);
}

#[test]
fn parse_errors_never_surface_as_issues() {
    let broken = js_keys("function {(:\n    ???\n");
    assert!(broken.iter().all(|(key, _)| !key.ends_with(":S2260")));
}

// ===== Batch2b tests: statement-shape and control-flow walks =====

#[test]
fn pointless_expression_statements_flagged_directives_exempt() {
    let source = "\
\"use strict\";
42;
foo;
-1;
`plain`;
void 0;
foo();
`tpl${x}`;
delete obj.a;
";
    let report = js(source);
    let pointless_lines: Vec<u32> = report
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(":S905"))
        .map(|issue| issue.range.start.line)
        .collect();
    // The `"use strict"` directive prologue stays exempt; calls, template
    // substitutions, and `delete` have effects.
    assert_eq!(pointless_lines, vec![2, 3, 4, 5, 6]);
}

#[test]
fn opening_brace_must_share_head_token_line() {
    let bad =
        js("function bad()\n{\n  if (a)\n  {\n    b();\n  }\n  else\n  {\n    c();\n  }\n}\n");
    let braces: Vec<_> = bad
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(":S1105"))
        .map(|issue| (issue.range.start.line, issue.range.start.column))
        .collect();
    assert_eq!(braces, vec![(2, 0), (4, 2), (8, 2)]);

    let mixed = js(
        "class A\n{ m() { n(); } }\nswitch (x)\n{ case 1: p(); break; }\nconst f = () =>\n{ q(); };\n",
    );
    let braces: Vec<_> = mixed
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(":S1105"))
        .map(|issue| (issue.range.start.line, issue.range.start.column))
        .collect();
    assert_eq!(braces, vec![(2, 0), (4, 0), (6, 0)]);
}

#[test]
fn declare_then_return_and_throw_pairs_are_flagged() {
    let source = "\
function f() {
  const value = compute();
  return value;
}
function g() {
  let failure = build();
  throw failure;
}
function clean() {
  const kept = compute();
  return other;
}
";
    let report = js(source);
    let s1488: Vec<_> = report
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(":S1488"))
        .map(|issue| issue.range.start.line)
        .collect();
    assert_eq!(s1488, vec![2, 6]);
}

// Tests for the regex-literal, React/JSX, jsx-a11y, Batch-5 hotspot,
// and Tier-B rule families live in their per-rule modules
// (`rules/react_jsx`, `rules/jsx_a11y`, `rules/batch5`, `rules/tier_b`,
// `rules/regex_family`, ...), not in this file.
