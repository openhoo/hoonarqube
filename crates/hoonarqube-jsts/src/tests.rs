use crate::test_support::{
    AnalyzerOptions, JstsLanguage, Language, PathBuf, RuleOptions, analyze, count_key, findings,
    issue, js, js_keys, js_with_rules, language_for_extension, report_keys, ts,
};
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
                "javascript:S3523",
                "The Function constructor is eval.",
                (2, 10),
                (2, 34),
            ),
            issue(
                "javascript:S1523",
                "Remove this usage of 'Function'.",
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
                "Either remove this useless object instantiation of \"window.Function\" or use it.",
                (5, 0),
                (5, 19),
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
fn broken_source_neither_panics_nor_hides_parse_errors() {
    // `javascript:S2260` / `typescript:S2260` are catalog-backed; recoverable
    // parse errors surface as issues while the partial AST is still analyzed
    // tolerantly instead of failing the run.
    let report = js("function {(:\n    ???\n");
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.rule_key == "javascript:S2260")
    );
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
fn javascript_only_rules_stay_suppressed_while_shared_require_rule_fires() {
    let source = "with (o) {}\nalert('hi');\nlegacy = require('m');\n";
    let typescript = findings(source, JstsLanguage::TypeScript);
    assert_eq!(count_key(&typescript, "typescript:S1321"), 0);
    assert_eq!(count_key(&typescript, "typescript:S1442"), 0);
    assert_eq!(count_key(&typescript, "typescript:S3533"), 1);
}

#[test]
fn parse_errors_emit_s2260() {
    let report = js_with_rules("function {(:\n    ???\n", &RuleOptions::default());
    let parse_errors: Vec<_> = report
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "javascript:S2260")
        .collect();
    assert!(!parse_errors.is_empty());
    assert!(
        parse_errors
            .iter()
            .all(|issue| issue.message.starts_with("Fix this syntax error: "))
    );
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

const TRACKED_JAVASCRIPT_ORACLE_CASES: &[(&str, &str, &str, usize)] = &[
    ("javascript:S100", "s100_bad.js", "s100_good.js", 1),
    ("javascript:S101", "s101_bad.js", "s101_good.js", 1),
    ("javascript:S131", "s131_bad.js", "s131_good.js", 1),
    ("javascript:S1523", "s1523_bad.js", "s1523_good.js", 1),
    ("javascript:S2301", "s2301_bad.js", "s2301_good.js", 1),
    ("javascript:S1068", "s1068_bad.js", "s1068_good.js", 1),
    ("javascript:S2432", "s2432_bad.js", "s2432_good.js", 1),
    ("javascript:S3800", "s3800_bad.js", "s3800_good.js", 1),
    ("javascript:S1186", "s1186_bad.js", "s1186_good.js", 1),
    ("javascript:S6637", "s6637_bad.js", "s6637_good.js", 1),
    ("javascript:S6676", "s6676_bad.js", "s6676_good.js", 1),
    ("javascript:S6666", "s6666_bad.js", "s6666_good.js", 1),
    ("javascript:S6959", "s6959_bad.js", "s6959_good.js", 1),
    ("javascript:S2871", "s2871_bad.js", "s2871_good.js", 1),
    ("javascript:S6653", "s6653_bad.js", "s6653_good.js", 1),
    ("javascript:S3533", "s3533_bad.js", "s3533_good.js", 1),
    ("javascript:S2817", "s2817_bad.js", "s2817_good.js", 1),
    ("javascript:S4624", "s4624_bad.js", "s4624_good.js", 1),
    ("javascript:S6657", "s6657_bad.js", "s6657_good.js", 1),
    ("javascript:S4140", "s4140_bad.js", "s4140_good.js", 1),
    ("javascript:S1516", "s1516_bad.js", "s1516_good.js", 1),
    ("javascript:S2685", "s2685_bad.js", "s2685_good.js", 1),
    ("javascript:S6654", "s6654_bad.js", "s6654_good.js", 1),
    ("javascript:S6661", "s6661_bad.js", "s6661_good.js", 1),
    ("javascript:S1110", "s1110_bad.js", "s1110_good.js", 1),
    ("javascript:S1529", "s1529_bad.js", "s1529_good.js", 1),
    ("javascript:S3735", "s3735_bad.js", "s3735_good.js", 1),
    ("javascript:S6638", "s6638_bad.js", "s6638_good.js", 1),
    ("javascript:S106", "s106_bad.js", "s106_good.js", 1),
    ("javascript:S878", "s878_bad.js", "s878_good.js", 1),
    ("javascript:S1116", "s1116_bad.js", "s1116_good.js", 1),
    ("javascript:S1321", "s1321_bad.js", "s1321_good.js", 1),
    ("javascript:S1525", "s1525_bad.js", "s1525_good.js", 1),
    ("javascript:S2208", "s2208_bad.js", "s2208_good.js", 1),
    ("javascript:S3504", "s3504_bad.js", "s3504_good.js", 1),
    ("javascript:S3696", "s3696_bad.js", "s3696_good.js", 1),
    ("javascript:S3984", "s3984_bad.js", "s3984_good.js", 1),
    ("javascript:S6836", "s6836_bad.js", "s6836_good.js", 1),
    ("javascript:S6859", "s6859_bad.js", "s6859_good.js", 1),
    ("javascript:S1117", "s1117_bad.js", "s1117_good.js", 1),
    ("javascript:S1128", "s1128_bad.js", "s1128_good.js", 1),
    ("javascript:S1172", "s1172_bad.js", "s1172_good.js", 1),
    ("javascript:S1226", "s1226_bad.js", "s1226_good.js", 1),
    ("javascript:S1481", "s1481_bad.js", "s1481_good.js", 1),
    ("javascript:S1526", "s1526_bad.js", "s1526_good.js", 1),
    ("javascript:S1537", "s1537_bad.js", "s1537_good.js", 2),
    ("javascript:S1854", "s1854_bad.js", "s1854_good.js", 1),
    ("javascript:S2077", "s2077_bad.js", "s2077_good.js", 2),
    ("javascript:S2123", "s2123_bad.js", "s2123_good.js", 1),
    ("javascript:S2259", "s2259_bad.js", "s2259_good.js", 1),
    ("javascript:S2392", "s2392_bad.js", "s2392_good.js", 1),
    ("javascript:S2589", "s2589_bad.js", "s2589_good.js", 1),
    ("javascript:S2703", "s2703_bad.js", "s2703_good.js", 1),
    ("javascript:S2814", "s2814_bad.js", "s2814_good.js", 1),
    ("javascript:S2870", "s2870_bad.js", "s2870_good.js", 1),
    ("javascript:S2999", "s2999_bad.js", "s2999_good.js", 1),
    ("javascript:S3353", "s3353_bad.js", "s3353_good.js", 1),
    ("javascript:S3500", "s3500_bad.js", "s3500_good.js", 1),
    ("javascript:S3686", "s3686_bad.js", "s3686_good.js", 1),
    ("javascript:S3723", "s3723_bad.js", "s3723_good.js", 2),
    ("javascript:S3827", "s3827_bad.js", "s3827_good.js", 1),
    ("javascript:S4030", "s4030_bad.js", "s4030_good.js", 1),
    ("javascript:S4043", "s4043_bad.js", "s4043_good.js", 1),
    ("javascript:S4143", "s4143_bad.js", "s4143_good.js", 1),
    ("javascript:S4165", "s4165_bad.js", "s4165_good.js", 1),
    ("javascript:S4784", "s4784_bad.js", "s4784_good.js", 3),
    ("javascript:S5443", "s5443_bad.js", "s5443_good.js", 2),
    ("javascript:S5725", "s5725_bad.js", "s5725_good.js", 2),
    ("javascript:S5876", "s5876_bad.js", "s5876_good.js", 1),
    ("javascript:S6486", "s6486_bad.jsx", "s6486_good.jsx", 1),
    ("javascript:S6522", "s6522_bad.js", "s6522_good.js", 1),
    ("javascript:S6544", "s6544_bad.js", "s6544_good.js", 1),
    ("javascript:S6249", "s6249_bad.js", "s6249_good.js", 1),
    ("javascript:S6252", "s6252_bad.js", "s6252_good.js", 1),
    ("javascript:S6265", "s6265_bad.js", "s6265_good.js", 1),
    ("javascript:S6270", "s6270_bad.js", "s6270_good.js", 1),
    ("javascript:S6275", "s6275_bad.js", "s6275_good.js", 1),
    ("javascript:S6281", "s6281_bad.js", "s6281_good.js", 1),
    ("javascript:S6302", "s6302_bad.js", "s6302_good.js", 1),
    ("javascript:S6303", "s6303_bad.js", "s6303_good.js", 1),
    ("javascript:S6304", "s6304_bad.js", "s6304_good.js", 1),
    ("javascript:S6308", "s6308_bad.js", "s6308_good.js", 1),
    ("javascript:S6317", "s6317_bad.js", "s6317_good.js", 1),
    ("javascript:S6319", "s6319_bad.js", "s6319_good.js", 1),
    ("javascript:S6321", "s6321_bad.js", "s6321_good.js", 2),
    ("javascript:S6327", "s6327_bad.js", "s6327_good.js", 1),
    ("javascript:S6329", "s6329_bad.js", "s6329_good.js", 2),
    ("javascript:S6330", "s6330_bad.js", "s6330_good.js", 2),
    ("javascript:S6332", "s6332_bad.js", "s6332_good.js", 2),
    ("javascript:S6333", "s6333_bad.js", "s6333_good.js", 2),
];

#[test]
fn tracked_javascript_oracle_pairs_trigger_only_the_bad_control() {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.oracle/sonar/projects/oracle-js/src");
    for &(key, bad_name, good_name, expected_bad_count) in TRACKED_JAVASCRIPT_ORACLE_CASES {
        let bad_path = project.join(bad_name);
        let bad_source = std::fs::read_to_string(&bad_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", bad_path.display()));
        let bad = analyze(
            bad_path,
            &bad_source,
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            bad.issues
                .iter()
                .filter(|issue| issue.rule_key == key)
                .count(),
            expected_bad_count,
            "bad oracle control for {key}",
        );

        let good_path = project.join(good_name);
        let good_source = std::fs::read_to_string(&good_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", good_path.display()));
        let good = analyze(
            good_path,
            &good_source,
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            good.issues
                .iter()
                .filter(|issue| issue.rule_key == key)
                .count(),
            0,
            "good oracle control for {key}",
        );
    }
}

const TRACKED_TYPESCRIPT_ORACLE_CASES: &[(&str, &str, &str, usize)] = &[
    ("typescript:S100", "s100_bad.ts", "s100_good.ts", 1),
    ("typescript:S101", "s101_bad.ts", "s101_good.ts", 1),
    ("typescript:S131", "s131_bad.ts", "s131_good.ts", 1),
    ("typescript:S1523", "s1523_bad.ts", "s1523_good.ts", 1),
    ("typescript:S2301", "s2301_bad.ts", "s2301_good.ts", 1),
    ("typescript:S3533", "s3533_bad.ts", "s3533_good.ts", 1),
    ("typescript:S1186", "s1186_bad.ts", "s1186_good.ts", 1),
    ("typescript:S2094", "s2094_bad.ts", "s2094_good.ts", 1),
    ("typescript:S2137", "s2137_bad.ts", "s2137_good.ts", 1),
    ("typescript:S2138", "s2138_bad.ts", "s2138_good.ts", 1),
    ("typescript:S4326", "s4326_bad.ts", "s4326_good.ts", 1),
    ("typescript:S5856", "s5856_bad.ts", "s5856_good.ts", 1),
    ("typescript:S6249", "s6249_bad.ts", "s6249_good.ts", 1),
    ("typescript:S6522", "s6522_bad.ts", "s6522_good.ts", 1),
    ("typescript:S6523", "s6523_bad.ts", "s6523_good.ts", 1),
    ("typescript:S6551", "s6551_bad.ts", "s6551_good.ts", 1),
    ("typescript:S6647", "s6647_bad.ts", "s6647_good.ts", 1),
    ("typescript:S108", "s108_bad.ts", "s108_good.ts", 1),
    ("typescript:S109", "s109_bad.ts", "s109_good.ts", 1),
    ("typescript:S117", "s117_bad.ts", "s117_good.ts", 1),
    ("typescript:S121", "s121_bad.ts", "s121_good.ts", 1),
    ("typescript:S122", "s122_bad.ts", "s122_good.ts", 1),
    ("typescript:S126", "s126_bad.ts", "s126_good.ts", 1),
    ("typescript:S128", "s128_bad.ts", "s128_good.ts", 1),
    ("typescript:S138", "s138_bad.ts", "s138_good.ts", 1),
    ("typescript:S1940", "s1940_bad.ts", "s1940_good.ts", 1),
    ("typescript:S2234", "s2234_bad.ts", "s2234_good.ts", 1),
    ("typescript:S2486", "s2486_bad.ts", "s2486_good.ts", 1),
    ("typescript:S2737", "s2737_bad.ts", "s2737_good.ts", 1),
    ("typescript:S3524", "s3524_bad.ts", "s3524_good.ts", 1),
    ("typescript:S1077", "s1077_bad.tsx", "s1077_good.tsx", 1),
    ("typescript:S1082", "s1082_bad.tsx", "s1082_good.tsx", 1),
    ("typescript:S1090", "s1090_bad.tsx", "s1090_good.tsx", 1),
    ("typescript:S4084", "s4084_bad.tsx", "s4084_good.tsx", 1),
    ("typescript:S5254", "s5254_bad.tsx", "s5254_good.tsx", 1),
    ("typescript:S5256", "s5256_bad.tsx", "s5256_good.tsx", 1),
    ("typescript:S5257", "s5257_bad.tsx", "s5257_good.tsx", 1),
    ("typescript:S5260", "s5260_bad.tsx", "s5260_good.tsx", 1),
    ("typescript:S5264", "s5264_bad.tsx", "s5264_good.tsx", 1),
    ("typescript:S6793", "s6793_bad.tsx", "s6793_good.tsx", 1),
    ("typescript:S6807", "s6807_bad.tsx", "s6807_good.tsx", 1),
    ("typescript:S6811", "s6811_bad.tsx", "s6811_good.tsx", 1),
    ("typescript:S6819", "s6819_bad.tsx", "s6819_good.tsx", 1),
    ("typescript:S6821", "s6821_bad.tsx", "s6821_good.tsx", 1),
    ("typescript:S6822", "s6822_bad.tsx", "s6822_good.tsx", 1),
    ("typescript:S6823", "s6823_bad.tsx", "s6823_good.tsx", 1),
    ("typescript:S6824", "s6824_bad.tsx", "s6824_good.tsx", 1),
    ("typescript:S6825", "s6825_bad.tsx", "s6825_good.tsx", 1),
    ("typescript:S6827", "s6827_bad.tsx", "s6827_good.tsx", 1),
    ("typescript:S6840", "s6840_bad.tsx", "s6840_good.tsx", 1),
    ("typescript:S6841", "s6841_bad.tsx", "s6841_good.tsx", 1),
    ("typescript:S6842", "s6842_bad.tsx", "s6842_good.tsx", 1),
    ("typescript:S6843", "s6843_bad.tsx", "s6843_good.tsx", 1),
    ("typescript:S6844", "s6844_bad.tsx", "s6844_good.tsx", 1),
    ("typescript:S6845", "s6845_bad.tsx", "s6845_good.tsx", 1),
    ("typescript:S6846", "s6846_bad.tsx", "s6846_good.tsx", 1),
    ("typescript:S6847", "s6847_bad.tsx", "s6847_good.tsx", 1),
    ("typescript:S6848", "s6848_bad.tsx", "s6848_good.tsx", 1),
    ("typescript:S6850", "s6850_bad.tsx", "s6850_good.tsx", 1),
    ("typescript:S6851", "s6851_bad.tsx", "s6851_good.tsx", 1),
    ("typescript:S6852", "s6852_bad.tsx", "s6852_good.tsx", 1),
    ("typescript:S6853", "s6853_bad.tsx", "s6853_good.tsx", 1),
    ("typescript:S1068", "s1068_bad.ts", "s1068_good.ts", 1),
    ("typescript:S2933", "s2933_bad.ts", "s2933_good.ts", 1),
    ("typescript:S4623", "s4623_bad.ts", "s4623_good.ts", 1),
    ("typescript:S4323", "s4323_bad.ts", "s4323_good.ts", 1),
    ("typescript:S4327", "s4327_bad.ts", "s4327_good.ts", 1),
    ("typescript:S1128", "s1128_bad.ts", "s1128_good.ts", 1),
    ("typescript:S1526", "s1526_bad.ts", "s1526_good.ts", 1),
    (
        "typescript:S1607",
        "s1607_bad.test.ts",
        "s1607_good.test.ts",
        1,
    ),
    (
        "typescript:S2187",
        "s2187_bad.test.ts",
        "s2187_good.test.ts",
        1,
    ),
    (
        "typescript:S2699",
        "s2699_bad.test.ts",
        "s2699_good.test.ts",
        1,
    ),
    (
        "typescript:S2970",
        "s2970_bad.test.ts",
        "s2970_good.test.ts",
        1,
    ),
    (
        "typescript:S3415",
        "s3415_bad.test.ts",
        "s3415_good.test.ts",
        1,
    ),
    (
        "typescript:S5863",
        "s5863_bad.test.ts",
        "s5863_good.test.ts",
        1,
    ),
    (
        "typescript:S5958",
        "s5958_bad.test.ts",
        "s5958_good.test.ts",
        1,
    ),
    (
        "typescript:S5973",
        "s5973_bad.test.ts",
        "s5973_good.test.ts",
        1,
    ),
    (
        "typescript:S6079",
        "s6079_bad.test.ts",
        "s6079_good.test.ts",
        1,
    ),
    (
        "typescript:S6080",
        "s6080_bad.test.ts",
        "s6080_good.test.ts",
        1,
    ),
    (
        "typescript:S6092",
        "s6092_bad.test.ts",
        "s6092_good.test.ts",
        1,
    ),
    (
        "typescript:S6426",
        "s6426_bad.test.ts",
        "s6426_good.test.ts",
        2,
    ),
    ("typescript:S103", "s103_bad.ts", "s103_good.ts", 1),
    ("typescript:S105", "s105_bad.ts", "s105_good.ts", 1),
    ("typescript:S1131", "s1131_bad.ts", "s1131_good.ts", 1),
    ("typescript:S1134", "s1134_bad.ts", "s1134_good.ts", 1),
    ("typescript:S1135", "s1135_bad.ts", "s1135_good.ts", 1),
    ("typescript:S125", "s125_bad.ts", "s125_good.ts", 1),
    ("typescript:S1291", "s1291_bad.ts", "s1291_good.ts", 1),
    ("typescript:S139", "s139_bad.ts", "s139_good.ts", 1),
    ("typescript:S2068", "s2068_bad.ts", "s2068_good.ts", 1),
    ("typescript:S3799", "s3799_bad.ts", "s3799_good.ts", 1),
    ("typescript:S6418", "s6418_bad.ts", "s6418_good.ts", 1),
    ("typescript:S6650", "s6650_bad.ts", "s6650_good.ts", 1),
    ("typescript:S1764", "s1764_bad.ts", "s1764_good.ts", 1),
    ("typescript:S1862", "s1862_bad.ts", "s1862_good.ts", 1),
    ("typescript:S1871", "s1871_bad.ts", "s1871_good.ts", 1),
    ("typescript:S3516", "s3516_bad.ts", "s3516_good.ts", 1),
    ("typescript:S3923", "s3923_bad.ts", "s3923_good.ts", 1),
    ("typescript:S4144", "s4144_bad.ts", "s4144_good.ts", 1),
    ("typescript:S1105", "s1105_bad.ts", "s1105_good.ts", 1),
    ("typescript:S1472", "s1472_bad.ts", "s1472_good.ts", 1),
    ("typescript:S1121", "s1121_bad.ts", "s1121_good.ts", 1),
    ("typescript:S1067", "s1067_bad.ts", "s1067_good.ts", 1),
    ("typescript:S1534", "s1534_bad.ts", "s1534_good.ts", 1),
    ("typescript:S1541", "s1541_bad.ts", "s1541_good.ts", 1),
    ("typescript:S3358", "s3358_bad.ts", "s3358_good.ts", 1),
    ("typescript:S3498", "s3498_bad.ts", "s3498_good.ts", 1),
    ("typescript:S3499", "s3499_bad.ts", "s3499_good.ts", 1),
    ("typescript:S3512", "s3512_bad.ts", "s3512_good.ts", 1),
    ("typescript:S3513", "s3513_bad.ts", "s3513_good.ts", 1),
    ("typescript:S3514", "s3514_bad.ts", "s3514_good.ts", 1),
    ("typescript:S3776", "s3776_bad.ts", "s3776_good.ts", 1),
    ("typescript:S3801", "s3801_bad.ts", "s3801_good.ts", 1),
    ("typescript:S3854", "s3854_bad.ts", "s3854_good.ts", 2),
    ("typescript:S3972", "s3972_bad.ts", "s3972_good.ts", 3),
    ("typescript:S3973", "s3973_bad.ts", "s3973_good.ts", 1),
    ("typescript:S4158", "s4158_bad.ts", "s4158_good.ts", 2),
    ("typescript:S4275", "s4275_bad.ts", "s4275_good.ts", 2),
    ("typescript:S4619", "s4619_bad.ts", "s4619_good.ts", 1),
    ("typescript:S4634", "s4634_bad.ts", "s4634_good.ts", 1),
    ("typescript:S4822", "s4822_bad.ts", "s4822_good.ts", 2),
    ("typescript:S6582", "s6582_bad.ts", "s6582_good.ts", 2),
    ("typescript:S6594", "s6594_bad.ts", "s6594_good.ts", 1),
    ("typescript:S6635", "s6635_bad.ts", "s6635_good.ts", 1),
    ("typescript:S6671", "s6671_bad.ts", "s6671_good.ts", 2),
    ("typescript:S6861", "s6861_bad.ts", "s6861_good.ts", 2),
    ("typescript:S1264", "s1264_bad.ts", "s1264_good.ts", 1),
    ("typescript:S1535", "s1535_bad.ts", "s1535_good.ts", 1),
    ("typescript:S1751", "s1751_bad.ts", "s1751_good.ts", 1),
    ("typescript:S1994", "s1994_bad.ts", "s1994_good.ts", 1),
    ("typescript:S2251", "s2251_bad.ts", "s2251_good.ts", 1),
    ("typescript:S2310", "s2310_bad.ts", "s2310_good.ts", 1),
    ("typescript:S4138", "s4138_bad.ts", "s4138_good.ts", 1),
    ("typescript:S4139", "s4139_bad.ts", "s4139_good.ts", 1),
    ("typescript:S1219", "s1219_bad.ts", "s1219_good.ts", 1),
    ("typescript:S1439", "s1439_bad.ts", "s1439_good.ts", 1),
    ("typescript:S1515", "s1515_bad.ts", "s1515_good.ts", 1),
    ("typescript:S1530", "s1530_bad.ts", "s1530_good.ts", 1),
    ("typescript:S1788", "s1788_bad.ts", "s1788_good.ts", 1),
    ("typescript:S2004", "s2004_bad.ts", "s2004_good.ts", 1),
    ("typescript:S2376", "s2376_bad.ts", "s2376_good.ts", 1),
    ("typescript:S3001", "s3001_bad.ts", "s3001_good.ts", 1),
    ("typescript:S3525", "s3525_bad.ts", "s3525_good.ts", 1),
    ("typescript:S3531", "s3531_bad.ts", "s3531_good.ts", 1),
    ("typescript:S3626", "s3626_bad.ts", "s3626_good.ts", 1),
    ("typescript:S1143", "s1143_bad.ts", "s1143_good.ts", 1),
    ("typescript:S5332", "s5332_bad.ts", "s5332_good.ts", 1),
    ("typescript:S5527", "s5527_bad.ts", "s5527_good.ts", 1),
    ("typescript:S5542", "s5542_bad.ts", "s5542_good.ts", 1),
    ("typescript:S5547", "s5547_bad.ts", "s5547_good.ts", 1),
    ("typescript:S5604", "s5604_bad.ts", "s5604_good.ts", 1),
    ("typescript:S5659", "s5659_bad.ts", "s5659_good.ts", 1),
    ("typescript:S5689", "s5689_bad.ts", "s5689_good.ts", 1),
    ("typescript:S5691", "s5691_bad.ts", "s5691_good.ts", 1),
    ("typescript:S5693", "s5693_bad.ts", "s5693_good.ts", 1),
    ("typescript:S5728", "s5728_bad.ts", "s5728_good.ts", 1),
    ("typescript:S5730", "s5730_bad.ts", "s5730_good.ts", 1),
    ("typescript:S5732", "s5732_bad.ts", "s5732_good.ts", 1),
    ("typescript:S5734", "s5734_bad.ts", "s5734_good.ts", 1),
    ("typescript:S5736", "s5736_bad.ts", "s5736_good.ts", 1),
    ("typescript:S5739", "s5739_bad.ts", "s5739_good.ts", 1),
    ("typescript:S5742", "s5742_bad.ts", "s5742_good.ts", 1),
    ("typescript:S5743", "s5743_bad.ts", "s5743_good.ts", 1),
    ("typescript:S5757", "s5757_bad.ts", "s5757_good.ts", 1),
    ("typescript:S5759", "s5759_bad.ts", "s5759_good.ts", 1),
    ("typescript:S6245", "s6245_bad.ts", "s6245_good.ts", 1),
    ("typescript:S6268", "s6268_bad.ts", "s6268_good.ts", 1),
    ("typescript:S6299", "s6299_bad.ts", "s6299_good.ts", 1),
    ("typescript:S3317", "s3317_bad.ts", "s3317_good.ts", 1),
    ("typescript:S7060", "s7060_bad.ts", "s7060_good.ts", 1),
    ("typescript:S2424", "s2424_bad.ts", "s2424_good.ts", 1),
    ("typescript:S2757", "s2757_bad.ts", "s2757_good.ts", 1),
    ("typescript:S3003", "s3003_bad.ts", "s3003_good.ts", 1),
    ("typescript:S3981", "s3981_bad.ts", "s3981_good.ts", 1),
    ("typescript:S6644", "s6644_bad.ts", "s6644_good.ts", 1),
    ("typescript:S6637", "s6637_bad.ts", "s6637_good.ts", 1),
    ("typescript:S6676", "s6676_bad.ts", "s6676_good.ts", 1),
    ("typescript:S6666", "s6666_bad.ts", "s6666_good.ts", 1),
    ("typescript:S6959", "s6959_bad.ts", "s6959_good.ts", 1),
    ("typescript:S2871", "s2871_bad.ts", "s2871_good.ts", 1),
    ("typescript:S6653", "s6653_bad.ts", "s6653_good.ts", 1),
    ("typescript:S2427", "s2427_bad.ts", "s2427_good.ts", 1),
    ("typescript:S2817", "s2817_bad.ts", "s2817_good.ts", 1),
    ("typescript:S1528", "s1528_bad.ts", "s1528_good.ts", 1),
    ("typescript:S1533", "s1533_bad.ts", "s1533_good.ts", 1),
    ("typescript:S6509", "s6509_bad.ts", "s6509_good.ts", 1),
    ("typescript:S1774", "s1774_bad.ts", "s1774_good.ts", 2),
    ("typescript:S4624", "s4624_bad.ts", "s4624_good.ts", 1),
    ("typescript:S6657", "s6657_bad.ts", "s6657_good.ts", 1),
    ("typescript:S4140", "s4140_bad.ts", "s4140_good.ts", 1),
    ("typescript:S1313", "s1313_bad.ts", "s1313_good.ts", 1),
    ("typescript:S1516", "s1516_bad.ts", "s1516_good.ts", 1),
    ("typescript:S3786", "s3786_bad.ts", "s3786_good.ts", 1),
    ("typescript:S6535", "s6535_bad.ts", "s6535_good.ts", 1),
    ("typescript:S1314", "s1314_bad.ts", "s1314_good.ts", 1),
    ("typescript:S6534", "s6534_bad.ts", "s6534_good.ts", 1),
    ("typescript:S1125", "s1125_bad.ts", "s1125_good.ts", 1),
    ("typescript:S1440", "s1440_bad.ts", "s1440_good.ts", 2),
    ("typescript:S2688", "s2688_bad.ts", "s2688_good.ts", 1),
    ("typescript:S6679", "s6679_bad.ts", "s6679_good.ts", 1),
    ("typescript:S2692", "s2692_bad.ts", "s2692_good.ts", 1),
    ("typescript:S6557", "s6557_bad.ts", "s6557_good.ts", 1),
    ("typescript:S2685", "s2685_bad.ts", "s2685_good.ts", 1),
    ("typescript:S6654", "s6654_bad.ts", "s6654_good.ts", 1),
    ("typescript:S6661", "s6661_bad.ts", "s6661_good.ts", 1),
    ("typescript:S6958", "s6958_bad.ts", "s6958_good.ts", 1),
    ("typescript:S6643", "s6643_bad.ts", "s6643_good.ts", 1),
    ("typescript:S1539", "s1539_bad.ts", "s1539_good.ts", 1),
    ("typescript:S2990", "s2990_bad.ts", "s2990_good.ts", 1),
    ("typescript:S2092", "s2092_bad.ts", "s2092_good.ts", 1),
    ("typescript:S2245", "s2245_bad.ts", "s2245_good.ts", 1),
    ("typescript:S2255", "s2255_bad.ts", "s2255_good.ts", 1),
    ("typescript:S2598", "s2598_bad.ts", "s2598_good.ts", 1),
    ("typescript:S2612", "s2612_bad.ts", "s2612_good.ts", 1),
    ("typescript:S2755", "s2755_bad.ts", "s2755_good.ts", 1),
    ("typescript:S2819", "s2819_bad.ts", "s2819_good.ts", 1),
    ("typescript:S3330", "s3330_bad.ts", "s3330_good.ts", 1),
    ("typescript:S4036", "s4036_bad.ts", "s4036_good.ts", 1),
    ("typescript:S4423", "s4423_bad.ts", "s4423_good.ts", 1),
    ("typescript:S4426", "s4426_bad.ts", "s4426_good.ts", 1),
    ("typescript:S4502", "s4502_bad.ts", "s4502_good.ts", 1),
    ("typescript:S4507", "s4507_bad.ts", "s4507_good.ts", 1),
    ("typescript:S4721", "s4721_bad.ts", "s4721_good.ts", 1),
    ("typescript:S4787", "s4787_bad.ts", "s4787_good.ts", 1),
    ("typescript:S4790", "s4790_bad.ts", "s4790_good.ts", 1),
    ("typescript:S4817", "s4817_bad.ts", "s4817_good.ts", 1),
    ("typescript:S4818", "s4818_bad.ts", "s4818_good.ts", 1),
    ("typescript:S4823", "s4823_bad.ts", "s4823_good.ts", 1),
    ("typescript:S4829", "s4829_bad.ts", "s4829_good.ts", 2),
    ("typescript:S4830", "s4830_bad.ts", "s4830_good.ts", 1),
    ("typescript:S5042", "s5042_bad.ts", "s5042_good.ts", 1),
    ("typescript:S5122", "s5122_bad.ts", "s5122_good.ts", 1),
    ("typescript:S5148", "s5148_bad.ts", "s5148_good.ts", 1),
    ("typescript:S5247", "s5247_bad.ts", "s5247_good.ts", 1),
    ("typescript:S1110", "s1110_bad.ts", "s1110_good.ts", 1),
    ("typescript:S1529", "s1529_bad.ts", "s1529_good.ts", 1),
    ("typescript:S3735", "s3735_bad.ts", "s3735_good.ts", 1),
    ("typescript:S6638", "s6638_bad.ts", "s6638_good.ts", 1),
    ("typescript:S107", "s107_bad.ts", "s107_good.ts", 1),
    ("typescript:S134", "s134_bad.ts", "s134_good.ts", 1),
    ("typescript:S135", "s135_bad.ts", "s135_good.ts", 1),
    ("typescript:S888", "s888_bad.ts", "s888_good.ts", 1),
    ("typescript:S881", "s881_bad.ts", "s881_good.ts", 1),
    ("typescript:S905", "s905_bad.ts", "s905_good.ts", 1),
    ("typescript:S106", "s106_bad.ts", "s106_good.ts", 1),
    ("typescript:S878", "s878_bad.ts", "s878_good.ts", 1),
    ("typescript:S1192", "s1192_bad.ts", "s1192_good.ts", 1),
    ("typescript:S1441", "s1441_bad.ts", "s1441_good.ts", 1),
    ("typescript:S2430", "s2430_bad.ts", "s2430_good.ts", 1),
    ("typescript:S1656", "s1656_bad.ts", "s1656_good.ts", 1),
    ("typescript:S1488", "s1488_bad.ts", "s1488_good.ts", 1),
    ("typescript:S1763", "s1763_bad.ts", "s1763_good.ts", 1),
    ("typescript:S1301", "s1301_bad.ts", "s1301_good.ts", 1),
    ("typescript:S1479", "s1479_bad.ts", "s1479_good.ts", 1),
    ("typescript:S1821", "s1821_bad.ts", "s1821_good.ts", 1),
    ("typescript:S3616", "s3616_bad.ts", "s3616_good.ts", 1),
    ("typescript:S4524", "s4524_bad.ts", "s4524_good.ts", 1),
    ("typescript:S1066", "s1066_bad.ts", "s1066_good.ts", 1),
    ("typescript:S1116", "s1116_bad.ts", "s1116_good.ts", 1),
    ("typescript:S1119", "s1119_bad.ts", "s1119_good.ts", 1),
    ("typescript:S1154", "s1154_bad.ts", "s1154_good.ts", 1),
    ("typescript:S1199", "s1199_bad.ts", "s1199_good.ts", 1),
    ("typescript:S1525", "s1525_bad.ts", "s1525_good.ts", 1),
    ("typescript:S1848", "s1848_bad.ts", "s1848_good.ts", 1),
    ("typescript:S2201", "s2201_bad.ts", "s2201_good.ts", 1),
    ("typescript:S2208", "s2208_bad.ts", "s2208_good.ts", 1),
    ("typescript:S2681", "s2681_bad.ts", "s2681_good.ts", 1),
    ("typescript:S3504", "s3504_bad.ts", "s3504_good.ts", 1),
    ("typescript:S3696", "s3696_bad.ts", "s3696_good.ts", 1),
    ("typescript:S3863", "s3863_bad.ts", "s3863_good.ts", 1),
    ("typescript:S3984", "s3984_bad.ts", "s3984_good.ts", 1),
    ("typescript:S6660", "s6660_bad.ts", "s6660_good.ts", 1),
    ("typescript:S6836", "s6836_bad.ts", "s6836_good.ts", 1),
    ("typescript:S6859", "s6859_bad.ts", "s6859_good.ts", 1),
    ("typescript:S6435", "s6435_bad.ts", "s6435_good.ts", 1),
    ("typescript:S6438", "s6438_bad.tsx", "s6438_good.tsx", 1),
    ("typescript:S6439", "s6439_bad.tsx", "s6439_good.tsx", 1),
    ("typescript:S6440", "s6440_bad.ts", "s6440_good.ts", 1),
    ("typescript:S6442", "s6442_bad.ts", "s6442_good.ts", 1),
    ("typescript:S6443", "s6443_bad.ts", "s6443_good.ts", 1),
    ("typescript:S6477", "s6477_bad.tsx", "s6477_good.tsx", 1),
    ("typescript:S6478", "s6478_bad.tsx", "s6478_good.tsx", 1),
    ("typescript:S6479", "s6479_bad.tsx", "s6479_good.tsx", 1),
    ("typescript:S6480", "s6480_bad.tsx", "s6480_good.tsx", 1),
    ("typescript:S6481", "s6481_bad.tsx", "s6481_good.tsx", 1),
    ("typescript:S6746", "s6746_bad.ts", "s6746_good.ts", 1),
    ("typescript:S6747", "s6747_bad.tsx", "s6747_good.tsx", 2),
    ("typescript:S6748", "s6748_bad.tsx", "s6748_good.tsx", 1),
    ("typescript:S6749", "s6749_bad.tsx", "s6749_good.tsx", 1),
    ("typescript:S6750", "s6750_bad.tsx", "s6750_good.tsx", 1),
    ("typescript:S6754", "s6754_bad.ts", "s6754_good.ts", 1),
    ("typescript:S6756", "s6756_bad.ts", "s6756_good.ts", 1),
    ("typescript:S6757", "s6757_bad.tsx", "s6757_good.tsx", 1),
    ("typescript:S6761", "s6761_bad.tsx", "s6761_good.tsx", 1),
    ("typescript:S6763", "s6763_bad.ts", "s6763_good.ts", 1),
    ("typescript:S6766", "s6766_bad.tsx", "s6766_good.tsx", 1),
    ("typescript:S6770", "s6770_bad.tsx", "s6770_good.tsx", 1),
    ("typescript:S6772", "s6772_bad.tsx", "s6772_good.tsx", 1),
    ("typescript:S6775", "s6775_bad.ts", "s6775_good.ts", 1),
    ("typescript:S6788", "s6788_bad.ts", "s6788_good.ts", 1),
    ("typescript:S6789", "s6789_bad.ts", "s6789_good.ts", 1),
    ("typescript:S6790", "s6790_bad.tsx", "s6790_good.tsx", 1),
    ("typescript:S6791", "s6791_bad.ts", "s6791_good.ts", 1),
    ("typescript:S6957", "s6957_bad.ts", "s6957_good.ts", 1),
    ("typescript:S2639", "s2639_bad.ts", "s2639_good.ts", 1),
    ("typescript:S5842", "s5842_bad.ts", "s5842_good.ts", 1),
    ("typescript:S5843", "s5843_bad.ts", "s5843_good.ts", 1),
    ("typescript:S5850", "s5850_bad.ts", "s5850_good.ts", 1),
    ("typescript:S5852", "s5852_bad.ts", "s5852_good.ts", 1),
    ("typescript:S5867", "s5867_bad.ts", "s5867_good.ts", 1),
    ("typescript:S5868", "s5868_bad.ts", "s5868_good.ts", 1),
    ("typescript:S5869", "s5869_bad.ts", "s5869_good.ts", 1),
    ("typescript:S6019", "s6019_bad.ts", "s6019_good.ts", 1),
    ("typescript:S6035", "s6035_bad.ts", "s6035_good.ts", 1),
    ("typescript:S6323", "s6323_bad.ts", "s6323_good.ts", 1),
    ("typescript:S6324", "s6324_bad.ts", "s6324_good.ts", 1),
    ("typescript:S6325", "s6325_bad.ts", "s6325_good.ts", 1),
    ("typescript:S6326", "s6326_bad.ts", "s6326_good.ts", 1),
    ("typescript:S6328", "s6328_bad.ts", "s6328_good.ts", 1),
    ("typescript:S6331", "s6331_bad.ts", "s6331_good.ts", 1),
    ("typescript:S6351", "s6351_bad.ts", "s6351_good.ts", 1),
    ("typescript:S6353", "s6353_bad.ts", "s6353_good.ts", 1),
    ("typescript:S6397", "s6397_bad.ts", "s6397_good.ts", 1),
    ("typescript:S3402", "s3402_bad.ts", "s3402_good.ts", 1),
    ("typescript:S3579", "s3579_bad.ts", "s3579_good.ts", 1),
    ("typescript:S3699", "s3699_bad.ts", "s3699_good.ts", 1),
    ("typescript:S4123", "s4123_bad.ts", "s4123_good.ts", 1),
    ("typescript:S1117", "s1117_bad.ts", "s1117_good.ts", 1),
    ("typescript:S1172", "s1172_bad.ts", "s1172_good.ts", 1),
    ("typescript:S1226", "s1226_bad.ts", "s1226_good.ts", 1),
    ("typescript:S1537", "s1537_bad.ts", "s1537_good.ts", 2),
    ("typescript:S1854", "s1854_bad.ts", "s1854_good.ts", 1),
    ("typescript:S2077", "s2077_bad.ts", "s2077_good.ts", 2),
    ("typescript:S2123", "s2123_bad.ts", "s2123_good.ts", 1),
    ("typescript:S2392", "s2392_bad.ts", "s2392_good.ts", 1),
    ("typescript:S2589", "s2589_bad.ts", "s2589_good.ts", 1),
    ("typescript:S2870", "s2870_bad.ts", "s2870_good.ts", 1),
    ("typescript:S2999", "s2999_bad.ts", "s2999_good.ts", 1),
    ("typescript:S3353", "s3353_bad.ts", "s3353_good.ts", 1),
    ("typescript:S3723", "s3723_bad.ts", "s3723_good.ts", 2),
    ("typescript:S4030", "s4030_bad.ts", "s4030_good.ts", 1),
    ("typescript:S4043", "s4043_bad.ts", "s4043_good.ts", 1),
    ("typescript:S4143", "s4143_bad.ts", "s4143_good.ts", 1),
    ("typescript:S4165", "s4165_bad.ts", "s4165_good.ts", 1),
    ("typescript:S4784", "s4784_bad.ts", "s4784_good.ts", 3),
    ("typescript:S5443", "s5443_bad.ts", "s5443_good.ts", 2),
    ("typescript:S5725", "s5725_bad.ts", "s5725_good.ts", 2),
    ("typescript:S5860", "s5860_bad.ts", "s5860_good.ts", 2),
    ("typescript:S5876", "s5876_bad.ts", "s5876_good.ts", 1),
    ("typescript:S6441", "s6441_bad.ts", "s6441_good.ts", 1),
    ("typescript:S6486", "s6486_bad.tsx", "s6486_good.tsx", 1),
    ("typescript:S6544", "s6544_bad.ts", "s6544_good.ts", 1),
    ("typescript:S6767", "s6767_bad.ts", "s6767_good.ts", 1),
    ("typescript:S6252", "s6252_bad.ts", "s6252_good.ts", 1),
    ("typescript:S6265", "s6265_bad.ts", "s6265_good.ts", 1),
    ("typescript:S6270", "s6270_bad.ts", "s6270_good.ts", 1),
    ("typescript:S6275", "s6275_bad.ts", "s6275_good.ts", 1),
    ("typescript:S6281", "s6281_bad.ts", "s6281_good.ts", 1),
    ("typescript:S6302", "s6302_bad.ts", "s6302_good.ts", 1),
    ("typescript:S6303", "s6303_bad.ts", "s6303_good.ts", 1),
    ("typescript:S6304", "s6304_bad.ts", "s6304_good.ts", 1),
    ("typescript:S6308", "s6308_bad.ts", "s6308_good.ts", 1),
    ("typescript:S6317", "s6317_bad.ts", "s6317_good.ts", 1),
    ("typescript:S6319", "s6319_bad.ts", "s6319_good.ts", 1),
    ("typescript:S6321", "s6321_bad.ts", "s6321_good.ts", 2),
    ("typescript:S6327", "s6327_bad.ts", "s6327_good.ts", 1),
    ("typescript:S6329", "s6329_bad.ts", "s6329_good.ts", 2),
    ("typescript:S6330", "s6330_bad.ts", "s6330_good.ts", 2),
    ("typescript:S6332", "s6332_bad.ts", "s6332_good.ts", 2),
    ("typescript:S6333", "s6333_bad.ts", "s6333_good.ts", 2),
    ("typescript:S2260", "s2260_bad.ts", "s2260_good.ts", 1),
    ("typescript:S3812", "s3812_bad.ts", "s3812_good.ts", 1),
    ("typescript:S909", "s909_bad.ts", "s909_good.ts", 1),
];

#[test]
fn tracked_typescript_oracle_pairs_trigger_only_the_bad_control() {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.oracle/sonar/projects/oracle-ts/src");
    for &(key, bad_name, good_name, expected_bad_count) in TRACKED_TYPESCRIPT_ORACLE_CASES {
        let bad_path = project.join(bad_name);
        let bad_source = std::fs::read_to_string(&bad_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", bad_path.display()));
        let bad = analyze(
            bad_path,
            &bad_source,
            JstsLanguage::TypeScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            bad.issues
                .iter()
                .filter(|issue| issue.rule_key == key)
                .count(),
            expected_bad_count,
            "bad oracle control for {key}",
        );

        let good_path = project.join(good_name);
        let good_source = std::fs::read_to_string(&good_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", good_path.display()));
        let good = analyze(
            good_path,
            &good_source,
            JstsLanguage::TypeScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            good.issues
                .iter()
                .filter(|issue| issue.rule_key == key)
                .count(),
            0,
            "good oracle control for {key}",
        );
    }
}

#[test]
fn configurable_typescript_rules_use_full_catalog_keys() {
    let rules = RuleOptions {
        maximum_lines_of_code: 1,
        header_format: "// Copyright\n".to_string(),
        ..RuleOptions::default()
    };
    let bad = crate::analyze_with_rules(
        PathBuf::from("config.ts"),
        "let first = 1;\nlet second = 2;\n",
        JstsLanguage::TypeScript,
        &AnalyzerOptions::default(),
        &rules,
    );
    let bad_keys = report_keys(&bad);
    assert_eq!(count_key(&bad_keys, "typescript:S104"), 1);
    assert_eq!(count_key(&bad_keys, "typescript:S1451"), 1);

    let good = crate::analyze_with_rules(
        PathBuf::from("config.ts"),
        "// Copyright\nlet first = 1;\n",
        JstsLanguage::TypeScript,
        &AnalyzerOptions::default(),
        &rules,
    );
    let good_keys = report_keys(&good);
    assert_eq!(count_key(&good_keys, "typescript:S104"), 0);
    assert_eq!(count_key(&good_keys, "typescript:S1451"), 0);
}

#[test]
fn deeply_nested_valid_program_does_not_overflow_the_process_stack() {
    const DEPTH: usize = 5_000;
    let mut source = String::with_capacity(DEPTH * 2 + 24);
    source.push_str(&"{".repeat(DEPTH));
    source.push_str("const value = 1;\n");
    source.push_str(&"}".repeat(DEPTH));

    let report = analyze(
        PathBuf::from("deep.js"),
        &source,
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
    );

    assert!(
        report
            .issues
            .iter()
            .all(|issue| issue.rule_key != "javascript:S2260"),
        "valid deeply nested source must still parse"
    );
}
