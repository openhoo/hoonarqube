use super::{AnalyzerOptions, JstsLanguage, RuleOptions, analyze, language_for_extension};
use std::fmt::Write as _;
use std::path::PathBuf;

fn pos(line: u32, column: u32) -> hoonarqube_ir::Pos {
    hoonarqube_ir::Pos { line, column }
}

fn issue(
    rule_key: &str,
    message: &str,
    start: (u32, u32),
    end: (u32, u32),
) -> hoonarqube_ir::Issue {
    hoonarqube_ir::Issue {
        rule_key: rule_key.to_string(),
        message: message.to_string(),
        range: hoonarqube_ir::Range {
            start: pos(start.0, start.1),
            end: pos(end.0, end.1),
        },
    }
}

fn js(source: &str) -> hoonarqube_ir::FileReport {
    analyze(
        PathBuf::from("test.js"),
        source,
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
    )
}

fn ts(source: &str) -> hoonarqube_ir::FileReport {
    analyze(
        PathBuf::from("test.ts"),
        source,
        JstsLanguage::TypeScript,
        &AnalyzerOptions::default(),
    )
}

#[test]
fn extensions_map_to_languages() {
    assert_eq!(language_for_extension("js"), Some(JstsLanguage::JavaScript));
    assert_eq!(
        language_for_extension("jsx"),
        Some(JstsLanguage::JavaScript)
    );
    assert_eq!(
        language_for_extension("mjs"),
        Some(JstsLanguage::JavaScript)
    );
    assert_eq!(
        language_for_extension("cjs"),
        Some(JstsLanguage::JavaScript)
    );
    assert_eq!(language_for_extension("ts"), Some(JstsLanguage::TypeScript));
    assert_eq!(
        language_for_extension("tsx"),
        Some(JstsLanguage::TypeScript)
    );
    assert_eq!(
        language_for_extension("mts"),
        Some(JstsLanguage::TypeScript)
    );
    assert_eq!(
        language_for_extension("cts"),
        Some(JstsLanguage::TypeScript)
    );
    assert_eq!(language_for_extension("py"), None);
}

#[test]
fn line_length_honors_option_with_exact_boundary_clean() {
    // Exactly at the limit: clean. One more character: flagged.
    let options = AnalyzerOptions {
        maximum_line_length: 13,
    };
    let at_limit = analyze(
        PathBuf::from("test.js"),
        "const ab = 1;\n",
        JstsLanguage::JavaScript,
        &options,
    );
    assert!(at_limit.issues.is_empty());

    let over_limit = analyze(
        PathBuf::from("test.js"),
        "const abc = 1;\n",
        JstsLanguage::JavaScript,
        &options,
    );
    assert_eq!(
        over_limit.issues,
        vec![issue(
            "javascript:S103",
            "This line exceeds the maximum allowed length of 13 characters.",
            (1, 0),
            (1, 14),
        )]
    );
}

#[test]
fn one_statement_per_line_flags_only_second_onwards_including_nesting() {
    let source = "\
let a = 1; let b = 2;
function f() {
  let c = 3; let d = 4;
}
if (a) { g(); h(); }
while (false) { i(); j(); }
try { k(); l(); } catch { m(); n(); }
";
    let report = js(source);
    let s122: Vec<_> = report
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(":S122"))
        .collect();
    // One issue per additional statement sharing a line: top level, the
    // function body, the `if` block, the `while` block, and two in the
    // try/catch line (`l()` and `n()`).
    assert_eq!(s122.len(), 6);
    assert!(
        s122.iter()
            .all(|issue| issue.message == "Only one statement per line is allowed.")
    );
    assert_eq!(
        s122[0].range,
        hoonarqube_ir::Range {
            start: pos(1, 11),
            end: pos(1, 21),
        }
    );
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
fn switch_and_loop_single_statement_bodies_are_walked() {
    let source = "\
for (let i = 0; i < 1; i++) o(); p();
switch (x) { case 1: q(); r(); }
label: s(); t();
with (obj) { u(); v(); }
";
    let report = js(source);
    assert_eq!(
        report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S122"))
            .count(),
        4
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
fn rule_keys_follow_file_language_prefix() {
    let javascript = js("eval(\"x\");");
    assert_eq!(javascript.issues[0].rule_key, "javascript:S1523");

    let typescript = ts("eval(\"x\");");
    assert_eq!(typescript.issues[0].rule_key, "typescript:S1523");
    assert_eq!(typescript.language, "typescript");
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

#[test]
fn multiline_block_comment_between_statements_is_fully_counted() {
    let source = "let a = 1;\n/* one\ntwo\nthree */\nlet b = 2;\n";
    let report = js(source);
    assert_eq!(report.metrics.comment_lines, 3);
    assert_eq!(report.metrics.code_lines, 2);
}

// ---- Batch-1 rule fixtures ----

fn findings(source: &str, language: JstsLanguage) -> Vec<(String, u32)> {
    analyze(
        PathBuf::from("test.js"),
        source,
        language,
        &AnalyzerOptions::default(),
    )
    .issues
    .into_iter()
    .map(|issue| (issue.rule_key, issue.range.start.line))
    .collect()
}

fn count_key(findings: &[(String, u32)], key: &str) -> usize {
    findings
        .iter()
        .filter(|(key_found, _)| key_found == key)
        .count()
}

fn js_keys(source: &str) -> Vec<(String, u32)> {
    findings(source, JstsLanguage::JavaScript)
}

fn ts_keys(source: &str) -> Vec<(String, u32)> {
    findings_ts(source)
}

fn findings_ts(source: &str) -> Vec<(String, u32)> {
    analyze(
        PathBuf::from("test.ts"),
        source,
        JstsLanguage::TypeScript,
        &AnalyzerOptions::default(),
    )
    .issues
    .into_iter()
    .map(|issue| (issue.rule_key, issue.range.start.line))
    .collect()
}

fn js_with_rules(source: &str, rules: &RuleOptions) -> hoonarqube_ir::FileReport {
    super::analyze_with_rules(
        PathBuf::from("test.js"),
        source,
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
        rules,
    )
}

fn keys_with_rules(source: &str, rules: &RuleOptions) -> Vec<(String, u32)> {
    report_keys(&js_with_rules(source, rules))
}

// ===== Batch2a naming/format rule tests =====

#[test]
fn function_class_and_interface_names_follow_catalog_formats() {
    let report = js(
        "function goodName() {}\nfunction BadName() {}\nfunction _underscoreOk() {}\nclass GoodClass {}\nclass badClass {}\n",
    );
    assert_eq!(count_key(&report_keys(&report), "javascript:S100"), 1);
    assert_eq!(count_key(&report_keys(&report), "javascript:S101"), 1);
    let bad_function: Vec<_> = report
        .issues
        .iter()
        .filter(|found| found.rule_key == "javascript:S100")
        .collect();
    assert_eq!(
        bad_function,
        vec![&issue(
            "javascript:S100",
            "Rename this function to match the regular expression '^[_a-z][a-zA-Z0-9]*$'.",
            (2, 9),
            (2, 16),
        )]
    );

    let ts_report = ts("interface goodInterface {}\ninterface GoodInterface {}\n");
    assert_eq!(count_key(&report_keys(&ts_report), "typescript:S101"), 1);
    assert_eq!(count_key(&report_keys(&ts_report), "typescript:S100"), 0);
}

#[test]
fn method_names_are_checked_but_constructors_are_exempt() {
    let rules = RuleOptions {
        format_functions: "^doRe$".to_string(),
        ..RuleOptions::default()
    };
    let flagged = keys_with_rules("class C { constructor() {} doIt() {} doRe() {} }\n", &rules);
    assert_eq!(count_key(&flagged, "javascript:S100"), 1);
}

#[test]
fn variables_parameters_and_properties_honor_format() {
    let defaults_clean = js_keys(
        "function f(goodParam) { let goodVar = 1; const UPPER_SNAKE = 2; const opts = { anyKey: 3 }; }\n",
    );
    assert_eq!(count_key(&defaults_clean, "javascript:S117"), 0);

    let rules = RuleOptions {
        format_variables: "^[a-z][a-zA-Z0-9]*$".to_string(),
        ..RuleOptions::default()
    };
    let strict = keys_with_rules(
        "function f(BadParam) { let BadVar = 1; let okVar = 2; }\n",
        &rules,
    );
    assert_eq!(count_key(&strict, "javascript:S117"), 2);
}

#[test]
fn magic_numbers_flagged_only_outside_allowed_contexts() {
    let report = js(
        "const LIMIT = 42;\nlet retries = 3;\nitems[0] = LIMIT;\nfunction g(x = 1, y = 5) { return x; }\nfunction h(z = -1) { return z; }\nlet offset = -7;\ng(2);\n",
    );
    let magic: Vec<_> = report
        .issues
        .iter()
        .filter(|found| found.rule_key == "javascript:S109")
        .collect();
    let message = "This numeric literal should be replaced by a named constant.";
    assert_eq!(
        magic,
        vec![
            &issue("javascript:S109", message, (2, 14), (2, 15)),
            &issue("javascript:S109", message, (4, 22), (4, 23)),
            &issue("javascript:S109", message, (6, 14), (6, 15)),
            &issue("javascript:S109", message, (7, 2), (7, 3)),
        ]
    );

    // Boundary: `-1..=2` parameter defaults are allowed, larger ones are not.
    let boundary = js("function k(a = 2, b = 3) {}\n");
    assert_eq!(count_key(&report_keys(&boundary), "javascript:S109"), 1);
}

#[test]
fn duplicate_string_literals_report_once_at_first_occurrence() {
    let report = js(
        "log('application/json');\nlog('application/json');\nlog('application/json');\nwarn('dup');\nwarn('dup');\nwarn('dup');\ntag('x');\ntag('x');\n",
    );
    let duplicates: Vec<_> = report
        .issues
        .iter()
        .filter(|found| found.rule_key == "javascript:S1192")
        .collect();
    // The configured `ignoreStrings` entry never fires; single-character
    // literals are excluded; the third occurrence reaches the threshold.
    assert_eq!(
        duplicates,
        vec![&issue(
            "javascript:S1192",
            "Define a constant instead of duplicating this literal \"dup\" 3 times.",
            (4, 5),
            (4, 10),
        )]
    );

    let eager = RuleOptions {
        duplicate_string_threshold: 2,
        ..RuleOptions::default()
    };
    let flagged = keys_with_rules("a('aa');\nb('aa');\nc('bb');\n", &eager);
    assert_eq!(count_key(&flagged, "javascript:S1192"), 1);
}

#[test]
fn string_quote_style_follows_single_quotes_param() {
    let report = js(
        "const a = \"double\";\nconst b = 'single';\nconst c = \"escaped \\\"quote\\\"\";\nconst d = `template`;\n",
    );
    let quotes: Vec<_> = report
        .issues
        .iter()
        .filter(|found| found.rule_key == "javascript:S1441")
        .collect();
    assert_eq!(
        quotes,
        vec![&issue(
            "javascript:S1441",
            "Use single quotes for this string literal.",
            (1, 10),
            (1, 18),
        )]
    );

    let double = RuleOptions {
        single_quotes: false,
        ..RuleOptions::default()
    };
    let relaxed = keys_with_rules("const a = 'quoted';\nconst b = \"doubled\";\n", &double);
    assert_eq!(count_key(&relaxed, "javascript:S1441"), 1);
}

#[test]
fn lowercase_constructor_callees_flagged() {
    let report = js("new foo();\nnew Foo();\nnew lib.Bar();\n");
    let constructors: Vec<_> = report
        .issues
        .iter()
        .filter(|found| found.rule_key == "javascript:S2430")
        .collect();
    assert_eq!(
        constructors,
        vec![&issue(
            "javascript:S2430",
            "Rename this constructor to start with an uppercase letter.",
            (1, 4),
            (1, 7),
        )]
    );
}

// ===== Batch2a structural duplicate/identity rule tests =====

#[test]
fn identical_binary_operands_flagged() {
    let report = js("if (a === a) {}\nif (b + c === b + c) {}\nif (x == y) {}\nlet t = p && p;\n");
    assert_eq!(count_key(&report_keys(&report), "javascript:S1764"), 2);
    let first: Vec<_> = report
        .issues
        .iter()
        .filter(|found| found.rule_key == "javascript:S1764")
        .collect();
    assert_eq!(
        first[0].range,
        hoonarqube_ir::Range {
            start: pos(1, 4),
            end: pos(1, 11),
        }
    );
}

#[test]
fn identical_if_branches_and_switch_cases_flagged() {
    let report = js(
        "function f(cond) {\n  if (cond) { work(); cleanup(); } else { work(); cleanup(); }\n}\n",
    );
    // The identical if/else pair is reported by both rule keys.
    assert_eq!(count_key(&report_keys(&report), "javascript:S1871"), 1);
    assert_eq!(count_key(&report_keys(&report), "javascript:S3923"), 1);

    let switch = js(
        "function g(v) {\nswitch (v) { case 1: a(); break; case 2: a(); break; case 3: b(); break; }\n}\n",
    );
    assert_eq!(count_key(&report_keys(&switch), "javascript:S1871"), 1);

    // Fallthrough placeholders are not duplicated bodies.
    let fallthrough = js("switch (v) { case 1: case 2: a(); break; }\n");
    assert_eq!(count_key(&report_keys(&fallthrough), "javascript:S1871"), 0);
}

#[test]
fn all_identical_branch_structures_flagged_once() {
    let ternary = js("const r = flag ? 1 : 1;\n");
    assert_eq!(count_key(&report_keys(&ternary), "javascript:S3923"), 1);

    let chain = js("function f(a, b) {\n  if (a) { x(); } else if (b) { x(); } else { x(); }\n}\n");
    assert_eq!(count_key(&report_keys(&chain), "javascript:S3923"), 1);
    // Only the last link's branches are identical.
    assert_eq!(count_key(&report_keys(&chain), "javascript:S1871"), 1);
}

#[test]
fn duplicated_conditions_in_chains_and_switches_flagged() {
    let chain = js("function f(a) {\n  if (a === 1) { x(); } else if (a === 1) { y(); }\n}\n");
    assert_eq!(count_key(&report_keys(&chain), "javascript:S1862"), 1);

    let distinct =
        js("function f(a, b) {\n  if (a === 1) { x(); } else if (b === 1) { y(); }\n}\n");
    assert_eq!(count_key(&report_keys(&distinct), "javascript:S1862"), 0);

    let switch = js("switch (v) { case 1: r(); break; case 1: s(); break; }\n");
    assert_eq!(count_key(&report_keys(&switch), "javascript:S1862"), 1);
}

#[test]
fn identical_function_bodies_flagged_but_trivial_ones_skipped() {
    let source = "\
function alpha() {
  setup();
  run();
}
function beta() {
  setup();
  run();
}
function gamma() {
  other();
}
";
    let report = js(source);
    assert_eq!(count_key(&report_keys(&report), "javascript:S4144"), 1);

    let trivial = js("function d1() { x(); }\nfunction d2() { x(); }\n");
    assert_eq!(count_key(&report_keys(&trivial), "javascript:S4144"), 0);
}

#[test]
fn invariant_literal_returns_flagged_once_per_function() {
    let same = js("function f(n) {\n  if (n) { return 'same'; }\n  return 'same';\n}\n");
    assert_eq!(count_key(&report_keys(&same), "javascript:S3516"), 1);

    let differing = js("function f(n) {\n  if (n) { return 'a'; }\n  return 'b';\n}\n");
    assert_eq!(count_key(&report_keys(&differing), "javascript:S3516"), 0);

    // A bare `return` means the returns are not all literal values.
    let bare_mixed = js("function f(n) {\n  if (n) { return; }\n  return 'x';\n}\n");
    assert_eq!(count_key(&report_keys(&bare_mixed), "javascript:S3516"), 0);

    // Non-literal returns never count as invariant duplicates.
    let identifiers = js("function f(n, m) {\n  if (n) { return m; }\n  return m;\n}\n");
    assert_eq!(count_key(&report_keys(&identifiers), "javascript:S3516"), 0);
}

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
    let report = super::analyze_with_rules(
        PathBuf::from("test.js"),
        "a();\nb();\nc();\nd();\n",
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
        &strict,
    );
    assert_eq!(count_key(&report_keys(&report), "javascript:S104"), 1);

    let long_function = "function f() {\n  a();\n  b();\n  c();\n}\n";
    let flagged = super::analyze_with_rules(
        PathBuf::from("test.js"),
        long_function,
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
        &strict,
    );
    assert_eq!(count_key(&report_keys(&flagged), "javascript:S138"), 1);

    let relaxed = RuleOptions {
        maximum_lines_of_code: 1000,
        maximum_function_lines: 200,
        ..RuleOptions::default()
    };
    let clean = super::analyze_with_rules(
        PathBuf::from("test.js"),
        long_function,
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
        &relaxed,
    );
    assert_eq!(count_key(&report_keys(&clean), "javascript:S138"), 0);
}

fn report_keys(report: &hoonarqube_ir::FileReport) -> Vec<(String, u32)> {
    report
        .issues
        .iter()
        .map(|issue| (issue.rule_key.clone(), issue.range.start.line))
        .collect()
}

#[test]
fn file_header_requires_configured_prefix() {
    let mut rules = RuleOptions {
        header_format: "// Copyright\n".to_string(),
        ..RuleOptions::default()
    };
    let missing = super::analyze_with_rules(
        PathBuf::from("test.js"),
        "let x = 1;\n",
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
        &rules,
    );
    assert_eq!(count_key(&report_keys(&missing), "javascript:S1451"), 1);

    let present = super::analyze_with_rules(
        PathBuf::from("test.js"),
        "// Copyright\nlet x = 1;\n",
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
        &rules,
    );
    assert_eq!(count_key(&report_keys(&present), "javascript:S1451"), 0);

    rules.header_is_regular_expression = true;
    rules.header_format = r"^// \(c\) \d{4}".to_string();
    let regex_present = super::analyze_with_rules(
        PathBuf::from("test.js"),
        "// (c) 2026 ACME\nlet x = 1;\n",
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
        &rules,
    );
    assert_eq!(
        count_key(&report_keys(&regex_present), "javascript:S1451"),
        0
    );

    let regex_missing = super::analyze_with_rules(
        PathBuf::from("test.js"),
        "// Other header\nlet x = 1;\n",
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
        &rules,
    );
    assert_eq!(
        count_key(&report_keys(&regex_missing), "javascript:S1451"),
        1
    );
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
fn disallowed_comment_pattern_only_fires_on_code_lines() {
    let inline = js_keys("let x = 1; // hack\n");
    assert_eq!(count_key(&inline, "javascript:S139"), 1);

    let own_line = js_keys("// hack\nlet x = 1;\n");
    assert_eq!(count_key(&own_line, "javascript:S139"), 0);
}

#[test]
fn commented_out_code_heuristic_flags_keyword_comments() {
    let flagged = js_keys("// return value;\n");
    assert_eq!(count_key(&flagged, "javascript:S125"), 1);

    let prose = js_keys("// this comment only explains things\n");
    assert_eq!(count_key(&prose, "javascript:S125"), 0);
}

#[test]
fn statement_level_batch_rules_fire() {
    let source = "\
debugger;
with (o) { }
var v = 1;
import * as ns from 'm';
import x from '/abs';
throw 'oops';
new Error('x');
;;
";
    let flagged = js_keys(source);
    for key in [
        "S1525", "S1321", "S3504", "S2208", "S6859", "S3696", "S3984", "S1848", "S1116",
    ] {
        assert!(
            count_key(&flagged, &format!("javascript:{key}")) >= 1,
            "expected {key}"
        );
    }
}

#[test]
fn control_structure_batch_rules_fire() {
    let source = "\
if (a) b();
else { if (c) d(); }
if (e) { if (f) g(); }
switch (s) { case 1: let z = 2; }
while (x) continue;
";
    let flagged = js_keys(source);
    for key in ["S121", "S6660", "S1066", "S6836", "S909"] {
        assert!(
            count_key(&flagged, &format!("javascript:{key}")) >= 1,
            "expected {key}"
        );
    }
}

#[test]
fn expression_level_batch_rules_fire() {
    let source = "\
if (a == b) { void c; (d, e); }
if (x === NaN) { if (list.length < 0) { } }
const n = parseInt(s);
console.log(n);
alert(n);
values.sort();
other.reduce(cb);
if (list.indexOf(x) > 0) { }
if ('a' < 'b') { }
q = cond ? nested(1) : outer(cond ? nested(2) : 3);
r = flag ? true : false;
f = (() => 1).bind(this);
g.call(ctx);
h.apply(ctx, [args]);
Object.assign({}, opts);
const arr = new Array(1, 2);
const num = new Number(5);
legacy = require('mod');
db = openDatabase(name);
outer = `${inner `${deep}`}`;
text = \"interp ${x}\";
host = '10.0.0.1';
";
    let flagged = js_keys(source);
    for key in [
        "S1440", "S3735", "S878", "S6679", "S3981", "S2427", "S106", "S1442", "S2871", "S6959",
        "S2692", "S3003", "S1774", "S6644", "S6637", "S6676", "S6666", "S6661", "S1528", "S1533",
        "S3533", "S2817", "S4624", "S3786", "S1313",
    ] {
        assert!(
            count_key(&flagged, &format!("javascript:{key}")) >= 1,
            "expected {key}"
        );
    }
}

#[test]
fn binding_and_pattern_batch_rules_fire() {
    let source = "\
const shadow = undefined;
const int = 1;
const { renamed: renamed } = pair;
const {} = empty;
const password = 'hunter2';
const apiKeyValue = 'Zx9kQ2vL8pR4tW7yB1nM6cJ3fH5dG0aE#';
NaN = 1;
";
    let flagged = js_keys(source);
    for key in [
        "S2138", "S6645", "S1527", "S6650", "S3799", "S2068", "S6418", "S2137",
    ] {
        assert!(
            count_key(&flagged, &format!("javascript:{key}")) >= 1,
            "expected {key}"
        );
    }
}

#[test]
fn class_interface_and_empty_body_rules_respect_scope() {
    let ts_source = "\
class Empty {}
interface Nothing {}
interface WithCtor { new (): void; }
function bare() {}
const cb = () => {};
arr.map(function () {});
";
    let ts_findings = findings(ts_source, JstsLanguage::TypeScript);
    assert_eq!(count_key(&ts_findings, "typescript:S2094"), 1);
    assert_eq!(count_key(&ts_findings, "typescript:S4023"), 1);
    assert_eq!(count_key(&ts_findings, "typescript:S4124"), 1);
    // Callback conventions suppress `S1186`.
    assert_eq!(count_key(&ts_findings, "typescript:S1186"), 2);

    let js_findings = findings(ts_source, JstsLanguage::JavaScript);
    assert_eq!(count_key(&js_findings, "javascript:S4023"), 0);
    assert_eq!(count_key(&js_findings, "javascript:S4124"), 0);
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
fn s126_flags_else_if_chain_without_final_else() {
    let chained =
        js_keys("if (a) {\n  f();\n} else if (b) {\n  g();\n} else if (c) {\n  h();\n}\n");
    assert_eq!(count_key(&chained, "javascript:S126"), 1);
    let tail_line = chained
        .iter()
        .find(|(key, _)| key == "javascript:S126")
        .map(|(_, line)| *line);
    assert_eq!(tail_line, Some(5));

    let with_final_else =
        js_keys("if (a) {\n  f();\n} else if (b) {\n  g();\n} else {\n  h();\n}\n");
    assert_eq!(count_key(&with_final_else, "javascript:S126"), 0);

    // A lone `if` is not a chain.
    let plain_if = js_keys("if (a) {\n  f();\n}\n");
    assert_eq!(count_key(&plain_if, "javascript:S126"), 0);
}

#[test]
fn s128_requires_unconditional_case_termination() {
    let falling_through = js_keys("switch (x) {\n  case 1:\n    f();\n}\n");
    assert_eq!(count_key(&falling_through, "javascript:S128"), 1);

    let with_break = js_keys("switch (x) {\n  case 1:\n    f();\n    break;\n}\n");
    assert_eq!(count_key(&with_break, "javascript:S128"), 0);

    // Empty consequents (case grouping) and block-wrapped jumps stay
    // clean.
    let grouped = js_keys("switch (x) {\n  case 1:\n  case 2:\n    f();\n    break;\n}\n");
    assert_eq!(count_key(&grouped, "javascript:S128"), 0);

    let via_block_return =
        js_keys("function f(x) {\n  switch (x) {\n    case 1:\n      { g(); return; }\n  }\n}\n");
    assert_eq!(count_key(&via_block_return, "javascript:S128"), 0);
}

#[test]
fn s131_flags_switch_without_default_case() {
    let source = "switch (x) {\n  case 1:\n    break;\n}\n";
    let missing = js_keys(source);
    assert_eq!(count_key(&missing, "javascript:S131"), 1);

    let with_default = js_keys("switch (x) {\n  case 1:\n    break;\n  default:\n    break;\n}\n");
    assert_eq!(count_key(&with_default, "javascript:S131"), 0);

    let typescript = findings(source, JstsLanguage::TypeScript);
    assert_eq!(count_key(&typescript, "typescript:S131"), 1);
    assert_eq!(count_key(&typescript, "javascript:S131"), 0);
}

#[test]
fn s4524_flags_default_case_not_in_last_position() {
    let misplaced = js_keys("switch (x) {\n  default:\n    break;\n  case 1:\n    break;\n}\n");
    assert_eq!(count_key(&misplaced, "javascript:S4524"), 1);

    let last = js_keys("switch (x) {\n  case 1:\n    break;\n  default:\n    break;\n}\n");
    assert_eq!(count_key(&last, "javascript:S4524"), 0);
}

#[test]
fn s3616_flags_sequence_and_logical_or_case_tests() {
    let sequence = js_keys("switch (x) {\n  case (a(), b):\n    break;\n}\n");
    assert_eq!(count_key(&sequence, "javascript:S3616"), 1);

    let logical_or = js_keys("switch (x) {\n  case a || b:\n    break;\n}\n");
    assert_eq!(count_key(&logical_or, "javascript:S3616"), 1);

    // Logical AND tests are ordinary expressions.
    let logical_and = js_keys("switch (x) {\n  case a && b:\n    break;\n}\n");
    assert_eq!(count_key(&logical_and, "javascript:S3616"), 0);
}

#[test]
fn s1479_flags_switches_with_more_than_thirty_cases() {
    let build = |case_count: usize| {
        let mut source = String::from("switch (x) {\n");
        for case_number in 0..case_count {
            let _ = write!(source, "  case {case_number}:\n    break;\n");
        }
        source.push_str("}\n");
        source
    };

    let at_limit = js_keys(&build(super::MAX_SWITCH_CASES));
    assert_eq!(count_key(&at_limit, "javascript:S1479"), 0);

    let over_limit = js_keys(&build(super::MAX_SWITCH_CASES + 1));
    assert_eq!(count_key(&over_limit, "javascript:S1479"), 1);
}

#[test]
fn s1301_flags_switches_convertible_to_if() {
    let two_cases = js_keys(
        "switch (x) {\n  case 1:\n    f();\n    break;\n  case 2:\n    g();\n    break;\n  default:\n    break;\n}\n",
    );
    assert_eq!(count_key(&two_cases, "javascript:S1301"), 1);

    let one_case =
        js_keys("switch (x) {\n  case 1:\n    f();\n    break;\n  default:\n    break;\n}\n");
    assert_eq!(count_key(&one_case, "javascript:S1301"), 1);

    let mut three_cases_source = String::from("switch (x) {\n  default:\n    break;\n");
    for case_number in 0..3 {
        let _ = write!(three_cases_source, "  case {case_number}:\n    break;\n");
    }
    three_cases_source.push_str("}\n");
    let three_cases = js_keys(&three_cases_source);
    assert_eq!(count_key(&three_cases, "javascript:S1301"), 0);
}

#[test]
fn s1821_flags_switch_nested_inside_case_consequent() {
    let nested = js_keys(
        "switch (x) {\n  case 1:\n    switch (y) {\n      case 2:\n        break;\n    }\n    break;\n}\n",
    );
    assert_eq!(count_key(&nested, "javascript:S1821"), 1);
    let inner_line = nested
        .iter()
        .find(|(key, _)| key == "javascript:S1821")
        .map(|(_, line)| *line);
    assert_eq!(inner_line, Some(3));

    // Sibling switches at the top level stay clean.
    let sibling = js_keys(
        "switch (x) {\n  case 1:\n    break;\n}\nswitch (y) {\n  default:\n    break;\n}\n",
    );
    assert_eq!(count_key(&sibling, "javascript:S1821"), 0);
}

#[test]
fn s888_flags_loose_equality_in_for_test() {
    let loose = js_keys("for (let i = 0; i == n; i++) {}\n");
    assert_eq!(count_key(&loose, "javascript:S888"), 1);

    let strict = js_keys("for (let i = 0; i === n; i++) {}\n");
    assert_eq!(count_key(&strict, "javascript:S888"), 0);
}

#[test]
fn s1264_flags_init_and_update_less_for_loops() {
    let bare = js_keys("for (;;) {\n  break;\n}\n");
    assert_eq!(count_key(&bare, "javascript:S1264"), 1);

    let counted = js_keys("for (let i = 0; i < n; i++) {\n  f(i);\n}\n");
    assert_eq!(count_key(&counted, "javascript:S1264"), 0);
}

#[test]
fn s2251_flags_counter_moving_away_from_bound() {
    let away = js_keys("for (let i = 0; i < n; i--) {}\n");
    assert_eq!(count_key(&away, "javascript:S2251"), 1);

    let towards = js_keys("for (let i = 0; i > n; i--) {}\n");
    assert_eq!(count_key(&towards, "javascript:S2251"), 0);

    let incrementing_up = js_keys("for (let i = 0; i < n; i++) {}\n");
    assert_eq!(count_key(&incrementing_up, "javascript:S2251"), 0);
}

#[test]
fn s1994_flags_update_clause_not_touching_counter() {
    let other_counter = js_keys("let j = 0;\nfor (let i = 0; i < n; j++) {}\n");
    assert_eq!(count_key(&other_counter, "javascript:S1994"), 1);

    let compound_update = js_keys("for (let i = 0; i < n; i += 2) {}\n");
    assert_eq!(count_key(&compound_update, "javascript:S1994"), 0);
}

#[test]
fn s2310_flags_counter_writes_inside_loop_body() {
    let assigned = js_keys("for (let i = 0; i < n; i++) {\n  i = 5;\n}\n");
    assert_eq!(count_key(&assigned, "javascript:S2310"), 1);

    let updated = js_keys("for (let i = 0; i < n; i++) {\n  i++;\n}\n");
    assert_eq!(count_key(&updated, "javascript:S2310"), 1);

    let other_variable = js_keys("for (let i = 0; i < n; i++) {\n  j = 5;\n}\n");
    assert_eq!(count_key(&other_variable, "javascript:S2310"), 0);
}

#[test]
fn s135_flags_more_than_one_direct_exit_point() {
    let two_breaks =
        js_keys("while (a) {\n  if (b) {\n    break;\n  }\n  if (c) {\n    break;\n  }\n}\n");
    assert_eq!(count_key(&two_breaks, "javascript:S135"), 1);

    let one_break = js_keys("while (a) {\n  if (b) {\n    break;\n  }\n  f();\n}\n");
    assert_eq!(count_key(&one_break, "javascript:S135"), 0);

    // Breaks inside a nested loop count for the inner loop only.
    let nested = js_keys(
        "while (a) {\n  if (b) {\n    break;\n  }\n  while (c) {\n    if (d) {\n      break;\n    }\n    break;\n  }\n}\n",
    );
    assert_eq!(count_key(&nested, "javascript:S135"), 1);
    let inner_line = nested
        .iter()
        .find(|(key, _)| key == "javascript:S135")
        .map(|(_, line)| *line);
    assert_eq!(inner_line, Some(5));
}

#[test]
fn s1751_flags_single_iteration_loops() {
    let constant_false = js_keys("while (false) {\n  f();\n}\n");
    assert_eq!(count_key(&constant_false, "javascript:S1751"), 1);

    let terminal_break = js_keys("while (x) {\n  f();\n  break;\n}\n");
    assert_eq!(count_key(&terminal_break, "javascript:S1751"), 1);

    let continue_keeps_iterations =
        js_keys("while (x) {\n  if (y) {\n    continue;\n  }\n  break;\n}\n");
    assert_eq!(count_key(&continue_keeps_iterations, "javascript:S1751"), 0);

    let ordinary = js_keys("while (x) {\n  f();\n}\n");
    assert_eq!(count_key(&ordinary, "javascript:S1751"), 0);
}

#[test]
fn s2189_flags_endless_loops_without_terminators() {
    let forever = js_keys("while (true) {\n  f();\n}\n");
    assert_eq!(count_key(&forever, "javascript:S2189"), 1);

    let do_forever = js_keys("do {\n  f();\n} while (true);\n");
    assert_eq!(count_key(&do_forever, "javascript:S2189"), 1);

    let with_break = js_keys("while (true) {\n  break;\n}\n");
    assert_eq!(count_key(&with_break, "javascript:S2189"), 0);

    let with_return = js_keys("function f() {\n  for (;;) {\n    return 1;\n  }\n}\n");
    assert_eq!(count_key(&with_return, "javascript:S2189"), 0);

    // JS-only rule: TypeScript files are never flagged.
    let typescript = findings("while (true) {\n  f();\n}\n", JstsLanguage::TypeScript);
    assert_eq!(count_key(&typescript, "typescript:S2189"), 0);
}

#[test]
fn s1535_requires_hasownproperty_guard_in_for_in() {
    let bare = js_keys("for (const k in obj) {\n  f(k);\n}\n");
    assert_eq!(count_key(&bare, "javascript:S1535"), 1);

    let guarded =
        js_keys("for (const k in obj) {\n  if (obj.hasOwnProperty(k)) {\n    f(k);\n  }\n}\n");
    assert_eq!(count_key(&guarded, "javascript:S1535"), 0);
}

#[test]
fn s4139_flags_for_in_over_arrays_and_strings() {
    let array = js_keys("for (const v in [\"a\", \"b\"]) {\n  f(v);\n}\n");
    assert_eq!(count_key(&array, "javascript:S4139"), 1);

    let string = js_keys("for (const v in \"ab\") {\n  f(v);\n}\n");
    assert_eq!(count_key(&string, "javascript:S4139"), 1);

    let object = js_keys("for (const v in obj) {\n  f(v);\n}\n");
    assert_eq!(count_key(&object, "javascript:S4139"), 0);
}

#[test]
fn s4138_flags_for_of_over_non_iterables() {
    let object = js_keys("for (const v of { a: 1 }) {\n  f(v);\n}\n");
    assert_eq!(count_key(&object, "javascript:S4138"), 1);

    let number = js_keys("for (const v of 5) {\n  f(v);\n}\n");
    assert_eq!(count_key(&number, "javascript:S4138"), 1);

    let array = js_keys("for (const v of [1, 2]) {\n  f(v);\n}\n");
    assert_eq!(count_key(&array, "javascript:S4138"), 0);
}

#[test]
fn too_many_parameters_flags_eighth_and_counts_rest() {
    assert_eq!(
        count_key(
            &js_keys("function f(a, b, c, d, e, g, h) { return a; }\n"),
            "javascript:S107"
        ),
        0
    );

    let over = js("function f(a, b, c, d, e, g, h, i) { return a; }\n");
    let s107: Vec<_> = over
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(":S107"))
        .collect();
    assert_eq!(s107.len(), 1);
    assert_eq!(
        s107[0].message,
        "This function has 8 parameters, which is greater than the 7 authorized."
    );
    assert_eq!(s107[0].range.start, pos(1, 10));

    // A rest parameter counts as one parameter toward the limit.
    assert_eq!(
        count_key(
            &js_keys("const f = (a, b, c, d, e, g, ...rest) => a;\n"),
            "javascript:S107"
        ),
        0
    );
    assert_eq!(
        count_key(
            &js_keys("const f = (a, b, c, d, e, g, h, ...rest) => a;\n"),
            "javascript:S107"
        ),
        1
    );
}

#[test]
fn control_flow_nesting_flags_fourth_level_and_resets_per_function() {
    let deep = js("if (a) { for (;;) { while (b) { if (c) { d(); } } } }\n");
    let s134: Vec<_> = deep
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(":S134"))
        .collect();
    assert_eq!(s134.len(), 1);
    assert_eq!(s134[0].range.start, pos(1, 32));

    // Three levels of nesting are exactly at the allowed maximum.
    assert_eq!(
        count_key(
            &js_keys("if (a) {\n  for (;;) {\n    while (b) {\n      c();\n    }\n  }\n}\n"),
            "javascript:S134"
        ),
        0
    );

    // Function boundaries reset the depth: without the reset, `if (c)`
    // would sit at depth four.
    assert_eq!(
        count_key(
            &js_keys(
                "function outer() {\n  if (a) {\n    function inner() {\n      if (b) {\n        if (c) {\n          e();\n        }\n      }\n    }\n  }\n}\n"
            ),
            "javascript:S134"
        ),
        0
    );
}

#[test]
fn jumps_in_finally_flagged_but_catch_return_allowed() {
    let source = "\
function withReturn() {
  try {
    a();
  } finally {
    return 1;
  }
}
function catchReturn() {
  try {
    b();
  } catch (e) {
    return e;
  } finally {
    c();
  }
}
function withThrow() {
  try {
    d();
  } finally {
    throw 'x';
  }
}
function loopJump() {
  for (;;) {
    try {
      e();
    } finally {
      continue;
    }
  }
}
";
    assert_eq!(count_key(&js_keys(source), "javascript:S1143"), 3);

    // A `return` in the catch clause is fine when there is no jump of
    // its own anywhere in the try statement.
    assert_eq!(
        count_key(
            &js_keys(
                "function f() {\n  try {\n    a();\n  } catch (err) {\n    return err;\n  }\n}\n"
            ),
            "javascript:S1143"
        ),
        0
    );
}

#[test]
fn embedded_updates_and_assignments_require_statement_roots() {
    let source = "\
let i = 0;
i++;
for (i = 0; i < 3; i++) {
  foo(i++);
}
let j = i++;
foo(k = 1);
if (k = 1) {}
m = n = 1;
";
    let report = js(source);
    let embedded: Vec<_> = report
        .issues
        .iter()
        .filter(|issue| {
            matches!(
                issue.rule_key.as_str(),
                "javascript:S881" | "javascript:S1121"
            )
        })
        .map(|issue| {
            (
                issue.rule_key.clone(),
                (
                    issue.range.start.line,
                    issue.range.start.column,
                    issue.range.end.line,
                    issue.range.end.column,
                ),
            )
        })
        .collect();
    // Standalone `i++`, the assignment in the `for` header, and the
    // statement-root assignment are clean; everything embedded deeper
    // than a statement root is flagged once per construct.
    let hit =
        |rule: &str, line: u32, start: u32, end: u32| (rule.to_string(), (line, start, line, end));
    assert_eq!(
        embedded,
        vec![
            hit("javascript:S881", 4, 6, 9),
            hit("javascript:S881", 6, 8, 11),
            hit("javascript:S1121", 7, 4, 9),
            hit("javascript:S1121", 8, 4, 9),
            hit("javascript:S1121", 9, 4, 9),
        ]
    );
}

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
fn brace_style_tolerates_comments_between_head_and_brace() {
    // The trailing comment shares the head's line; the brace on the next
    // line is still flagged against it.
    let trailing = js("if (a) // note\n{\n  b();\n}\n");
    let braces: Vec<_> = trailing
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(":S1105"))
        .map(|issue| (issue.range.start.line, issue.range.start.column))
        .collect();
    assert_eq!(braces, vec![(2, 0)]);

    // A comment-only line between head and brace is skipped entirely.
    let separated = js("if (a)\n// note\n{\n  b();\n}\n");
    let braces: Vec<_> = separated
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(":S1105"))
        .map(|issue| (issue.range.start.line, issue.range.start.column))
        .collect();
    assert_eq!(braces, vec![(3, 0)]);

    // Fully 1tbs code stays clean across constructs.
    assert_eq!(
        count_key(
            &js_keys(
                "function good() {\n  if (a) {\n    b();\n  } else {\n    c();\n  }\n  try {\n    d();\n  } catch (e) {\n    f();\n  } finally {\n    g();\n  }\n  while (a) {\n    h();\n  }\n}\n"
            ),
            "javascript:S1105"
        ),
        0
    );
}

#[test]
fn labels_on_switch_cases_and_non_loops_are_flagged() {
    assert_eq!(
        count_key(
            &js_keys("switch (x) {\n  case 1:\n    outer: break;\n}\n"),
            "javascript:S1219"
        ),
        1
    );

    assert_eq!(
        count_key(
            &js_keys("outer: for (;;) {\n  break outer;\n}\n"),
            "javascript:S1439"
        ),
        0
    );

    assert_eq!(
        count_key(&js_keys("outer: {\n  f();\n}\n"), "javascript:S1439"),
        1
    );
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

#[test]
fn statements_after_jumps_are_unreachable() {
    let source = "\
function f() {
  return 1;
  g();
}
function clean() {
  if (a) {
    return 1;
  }
  g();
}
";
    let report = js(source);
    let s1763: Vec<_> = report
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(":S1763"))
        .map(|issue| issue.range.start.line)
        .collect();
    assert_eq!(s1763, vec![3]);
}

#[test]
fn functions_in_loops_blocks_and_depths_are_flagged() {
    // S1515: a closure created inside a loop body.
    let in_loop = js_keys("for (const v of items) {\n  setTimeout(() => v);\n}\n");
    assert_eq!(count_key(&in_loop, "javascript:S1515"), 1);

    let in_header = js_keys("for (const f of makers) {\n  f();\n}\n");
    assert_eq!(count_key(&in_header, "javascript:S1515"), 0);

    // S1530: function declaration nested in a block; top level is fine.
    let in_block = js_keys("{\n  function inner() {}\n}\n");
    assert_eq!(count_key(&in_block, "javascript:S1530"), 1);
    let top_level = js_keys("function outer() {}\n");
    assert_eq!(count_key(&top_level, "javascript:S1530"), 0);

    // S2004: five levels of nesting exceed the maximum of four.
    let deep_keys = js_keys(
        "function a() {\n  const b = () => {\n    const c = () => {\n      const d = () => {\n        const e = () => {};\n      };\n    };\n  };\n}\n",
    );
    assert_eq!(count_key(&deep_keys, "javascript:S2004"), 1);
    assert_eq!(count_key(&deep_keys, "javascript:S1515"), 0);

    // Four levels are exactly at the allowed maximum.
    assert_eq!(
        count_key(
            &js_keys(
                "function a() {\n  const b = () => {\n    const c = () => {\n      const d = () => {};\n    };\n  };\n}\n"
            ),
            "javascript:S2004"
        ),
        0
    );
}

#[test]
fn default_parameters_must_come_last() {
    let ordered = js_keys("function f(a, b = 1, c = 2) { return a; }\n");
    assert_eq!(count_key(&ordered, "javascript:S1788"), 0);

    let unordered = js_keys("function f(a = 1, b) { return b; }\n");
    assert_eq!(count_key(&unordered, "javascript:S1788"), 1);
}

#[test]
fn call_arguments_split_across_lines_are_flagged() {
    let split = js("foo(\n  bar);\n");
    let s1472: Vec<_> = split
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(":S1472"))
        .collect();
    assert_eq!(s1472.len(), 1);
    assert_eq!(
        s1472[0].range,
        hoonarqube_ir::Range {
            start: pos(2, 2),
            end: pos(2, 5),
        }
    );

    assert_eq!(count_key(&js_keys("foo(bar);\n"), "javascript:S1472"), 0);
}

#[test]
fn self_assignments_are_flagged_for_names_and_chains() {
    let source = "\
a = a;
obj.x = obj.x;
b = c;
";
    let report = js(source);
    let s1656_lines: Vec<u32> = report
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(":S1656"))
        .map(|issue| issue.range.start.line)
        .collect();
    assert_eq!(s1656_lines, vec![1, 2]);
}
#[test]
fn exception_handling_rules_flag_empty_rethrow_and_setter_returns() {
    let source = "\
function rethrowOnly() {
  try {
    a();
  } catch (e) {
    throw e;
  }
}
function meaningful() {
  try {
    b();
  } catch (e) {
    log(e);
    throw e;
  }
}
function silent() {
  try {
    c();
  } catch {
  }
}
";
    let keys = js_keys(source);
    assert_eq!(count_key(&keys, "javascript:S2737"), 1);
    // The comment-only catch is tolerated by `S2486`.
    let with_comment = js_keys(
        "function f() {\n  try {\n    d();\n  } catch {\n    // ignored on purpose\n  }\n}\n",
    );
    assert_eq!(count_key(&with_comment, "javascript:S2486"), 0);
    assert_eq!(count_key(&keys, "javascript:S2486"), 1);

    // A setter returning a value is flagged only for JavaScript files.
    let setter_source = "class A {\n  set value(next) {\n    return next;\n  }\n}\n";
    assert_eq!(
        js(setter_source)
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S2432"))
            .count(),
        1
    );
    assert_eq!(
        ts(setter_source)
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S2432"))
            .count(),
        0
    );
}

#[test]
fn delete_prototype_and_generator_rules_flag_expected_shapes() {
    let delete_plain = js_keys("delete variable;\n");
    assert_eq!(count_key(&delete_plain, "javascript:S3001"), 1);
    let delete_member = js_keys("delete obj.field;\n");
    assert_eq!(count_key(&delete_member, "javascript:S3001"), 0);

    let prototype_assignment = js_keys("Type.prototype.method = function () {};\n");
    assert_eq!(count_key(&prototype_assignment, "javascript:S3525"), 1);
    let plain_assignment = js_keys("obj.handler = function () {};\n");
    assert_eq!(count_key(&plain_assignment, "javascript:S3525"), 0);

    let empty_generator = js_keys("function* generate() {}\n");
    assert_eq!(count_key(&empty_generator, "javascript:S3531"), 1);
    let yielding_generator = js_keys("function* generate() {\n  yield 1;\n}\n");
    assert_eq!(count_key(&yielding_generator, "javascript:S3531"), 0);
    // A yield inside a nested generator belongs to that nested function.
    let nested_yield_only =
        js_keys("function* outer() {\n  function* inner() {\n    yield 1;\n  }\n}\n");
    assert_eq!(count_key(&nested_yield_only, "javascript:S3531"), 1);
}

#[test]
fn trailing_jumps_flagged_only_in_redundant_positions() {
    let loop_break = js_keys("while (a) {\n  break;\n}\n");
    assert_eq!(count_key(&loop_break, "javascript:S3626"), 1);

    let bare_block = js("function f() {\n  {\n    return 1;\n  }\n}\n");
    let s3626_lines: Vec<u32> = bare_block
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(":S3626"))
        .map(|issue| issue.range.start.line)
        .collect();
    assert_eq!(s3626_lines, vec![3]);

    // Function bodies and case bodies end with jumps conventionally.
    let conventional = js_keys("switch (x) {\n  case 1:\n    break;\n}\n");
    assert_eq!(count_key(&conventional, "javascript:S3626"), 0);
    let fn_tail = js_keys("function f() {\n  return 1;\n}\n");
    assert_eq!(count_key(&fn_tail, "javascript:S3626"), 0);
}

#[test]
fn getters_without_setters_are_flagged_on_classes_and_objects() {
    let class_unpaired = js_keys("class A {\n  get value() {\n    return 1;\n  }\n}\n");
    assert_eq!(count_key(&class_unpaired, "javascript:S2376"), 1);
    let class_paired =
        js_keys("class A {\n  get value() {\n    return 1;\n  }\n  set value(next) {}\n}\n");
    assert_eq!(count_key(&class_paired, "javascript:S2376"), 0);

    let object_unpaired = js_keys("const obj = {\n  get count() {\n    return this.n;\n  }\n};\n");
    assert_eq!(count_key(&object_unpaired, "javascript:S2376"), 1);
}

#[test]
fn swapped_call_arguments_detected_by_name_match() {
    let source = "\
function draw(width, height) {}
draw(height, width);
draw(width, height);
draw(other, more);
";
    let report = js(source);
    let s2234_lines: Vec<u32> = report
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(":S2234"))
        .map(|issue| issue.range.start.line)
        .collect();
    assert_eq!(s2234_lines, vec![2]);
}

#[test]
fn mixed_arrow_body_styles_flag_the_minority() {
    let minority_block =
        js_keys("const a = () => 1;\nconst b = () => 2;\nconst c = () => {\n  return 3;\n};\n");
    assert_eq!(count_key(&minority_block, "javascript:S3524"), 1);

    let consistent = js_keys("const a = () => 1;\nconst b = () => 2;\n");
    assert_eq!(count_key(&consistent, "javascript:S3524"), 0);

    // On ties the expression-bodied arrows are flagged.
    let tie = js_keys("const a = () => {\n  return 1;\n};\nconst b = () => 2;\n");
    assert_eq!(count_key(&tie, "javascript:S3524"), 1);
}
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
fn mixed_return_styles_are_flagged() {
    let mixed = js_keys("function f(c) {\n  if (c) {\n    return 1;\n  }\n  return;\n}\n");
    assert_eq!(count_key(&mixed, "javascript:S3801"), 1);

    // Valued returns plus an implicit fall-off end.
    let falls_off = js_keys("function g(c) {\n  if (c) {\n    return 1;\n  }\n}\n");
    assert_eq!(count_key(&falls_off, "javascript:S3801"), 1);

    let consistent = js_keys("function h(c) {\n  if (c) {\n    return 1;\n  }\n  return 2;\n}\n");
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
    let nested =
        js_keys("[1].map(function (x) {\n  setTimeout(function () {\n    return 5;\n  });\n});\n");
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
    assert_eq!(count_key(&missing, "javascript:S3854"), 1);
    // this-use is not separately flagged when no super() exists at all.

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

    let setter_bad = js_keys("class C {\n  set size(value) {\n    this.length = value;\n  }\n}\n");
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
    let flagged = js_keys("const a = cond ? (x ? 1 : 2) : 3;\nconst b = cond ? 1 : (y ? 2 : 3);\n");
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
fn pure_string_concatenation_suggests_template_literals() {
    let flagged = js_keys("const s = 'a' + 'b' + 'c';\n");
    // Only the outermost chain root is flagged.
    assert_eq!(count_key(&flagged, "javascript:S3512"), 1);

    let dynamic = js_keys("const t = 'a' + name;\n");
    assert_eq!(count_key(&dynamic, "javascript:S3512"), 0);
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
fn match_with_global_regex_prefers_match_all() {
    let flagged = js_keys("const hits = text.match(/ab/g);\n");
    assert_eq!(count_key(&flagged, "javascript:S6594"), 1);

    let no_global = js_keys("const one = text.match(/ab/);\n");
    assert_eq!(count_key(&no_global, "javascript:S6594"), 0);
}

// ----- Regex-literal family (Batch3, check_regex_family) -----

#[test]
fn invalid_regex_literals_are_flagged() {
    // Unbalanced parenthesis, unknown group header, and reversed class
    // range are definite syntax errors for the mini parser.
    assert_eq!(
        count_key(&js_keys("const re = /(/;\n"), "javascript:S5856"),
        1
    );
    assert_eq!(
        count_key(&js_keys("const re = /(?P<name>a)/;\n"), "javascript:S5856"),
        1
    );
    assert_eq!(
        count_key(&js_keys("const re = /[z-a]/;\n"), "javascript:S5856"),
        1
    );

    let clean = js_keys("const re = /ab+/;\n");
    assert_eq!(count_key(&clean, "javascript:S5856"), 0);

    // Forward class ranges are valid JavaScript; only reversed ones are
    // definite errors.
    let ranges = js_keys("const re = /[A-Z][a-z0-9]*/;\n");
    assert_eq!(count_key(&ranges, "javascript:S5856"), 0);

    // An escape on either side of a dash stays valid: `[a-z\d]` parses
    // as range plus shorthand, and `[a-\d]` keeps the dash literal
    // (Annex B) instead of failing.
    let mixed = js_keys("const re = /[a-z\\d]/;\n");
    assert_eq!(count_key(&mixed, "javascript:S5856"), 0);
    let dash_escape = js_keys("const re = /[a-\\d]/;\n");
    assert_eq!(count_key(&dash_escape, "javascript:S5856"), 0);

    // The family is cataloged for both languages; the prefix follows the
    // file language.
    let typescript = findings("const re = /[z-a]/;\n", JstsLanguage::TypeScript);
    assert_eq!(count_key(&typescript, "typescript:S5856"), 1);
}

#[test]
fn constant_regexp_constructor_prefers_literal() {
    let flagged = js_keys("const re = new RegExp('ab+c');\nRegExp('\\\\d+', 'g');\n");
    assert_eq!(count_key(&flagged, "javascript:S6325"), 2);

    // A substitution-free template literal also counts as constant.
    let template = js_keys("const re = new RegExp(`ab+c`);\n");
    assert_eq!(count_key(&template, "javascript:S6325"), 1);

    let dynamic = js_keys("const re = new RegExp(userPattern);\n");
    assert_eq!(count_key(&dynamic, "javascript:S6325"), 0);

    let literal_form = js_keys("const re = /ab+c/;\n");
    assert_eq!(count_key(&literal_form, "javascript:S6325"), 0);
}

#[test]
fn empty_character_classes_are_flagged() {
    let empty = js_keys("const re = /[]/;\n");
    assert_eq!(count_key(&empty, "javascript:S2639"), 1);

    let negated = js_keys("const re = /[^]/;\n");
    assert_eq!(count_key(&negated, "javascript:S2639"), 1);

    let clean = js_keys("const re = /[ab]/;\n");
    assert_eq!(count_key(&clean, "javascript:S2639"), 0);
}

#[test]
fn empty_alternation_branches_are_flagged() {
    let trailing = js_keys("const re = /a|/;\n");
    assert_eq!(count_key(&trailing, "javascript:S6323"), 1);

    let leading = js_keys("const re = /|b/;\n");
    assert_eq!(count_key(&leading, "javascript:S6323"), 1);

    // An empty branch inside a group belongs here, not to S6331.
    let in_group = js_keys("const re = /(a|)/;\n");
    assert_eq!(count_key(&in_group, "javascript:S6323"), 1);

    let clean = js_keys("const re = /a|b/;\n");
    assert_eq!(count_key(&clean, "javascript:S6323"), 0);
}

#[test]
fn wholly_empty_groups_are_flagged() {
    let capturing = js_keys("const re = /()/;\n");
    assert_eq!(count_key(&capturing, "javascript:S6331"), 1);
    // A wholly empty group is not reported as an empty alternative.
    assert_eq!(count_key(&capturing, "javascript:S6323"), 0);

    let non_capturing = js_keys("const re = /(?:)/;\n");
    assert_eq!(count_key(&non_capturing, "javascript:S6331"), 1);

    let clean = js_keys("const re = /(a)/;\n");
    assert_eq!(count_key(&clean, "javascript:S6331"), 0);
}

#[test]
fn duplicate_class_members_are_flagged() {
    let duplicated = js_keys("const re = /[aa]/;\n");
    assert_eq!(count_key(&duplicated, "javascript:S5869"), 1);
    // Duplicate-only classes additionally receive the concise rewrite.
    assert_eq!(count_key(&duplicated, "javascript:S6353"), 1);

    let twice = js_keys("const re = /[aaa]/;\n");
    assert_eq!(count_key(&twice, "javascript:S5869"), 2);

    let clean = js_keys("const re = /[ab]/;\n");
    assert_eq!(count_key(&clean, "javascript:S5869"), 0);
}

#[test]
fn single_member_classes_are_flagged() {
    let single = js_keys("const re = /[a]/;\n");
    assert_eq!(count_key(&single, "javascript:S6397"), 1);

    // Shorthand escapes are not literal characters and stay out of the
    // rewrite scope.
    let escape = js_keys("const re = /[\\d]/;\n");
    assert_eq!(count_key(&escape, "javascript:S6397"), 0);

    let clean = js_keys("const re = /[ab]/;\n");
    assert_eq!(count_key(&clean, "javascript:S6397"), 0);
}

#[test]
fn redundant_quantifier_shapes_are_flagged() {
    let exact = js_keys("const re = /a{1}/;\n");
    assert_eq!(count_key(&exact, "javascript:S6353"), 1);

    let explicit_range = js_keys("const re = /ab{1,1}c/;\n");
    assert_eq!(count_key(&explicit_range, "javascript:S6353"), 1);

    let clean = js_keys("const re = /a{2}/;\n");
    assert_eq!(count_key(&clean, "javascript:S6353"), 0);
}

#[test]
fn space_runs_in_patterns_are_flagged() {
    let double = js_keys("const re = /a  b/;\n");
    assert_eq!(count_key(&double, "javascript:S6326"), 1);

    let triple = js_keys("const re = /a   b/;\n");
    assert_eq!(count_key(&triple, "javascript:S6326"), 1);

    let clean = js_keys("const re = /a b/;\n");
    assert_eq!(count_key(&clean, "javascript:S6326"), 0);
}

#[test]
fn bare_control_characters_are_flagged() {
    let control = js_keys("const re = /a\u{0001}b/;\n");
    assert_eq!(count_key(&control, "javascript:S6324"), 1);

    // Tab/newline conventions are exempt.
    let tab = js_keys("const re = /a\tb/;\n");
    assert_eq!(count_key(&tab, "javascript:S6324"), 0);
}

#[test]
fn replacement_group_references_are_validated() {
    let out_of_range = js_keys("'ab'.replace(/(a)(b)/, '$3');\n");
    assert_eq!(count_key(&out_of_range, "javascript:S6328"), 1);

    let unknown_name = js_keys("'a'.replace(/(?<first>a)/, '$<second>');\n");
    assert_eq!(count_key(&unknown_name, "javascript:S6328"), 1);

    let clean = js_keys("'ab'.replace(/(a)(b)/, '$2$1');\n'a'.replace(/(?<x>a)/, '$<x>');\n");
    assert_eq!(count_key(&clean, "javascript:S6328"), 0);

    // `$$` escapes the dollar and never references a group.
    let escaped = js_keys("'ab'.replace(/(a)/, '$$1');\n");
    assert_eq!(count_key(&escaped, "javascript:S6328"), 0);
}

#[test]
fn empty_string_repetition_is_flagged() {
    // Bounded repetition over a group that can match empty still loops.
    let bounded = js_keys("const re = /x(a*){2}y/;\n");
    assert_eq!(count_key(&bounded, "javascript:S5842"), 1);

    // `(a*)+` trips both this rule and exponential backtracking.
    let unbounded = js_keys("const re = /(a*)+b/;\n");
    assert_eq!(count_key(&unbounded, "javascript:S5842"), 1);
    assert_eq!(count_key(&unbounded, "javascript:S5852"), 1);

    let clean = js_keys("const re = /(a+){2}/;\n");
    assert_eq!(count_key(&clean, "javascript:S5842"), 0);
}

#[test]
fn pointless_reluctant_quantifiers_are_flagged() {
    let reluctant = js_keys("const re = /a*?b*/;\n");
    assert_eq!(count_key(&reluctant, "javascript:S6019"), 1);

    let clean = js_keys("const re = /a*?b/;\n");
    assert_eq!(count_key(&clean, "javascript:S6019"), 0);
}

#[test]
fn single_char_alternations_become_classes() {
    let top_level = js_keys("const re = /a|b|c/;\n");
    assert_eq!(count_key(&top_level, "javascript:S6035"), 1);

    // Alternations nested inside groups are flagged at the group span.
    let nested = js_keys("const re = /x(a|b)y/;\n");
    assert_eq!(count_key(&nested, "javascript:S6035"), 1);

    let clean = js_keys("const re = /(ab)|c/;\n");
    assert_eq!(count_key(&clean, "javascript:S6035"), 0);
}

#[test]
fn anchored_alternations_need_explicit_grouping() {
    let both_anchors = js_keys("const re = /^a|b$/;\n");
    assert_eq!(count_key(&both_anchors, "javascript:S5850"), 1);

    let start_only = js_keys("const re = /^a|b/;\n");
    assert_eq!(count_key(&start_only, "javascript:S5850"), 1);

    let grouped = js_keys("const re = /^(a|b)$/;\n");
    assert_eq!(count_key(&grouped, "javascript:S5850"), 0);

    let unanchored = js_keys("const re = /a|b/;\n");
    assert_eq!(count_key(&unanchored, "javascript:S5850"), 0);
}

#[test]
fn unicode_constructs_require_the_u_flag() {
    let property_escape = js_keys("const re = /\\p{L}/;\n");
    assert_eq!(count_key(&property_escape, "javascript:S5867"), 1);

    let brace_escape = js_keys("const re = /\\u{1F600}/;\n");
    assert_eq!(count_key(&brace_escape, "javascript:S5867"), 1);

    let with_flag = js_keys("const re = /\\p{L}/u;\n");
    assert_eq!(count_key(&with_flag, "javascript:S5867"), 0);
}

#[test]
fn grapheme_components_inside_classes_are_flagged() {
    // Combining acute accent after `e` matches one scalar, not `é`.
    let combining = js_keys("const re = /[e\u{0301}]/u;\n");
    assert_eq!(count_key(&combining, "javascript:S5868"), 1);

    // Each regional indicator inside a class is its own defect.
    let regional = js_keys("const flags = /[\u{1F1E6}\u{1F1E7}]/u;\n");
    assert_eq!(count_key(&regional, "javascript:S5868"), 2);

    let clean = js_keys("const re = /[ab]/u;\n");
    assert_eq!(count_key(&clean, "javascript:S5868"), 0);
}
#[test]
fn regex_complexity_budget_is_enforced() {
    // Scores 29 against the budget of 20: three alternation branches
    // of quantified shorthands and classes.
    let over = js_keys("const re = /\\d{4}-\\d{2}-\\d{2}|\\d{8}|\\d{2}[A-Z]{4}/;\n");
    assert_eq!(count_key(&over, "javascript:S5843"), 1);

    let under = js_keys("const re = /\\d{4}-\\d{2}-\\d{2}/;\n");
    assert_eq!(count_key(&under, "javascript:S5843"), 0);
}

#[test]
fn nested_unbounded_quantifiers_risk_backtracking() {
    let classic = js_keys("const re = /(a+)+$/;\n");
    assert_eq!(count_key(&classic, "javascript:S5852"), 1);
    // `(a+)` cannot match empty, so S5842 stays silent here.
    assert_eq!(count_key(&classic, "javascript:S5842"), 0);

    // Zero-minimum repetition escapes S5842's consuming-quantifier subset.
    let zero_min = js_keys("const re = /(a*)*b/;\n");
    assert_eq!(count_key(&zero_min, "javascript:S5852"), 1);
    assert_eq!(count_key(&zero_min, "javascript:S5842"), 0);

    let flat = js_keys("const re = /a+b+c/;\n");
    assert_eq!(count_key(&flat, "javascript:S5852"), 0);
}

#[test]
fn stateful_global_regexes_inside_loops_are_flagged() {
    let while_loop =
        js_keys("while (more) {\n  if (/\\d+/g.test(input)) {\n    more = false;\n  }\n}\n");
    assert_eq!(count_key(&while_loop, "javascript:S6351"), 1);

    let for_of_loop =
        js_keys("for (const part of parts) {\n  const m = /[a-z]+/g.exec(part);\n}\n");
    assert_eq!(count_key(&for_of_loop, "javascript:S6351"), 1);

    let outside_loop = js_keys("const found = /\\d+/g.test(input);\n");
    assert_eq!(count_key(&outside_loop, "javascript:S6351"), 0);

    let not_global = js_keys("while (more) {\n  found = /\\d+/.test(input);\n}\n");
    assert_eq!(count_key(&not_global, "javascript:S6351"), 0);
}
// ===== Batch4 group R1 tests: React/JSX structural rules =====

fn jsx_keys(source: &str) -> Vec<(String, u32)> {
    analyze(
        PathBuf::from("test.jsx"),
        source,
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
    )
    .issues
    .into_iter()
    .map(|issue| (issue.rule_key, issue.range.start.line))
    .collect()
}

#[test]
fn children_prop_conflicts_with_nested_children() {
    let both = jsx_keys("const el = <div children={<a/>}><b/></div>;\n");
    assert_eq!(count_key(&both, "javascript:S6748"), 1);

    let attribute_only = jsx_keys("const el = <div children={<a/>}/>;\n");
    assert_eq!(count_key(&attribute_only, "javascript:S6748"), 0);

    let nested_only = jsx_keys("const el = <div><b/></div>;\n");
    assert_eq!(count_key(&nested_only, "javascript:S6748"), 0);
}

#[test]
fn children_and_raw_html_attributes_conflict() {
    let both =
        jsx_keys("const el = <div children={<a/>} dangerouslySetInnerHTML={{__html: 'x'}}/>;\n");
    assert_eq!(count_key(&both, "javascript:S6761"), 1);

    let raw_only = jsx_keys("const el = <div dangerouslySetInnerHTML={{__html: 'x'}}/>;\n");
    assert_eq!(count_key(&raw_only, "javascript:S6761"), 0);
}

#[test]
fn single_child_fragments_are_flagged() {
    let element_child = jsx_keys("const el = <><span/></>;\n");
    assert_eq!(count_key(&element_child, "javascript:S6749"), 1);

    let expression_child = jsx_keys("let item = 1;\nconst el = <>{item}</>;\n");
    assert_eq!(count_key(&expression_child, "javascript:S6749"), 1);

    let two_children = jsx_keys("const el = <><span/><span/></>;\n");
    assert_eq!(count_key(&two_children, "javascript:S6749"), 0);

    let empty_fragment = jsx_keys("const el = <></>;\n");
    assert_eq!(count_key(&empty_fragment, "javascript:S6749"), 0);
}

#[test]
fn consumed_render_results_are_flagged() {
    let consumed = jsx_keys("const el = ReactDOM.render(<span/>, node);\n");
    assert_eq!(count_key(&consumed, "javascript:S6750"), 1);

    let statement = jsx_keys("ReactDOM.render(<span/>, node);\n");
    assert_eq!(count_key(&statement, "javascript:S6750"), 0);
}

#[test]
fn use_state_pairs_follow_naming_convention() {
    let symmetric = js_keys("const [count, setCount] = useState(0);\n");
    assert_eq!(count_key(&symmetric, "javascript:S6754"), 0);

    let asymmetric = js_keys("const [count, setValue] = useState(0);\n");
    assert_eq!(count_key(&asymmetric, "javascript:S6754"), 1);

    let missing_set_prefix = js_keys("const [count, countUpdated] = useState(0);\n");
    assert_eq!(count_key(&missing_set_prefix, "javascript:S6754"), 1);
}

#[test]
fn noop_state_setters_are_flagged() {
    let self_assigning = js_keys("setCount(count);\n");
    assert_eq!(count_key(&self_assigning, "javascript:S6443"), 1);

    let updater = js_keys("setCount(count + 1);\n");
    assert_eq!(count_key(&updater, "javascript:S6443"), 0);

    let different_value = js_keys("setCount(other);\n");
    assert_eq!(count_key(&different_value, "javascript:S6443"), 0);
}

#[test]
fn find_dom_node_calls_are_flagged() {
    let flagged = js_keys("ReactDOM.findDOMNode(this).focus();\n");
    assert_eq!(count_key(&flagged, "javascript:S6788"), 1);

    let other_root = js_keys("wrapper.findDOMNode(this);\n");
    assert_eq!(count_key(&other_root, "javascript:S6788"), 0);
}

#[test]
fn is_mounted_calls_are_flagged() {
    let flagged = js_keys("if (this.isMounted()) {\n  done();\n}\n");
    assert_eq!(count_key(&flagged, "javascript:S6789"), 1);

    let other_object = js_keys("if (widget.isMounted()) {\n  done();\n}\n");
    assert_eq!(count_key(&other_object, "javascript:S6789"), 0);
}

#[test]
fn string_refs_and_refs_accesses_are_flagged() {
    let string_ref = jsx_keys("const el = <input ref=\"name\"/>;\n");
    assert_eq!(count_key(&string_ref, "javascript:S6790"), 1);

    let callback_ref = jsx_keys("const el = <input ref={(node) => save(node)}/>;\n");
    assert_eq!(count_key(&callback_ref, "javascript:S6790"), 0);

    let refs_access = js_keys("this.refs.name.focus();\n");
    assert_eq!(count_key(&refs_access, "javascript:S6790"), 1);

    let refs_write = js_keys("this.refs.name = node;\n");
    assert_eq!(count_key(&refs_write, "javascript:S6790"), 1);

    let plain_member = js_keys("this.props.name.focus();\n");
    assert_eq!(count_key(&plain_member, "javascript:S6790"), 0);
}

#[test]
fn legacy_lifecycle_methods_are_flagged() {
    let flagged =
        js_keys("class A extends B {\n  componentWillMount() {}\n  componentDidMount() {}\n}\n");
    assert_eq!(count_key(&flagged, "javascript:S6791"), 1);

    let safe = js_keys("class A extends B {\n  UNSAFE_componentWillMount() {}\n}\n");
    assert_eq!(count_key(&safe, "javascript:S6791"), 0);
}

#[test]
fn deprecated_react_apis_are_flagged() {
    let prop_types_package = js_keys("import PropTypes from 'prop-types';\n");
    assert_eq!(count_key(&prop_types_package, "javascript:S6957"), 1);
    let create_class = js_keys("const x = React.createClass({});\n");
    assert_eq!(count_key(&create_class, "javascript:S6957"), 1);

    let render_call = jsx_keys("ReactDOM.render(<span/>, node);\n");
    assert_eq!(count_key(&render_call, "javascript:S6957"), 1);

    let current_api =
        js_keys("import React from 'react';\nconst x = React.createElement('div');\n");
    assert_eq!(count_key(&current_api, "javascript:S6957"), 0);
}

#[test]
fn pure_component_update_is_useless() {
    let flagged = js_keys(
        "class A extends PureComponent {\n  shouldComponentUpdate() {\n    return true;\n  }\n}\n",
    );
    assert_eq!(count_key(&flagged, "javascript:S6763"), 1);

    let plain_component = js_keys(
        "class A extends Component {\n  shouldComponentUpdate() {\n    return true;\n  }\n}\n",
    );
    assert_eq!(count_key(&plain_component, "javascript:S6763"), 0);
}

#[test]
fn direct_state_mutations_are_flagged() {
    let method_mutation = js_keys("this.state.items.push(1);\n");
    assert_eq!(count_key(&method_mutation, "javascript:S6746"), 1);

    let field_write = js_keys("this.state.count = 5;\n");
    assert_eq!(count_key(&field_write, "javascript:S6746"), 1);

    let copy_first = js_keys("const copy = [...this.state.items];\ncopy.push(1);\n");
    assert_eq!(count_key(&copy_first, "javascript:S6746"), 0);

    let props_chain = js_keys("this.props.items.push(1);\n");
    assert_eq!(count_key(&props_chain, "javascript:S6746"), 0);
}

#[test]
fn unescaped_jsx_entities_are_flagged() {
    // oxc's JSX lexer rejects raw `>` and `}` in text (tolerant parse
    // recovers with no AST), so the flaggable surface is quote marks.
    let double_quoted = jsx_keys("const el = <div>say \"hi\"</div>;\n");
    assert_eq!(count_key(&double_quoted, "javascript:S6766"), 1);

    let apostrophe = jsx_keys("const el = <div>it's here</div>;\n");
    assert_eq!(count_key(&apostrophe, "javascript:S6766"), 1);

    let plain_text = jsx_keys("const el = <div>plain text</div>;\n");
    assert_eq!(count_key(&plain_text, "javascript:S6766"), 0);
}

#[test]
fn empty_containers_without_comments_are_flagged() {
    let empty = jsx_keys("const el = <div>{}</div>;\n");
    assert_eq!(count_key(&empty, "javascript:S6438"), 1);

    let commented = jsx_keys("const el = <div>{/* note */}</div>;\n");
    assert_eq!(count_key(&commented, "javascript:S6438"), 0);
}

#[test]
fn inline_function_props_are_flagged() {
    let arrow_value = jsx_keys("const el = <button onClick={() => save()}/>;\n");
    assert_eq!(count_key(&arrow_value, "javascript:S6480"), 1);

    let bound_value = jsx_keys("const el = <button onClick={handler.bind(this)}/>;\n");
    assert_eq!(count_key(&bound_value, "javascript:S6480"), 1);

    let reference_value = jsx_keys("const el = <button onClick={handler}/>\n;\n");
    assert_eq!(count_key(&reference_value, "javascript:S6480"), 0);
}

#[test]
fn map_index_keys_and_missing_keys_are_flagged() {
    let index_key = jsx_keys("items.map((item, index) => <li key={index}/>);\n");
    assert_eq!(count_key(&index_key, "javascript:S6479"), 1);
    assert_eq!(count_key(&index_key, "javascript:S6477"), 0);

    let stable_key = jsx_keys("items.map((item) => <li key={item.id}/>);\n");
    assert_eq!(count_key(&stable_key, "javascript:S6479"), 0);

    let missing_key = jsx_keys("items.map((item, index) => <li/>);\n");
    assert_eq!(count_key(&missing_key, "javascript:S6477"), 1);
}

#[test]
fn unknown_lowercase_tags_are_flagged() {
    let unknown = jsx_keys("const el = <widget/>;\n");
    assert_eq!(count_key(&unknown, "javascript:S6770"), 1);

    let intrinsic = jsx_keys("const el = <div/>;\n");
    assert_eq!(count_key(&intrinsic, "javascript:S6770"), 0);

    let custom_element = jsx_keys("const el = <my-widget/>;\n");
    assert_eq!(count_key(&custom_element, "javascript:S6770"), 0);

    let component = jsx_keys("const el = <Widget/>;\n");
    assert_eq!(count_key(&component, "javascript:S6770"), 0);
}

#[test]
fn render_methods_must_return_jsx_or_null() {
    let returns_jsx = js_keys("class A {\n  render() {\n    return <span/>;\n  }\n}\n");
    assert_eq!(count_key(&returns_jsx, "javascript:S6435"), 0);

    let returns_nothing = js_keys("class A {\n  render() {\n    console.log(1);\n  }\n}\n");
    assert_eq!(count_key(&returns_nothing, "javascript:S6435"), 1);

    let conditional_null = js_keys(
        "class A {\n  render() {\n    if (done) {\n      return null;\n    }\n    return <span/>;\n  }\n}\n",
    );
    assert_eq!(count_key(&conditional_null, "javascript:S6435"), 0);
}

#[test]
fn literal_conditionals_rendering_children_are_flagged() {
    let numeric_guard = jsx_keys("const el = <div>{5 && <span/>}</div>;\n");
    assert_eq!(count_key(&numeric_guard, "javascript:S6439"), 1);

    let string_guard = jsx_keys("const el = <div>{'x' && <span/>}</div>;\n");
    assert_eq!(count_key(&string_guard, "javascript:S6439"), 1);

    let boolean_guard = jsx_keys("let ready = true;\nconst el = <div>{ready && <span/>}</div>;\n");
    assert_eq!(count_key(&boolean_guard, "javascript:S6439"), 0);

    let attribute_position = jsx_keys("const el = <div prop={5 && <span/>}/>;\n");
    assert_eq!(count_key(&attribute_position, "javascript:S6439"), 0);
}
#[test]
fn hook_calls_under_conditions_are_flagged() {
    let under_if = js_keys("function C() {\n  if (ready) {\n    useState();\n  }\n}\n");
    assert_eq!(count_key(&under_if, "javascript:S6440"), 1);

    let under_loop = js_keys("for (const item of items) {\n  useState();\n}\n");
    assert_eq!(count_key(&under_loop, "javascript:S6440"), 1);

    let in_callback = js_keys("useEffect(() => {\n  useState();\n}, []);\n");
    assert_eq!(count_key(&in_callback, "javascript:S6440"), 1);

    let top_level = js_keys("function Component() {\n  const [v] = useState(0);\n}\n");
    assert_eq!(count_key(&top_level, "javascript:S6440"), 0);
}

#[test]
fn undestructured_use_state_is_flagged() {
    let plain_binding = js_keys("const state = useState(0);\n");
    assert_eq!(count_key(&plain_binding, "javascript:S6442"), 1);

    let destructured = js_keys("const [value, setValue] = useState(0);\n");
    assert_eq!(count_key(&destructured, "javascript:S6442"), 0);
}

#[test]
fn inline_context_values_are_flagged() {
    let object_value = jsx_keys("const el = <Ctx.Provider value={{a: 1}}/>;\n");
    assert_eq!(count_key(&object_value, "javascript:S6481"), 1);

    let array_value = jsx_keys("const el = <Ctx.Provider value={[1]}/>\n;\n");
    assert_eq!(count_key(&array_value, "javascript:S6481"), 1);

    let stable_value = jsx_keys("let memo = {};\nconst el = <Ctx.Provider value={memo}/>\n;\n");
    assert_eq!(count_key(&stable_value, "javascript:S6481"), 0);
}

#[test]
fn nested_component_definitions_are_flagged() {
    let nested = jsx_keys(
        "function Outer() {\n  function Inner() {\n    return <span/>;\n  }\n  return <Inner/>;\n}\n",
    );
    assert_eq!(count_key(&nested, "javascript:S6478"), 1);

    let siblings = jsx_keys(
        "function Outer() {\n  return <span/>;\n}\nfunction Inner() {\n  return <span/>;\n}\n",
    );
    assert_eq!(count_key(&siblings, "javascript:S6478"), 0);
}

#[test]
fn set_state_reading_state_is_flagged() {
    let direct_read = js_keys("this.setState({count: this.state.count + 1});\n");
    assert_eq!(count_key(&direct_read, "javascript:S6756"), 1);

    let updater = js_keys("this.setState((previous) => ({count: previous.count + 1}));\n");
    assert_eq!(count_key(&updater, "javascript:S6756"), 0);
}

#[test]
fn this_in_functional_components_is_flagged() {
    let flagged =
        jsx_keys("function Component() {\n  return <button onClick={() => this.save()}/>;\n}\n");
    assert_eq!(count_key(&flagged, "javascript:S6757"), 1);

    let class_method = js_keys("class Widget {\n  save() {\n    this.x();\n  }\n}\n");
    assert_eq!(count_key(&class_method, "javascript:S6757"), 0);
}

#[test]
fn collapsing_whitespace_between_inline_siblings_is_flagged() {
    let inline_gap = jsx_keys("const el = <div><span>a</span> <b>c</b></div>;\n");
    assert_eq!(count_key(&inline_gap, "javascript:S6772"), 1);

    let block_elements = jsx_keys("const el = <div><p>a</p> <p>b</p></div>;\n");
    assert_eq!(count_key(&block_elements, "javascript:S6772"), 0);
}

#[test]
fn props_without_prop_types_flagged_javascript_only() {
    let flagged = js_keys("class A {\n  m() {\n    return this.props.x;\n  }\n}\n");
    assert_eq!(count_key(&flagged, "javascript:S6774"), 1);

    let declared =
        js_keys("class A {\n  static propTypes = {};\n  m() {\n    return this.props.x;\n  }\n}\n");
    assert_eq!(count_key(&declared, "javascript:S6774"), 0);

    let typescript_report = ts("class A {\n  m() {\n    return this.props.x;\n  }\n}\n");
    assert_eq!(
        count_key(&report_keys(&typescript_report), "typescript:S6774"),
        0
    );
}

#[test]
fn default_props_require_matching_required_prop_types() {
    let missing_entry = js_keys(
        "C.propTypes = {a: PropTypes.string.isRequired};\nC.defaultProps = {a: 'x', b: 'y'};\n",
    );
    assert_eq!(count_key(&missing_entry, "javascript:S6775"), 1);

    let optional_entry =
        js_keys("C.propTypes = {a: PropTypes.string};\nC.defaultProps = {a: 'x'};\n");
    assert_eq!(count_key(&optional_entry, "javascript:S6775"), 1);

    let covered =
        js_keys("C.propTypes = {a: PropTypes.string.isRequired};\nC.defaultProps = {a: 'x'};\n");
    assert_eq!(count_key(&covered, "javascript:S6775"), 0);
}

#[test]
fn unknown_jsx_attributes_are_flagged() {
    let html_spelling = jsx_keys("const el = <div class=\"x\"/>;\n");
    assert_eq!(count_key(&html_spelling, "javascript:S6747"), 1);

    let unknown_name = jsx_keys("const el = <div foo=\"1\"/>;\n");
    assert_eq!(count_key(&unknown_name, "javascript:S6747"), 1);

    let known_names = jsx_keys(
        "const el = <div className=\"x\" tabIndex={0} data-x=\"1\" aria-hidden=\"true\" onClick={f}/>;\n",
    );
    assert_eq!(count_key(&known_names, "javascript:S6747"), 0);

    let rules = RuleOptions {
        jsx_attribute_whitelist: vec!["foo".to_string()],
        ..RuleOptions::default()
    };
    let whitelisted = keys_with_rules("<div foo=\"1\"/>\n", &rules);
    assert_eq!(count_key(&whitelisted, "javascript:S6747"), 0);

    let on_component = jsx_keys("const el = <Widget arbitraryProp=\"1\"/>;\n");
    assert_eq!(count_key(&on_component, "javascript:S6747"), 0);
}

// ===== Batch4 group A1 tests: JSX accessibility rules =====

#[test]
fn alt_text_is_required_on_replaced_elements() {
    let missing = jsx_keys("const el = <img src=\"a.png\"/>;\n");
    assert_eq!(count_key(&missing, "javascript:S1077"), 1);

    let present = jsx_keys("const el = <img src=\"a.png\" alt=\"Chart\"/>;\n");
    assert_eq!(count_key(&present, "javascript:S1077"), 0);

    let image_input = jsx_keys("const el = <input type=\"image\"/>;\n");
    assert_eq!(count_key(&image_input, "javascript:S1077"), 1);

    let text_input = jsx_keys("const el = <input type=\"text\"/>;\n");
    assert_eq!(count_key(&text_input, "javascript:S1077"), 0);

    let spread_props = jsx_keys("const el = <img {...props}/>;\n");
    assert_eq!(count_key(&spread_props, "javascript:S1077"), 0);
}

#[test]
fn mouse_handlers_need_focus_counterparts() {
    let alone = jsx_keys("const el = <div onMouseOver={hover}/>;\n");
    assert_eq!(count_key(&alone, "javascript:S1082"), 1);

    let paired = jsx_keys("const el = <div onMouseOver={hover} onFocus={focus}/>\n;\n");
    assert_eq!(count_key(&paired, "javascript:S1082"), 0);

    let out_blur = jsx_keys("const el = <div onMouseOut={leave} onBlur={blur}/>\n;\n");
    assert_eq!(count_key(&out_blur, "javascript:S1082"), 0);
}

#[test]
fn iframes_require_titles() {
    let bare = jsx_keys("const el = <iframe/>;\n");
    assert_eq!(count_key(&bare, "javascript:S1090"), 1);

    let titled = jsx_keys("const el = <iframe title=\"Map\"/>\n;\n");
    assert_eq!(count_key(&titled, "javascript:S1090"), 0);
}

#[test]
fn media_elements_need_caption_tracks() {
    let bare_video = jsx_keys("const el = <video src=\"a.mp4\"/>;\n");
    assert_eq!(count_key(&bare_video, "javascript:S4084"), 1);

    let captioned =
        jsx_keys("const el = <video src=\"a.mp4\"><track kind=\"captions\"/></video>;\n");
    assert_eq!(count_key(&captioned, "javascript:S4084"), 0);

    let bare_audio = jsx_keys("const el = <audio src=\"a.mp3\"/>;\n");
    assert_eq!(count_key(&bare_audio, "javascript:S4084"), 1);
}

#[test]
fn html_elements_need_valid_language_tags() {
    let missing = jsx_keys("const el = <html><body/></html>;\n");
    assert_eq!(count_key(&missing, "javascript:S5254"), 1);

    let valid_region = jsx_keys("const el = <html lang=\"de-DE\"><body/></html>;\n");
    assert_eq!(count_key(&valid_region, "javascript:S5254"), 0);

    let numeric_primary = jsx_keys("const el = <html lang=\"123\"><body/></html>;\n");
    assert_eq!(count_key(&numeric_primary, "javascript:S5254"), 1);

    let too_short = jsx_keys("const el = <html lang=\"e\"><body/></html>;\n");
    assert_eq!(count_key(&too_short, "javascript:S5254"), 1);
}

#[test]
fn tables_need_header_cells() {
    let headerless = jsx_keys("const el = <table><tr><td>x</td></tr></table>;\n");
    assert_eq!(count_key(&headerless, "javascript:S5256"), 1);

    let headed = jsx_keys("const el = <table><tr><th>x</th></tr></table>;\n");
    assert_eq!(count_key(&headed, "javascript:S5256"), 0);
}

#[test]
fn layout_tables_need_presentation_role() {
    let plain_layout = jsx_keys("const el = <table><tr><td>x</td></tr></table>;\n");
    assert_eq!(count_key(&plain_layout, "javascript:S5257"), 1);

    let captioned =
        jsx_keys("const el = <table><caption>t</caption><tr><td>x</td></tr></table>;\n");
    assert_eq!(count_key(&captioned, "javascript:S5257"), 0);

    let presentation =
        jsx_keys("const el = <table role=\"presentation\"><tr><td>x</td></tr></table>;\n");
    assert_eq!(count_key(&presentation, "javascript:S5257"), 0);
}

#[test]
fn header_references_must_match_th_ids() {
    let broken_reference = jsx_keys(
        "const el = <table><tr><th id=\"a\"/><td headers=\"a\"/></tr><tr><td headers=\"zzz\"/></tr></table>;\n",
    );
    assert_eq!(count_key(&broken_reference, "javascript:S5260"), 1);

    let valid_references =
        jsx_keys("const el = <table><tr><th id=\"a\"/><td headers=\"a\"/></tr></table>;\n");
    assert_eq!(count_key(&valid_references, "javascript:S5260"), 0);
}

#[test]
fn object_elements_need_text_alternatives() {
    let bare = jsx_keys("const el = <object data=\"x.swf\"/>;\n");
    assert_eq!(count_key(&bare, "javascript:S5264"), 1);

    let text_child = jsx_keys("const el = <object data=\"x.swf\">fallback</object>\n;\n");
    assert_eq!(count_key(&text_child, "javascript:S5264"), 0);

    let labeled = jsx_keys("const el = <object data=\"x.swf\" aria-label=\"movie\"/>\n;\n");
    assert_eq!(count_key(&labeled, "javascript:S5264"), 0);
}

#[test]
fn accesskeys_are_flagged_everywhere() {
    let flagged = jsx_keys("const el = <div accesskey=\"s\"/>;\n");
    assert_eq!(count_key(&flagged, "javascript:S6846"), 1);

    let clean = jsx_keys("const el = <div/>;\n");
    assert_eq!(count_key(&clean, "javascript:S6846"), 0);
}

#[test]
fn tab_indices_are_limited_to_zero_and_minus_one() {
    let positive = jsx_keys("const el = <div tabIndex={3}/>\n;\n");
    assert_eq!(count_key(&positive, "javascript:S6841"), 1);

    let removable = jsx_keys("const el = <div tabIndex={-1}/>\n;\n");
    assert_eq!(count_key(&removable, "javascript:S6841"), 0);

    let string_value = jsx_keys("const el = <div tabIndex=\"2\"/>\n;\n");
    assert_eq!(count_key(&string_value, "javascript:S6841"), 1);

    let dynamic = jsx_keys("let t = 0;\nconst el = <div tabIndex={t}/>\n;\n");
    assert_eq!(count_key(&dynamic, "javascript:S6841"), 0);
}
// ===== Batch4 group A2 tests: role and value accessibility rules =====

#[test]
fn headings_need_text_content_or_labels() {
    let bare = jsx_keys("const el = <h1/>;\n");
    assert_eq!(count_key(&bare, "javascript:S6850"), 1);

    let textual = jsx_keys("const el = <h2>Quarterly results</h2>;\n");
    assert_eq!(count_key(&textual, "javascript:S6850"), 0);

    let aria_labeled = jsx_keys("const el = <h3 aria-label=\"Summary\"/>;\n");
    assert_eq!(count_key(&aria_labeled, "javascript:S6850"), 0);

    let titled = jsx_keys("const el = <h4 title=\"Status\"/>;\n");
    assert_eq!(count_key(&titled, "javascript:S6850"), 0);

    let nested_text = jsx_keys("const el = <h5><span>Total</span></h5>;\n");
    assert_eq!(count_key(&nested_text, "javascript:S6850"), 0);

    let not_heading = jsx_keys("const el = <p>text</p>;\n");
    assert_eq!(count_key(&not_heading, "javascript:S6850"), 0);
}

#[test]
fn redundant_alt_texts_are_flagged() {
    let filler_word = jsx_keys("const el = <img src=\"report.pdf\" alt=\"Image\"/>;\n");
    assert_eq!(count_key(&filler_word, "javascript:S6851"), 1);

    let file_name = jsx_keys("const el = <img src=\"chart.png\" alt=\"Chart\"/>;\n");
    assert_eq!(count_key(&file_name, "javascript:S6851"), 1);

    let trimmed_and_cased = jsx_keys("const el = <img src=\"LOGO.png\" alt=\"  Logo \"/>;\n");
    assert_eq!(count_key(&trimmed_and_cased, "javascript:S6851"), 1);

    let descriptive = jsx_keys("const el = <img src=\"chart.png\" alt=\"Sales by region\"/>;\n");
    assert_eq!(count_key(&descriptive, "javascript:S6851"), 0);

    let different_stem = jsx_keys("const el = <img src=\"team.jpg\" alt=\"Office\"/>;\n");
    assert_eq!(count_key(&different_stem, "javascript:S6851"), 0);
}

#[test]
fn anchors_need_href_or_accessible_text() {
    let bare_anchor = jsx_keys("const el = <a/>;\n");
    assert_eq!(count_key(&bare_anchor, "javascript:S6827"), 1);

    let linked = jsx_keys("const el = <a href=\"/docs\"/>;\n");
    assert_eq!(count_key(&linked, "javascript:S6827"), 0);

    let unlabeled_named = jsx_keys("const el = <a aria-label=\"Open docs\"/>;\n");
    assert_eq!(count_key(&unlabeled_named, "javascript:S6827"), 1);

    let textual = jsx_keys("const el = <a>Documentation</a>;\n");
    assert_eq!(count_key(&textual, "javascript:S6827"), 0);

    let other_tag = jsx_keys("const el = <span/>;\n");
    assert_eq!(count_key(&other_tag, "javascript:S6827"), 0);
}

#[test]
fn duplicate_implicit_roles_are_flagged() {
    let list_role = jsx_keys("const el = <ul role=\"list\"><li>Item</li></ul>;\n");
    assert_eq!(count_key(&list_role, "javascript:S6822"), 1);
    assert_eq!(count_key(&list_role, "javascript:S6819"), 1);

    let nav_role = jsx_keys("const el = <nav role=\"navigation\"/>;\n");
    assert_eq!(count_key(&nav_role, "javascript:S6822"), 1);
    assert_eq!(count_key(&nav_role, "javascript:S6819"), 1);

    let changed_role = jsx_keys("const el = <ul role=\"toolbar\"><li>Item</li></ul>;\n");
    assert_eq!(count_key(&changed_role, "javascript:S6822"), 0);
    assert_eq!(count_key(&changed_role, "javascript:S6819"), 0);

    let plain_list = jsx_keys("const el = <ul><li>Item</li></ul>;\n");
    assert_eq!(count_key(&plain_list, "javascript:S6822"), 0);
    assert_eq!(count_key(&plain_list, "javascript:S6819"), 0);
}

#[test]
fn abstract_roles_are_flagged() {
    let select_role = jsx_keys("const el = <div role=\"select\"/>;\n");
    assert_eq!(count_key(&select_role, "javascript:S6821"), 1);

    let composite_role = jsx_keys("const el = <div role=\"composite\"/>;\n");
    assert_eq!(count_key(&composite_role, "javascript:S6821"), 1);

    let concrete_role = jsx_keys("const el = <div role=\"note\"/>;\n");
    assert_eq!(count_key(&concrete_role, "javascript:S6821"), 0);
}
#[test]
fn aria_values_are_validated_against_tables() {
    let bad_boolean = jsx_keys("const el = <div aria-hidden=\"yes\"/>;\n");
    assert_eq!(count_key(&bad_boolean, "javascript:S6793"), 1);

    let good_boolean = jsx_keys("const el = <div aria-hidden=\"true\"/>;\n");
    assert_eq!(count_key(&good_boolean, "javascript:S6793"), 0);

    let bad_token = jsx_keys("const el = <div aria-live=\"fast\"/>;\n");
    assert_eq!(count_key(&bad_token, "javascript:S6793"), 1);

    let good_token = jsx_keys("const el = <div aria-live=\"polite\"/>;\n");
    assert_eq!(count_key(&good_token, "javascript:S6793"), 0);

    let bad_numeric = jsx_keys("const el = <div aria-level=\"two\"/>;\n");
    assert_eq!(count_key(&bad_numeric, "javascript:S6793"), 1);

    let good_numeric = jsx_keys("const el = <div aria-level=\"2\"/>;\n");
    assert_eq!(count_key(&good_numeric, "javascript:S6793"), 0);

    let dynamic_value = jsx_keys("let mode = 'polite';\nconst el = <div aria-live={mode}/>;\n");
    assert_eq!(count_key(&dynamic_value, "javascript:S6793"), 0);
}

#[test]
fn list_roles_require_owned_listitems() {
    let bare = jsx_keys("const el = <div role=\"list\"/>;\n");
    assert_eq!(count_key(&bare, "javascript:S6807"), 1);

    let implicit_owned = jsx_keys("const el = <div role=\"list\"><li>Item</li></div>;\n");
    assert_eq!(count_key(&implicit_owned, "javascript:S6807"), 0);

    let explicit_owned =
        jsx_keys("const el = <div role=\"list\"><div role=\"listitem\">Item</div></div>;\n");
    assert_eq!(count_key(&explicit_owned, "javascript:S6807"), 0);
}

#[test]
fn unsupported_aria_properties_are_flagged_per_role() {
    let unsupported = jsx_keys("const el = <div role=\"heading\" aria-selected=\"true\"/>;\n");
    assert_eq!(count_key(&unsupported, "javascript:S6811"), 1);

    let supported = jsx_keys("const el = <div role=\"heading\" aria-level=\"2\"/>;\n");
    assert_eq!(count_key(&supported, "javascript:S6811"), 0);

    let global_property = jsx_keys("const el = <div role=\"heading\" aria-hidden=\"true\"/>;\n");
    assert_eq!(count_key(&global_property, "javascript:S6811"), 0);
}

#[test]
fn activedescendant_requires_tab_index() {
    let missing = jsx_keys("const el = <div aria-activedescendant=\"opt-1\"/>;\n");
    assert_eq!(count_key(&missing, "javascript:S6823"), 1);

    let camel_case = jsx_keys("const el = <div aria-activedescendant=\"opt-1\" tabIndex={0}/>;\n");
    assert_eq!(count_key(&camel_case, "javascript:S6823"), 0);

    let lower_case =
        jsx_keys("const el = <div aria-activedescendant=\"opt-1\" tabindex=\"0\"/>;\n");
    assert_eq!(count_key(&lower_case, "javascript:S6823"), 0);

    let spread_props = jsx_keys("const el = <div {...rest} aria-activedescendant=\"opt-1\"/>;\n");
    assert_eq!(count_key(&spread_props, "javascript:S6823"), 0);
}
// ===== Batch4 group A3 tests: interaction-matrix accessibility rules =====

#[test]
fn roles_must_be_allowed_on_their_elements() {
    let heading_role = jsx_keys("const el = <h1 role=\"button\">Title</h1>;\n");
    assert_eq!(count_key(&heading_role, "javascript:S6824"), 1);

    let cell_role = jsx_keys("const el = <td role=\"link\">x</td>;\n");
    assert_eq!(count_key(&cell_role, "javascript:S6824"), 1);

    let allowed_cell = jsx_keys("const el = <td role=\"cell\">x</td>;\n");
    assert_eq!(count_key(&allowed_cell, "javascript:S6824"), 0);

    let unrestricted_tag = jsx_keys("const el = <div role=\"button\"/>;\n");
    assert_eq!(count_key(&unrestricted_tag, "javascript:S6824"), 0);

    let list_toolbar = jsx_keys("const el = <ul role=\"toolbar\"><li>x</li></ul>;\n");
    assert_eq!(count_key(&list_toolbar, "javascript:S6824"), 0);
}

#[test]
fn aria_hidden_must_not_hide_focusable_elements() {
    let hidden_button = jsx_keys("const el = <button aria-hidden=\"true\">Go</button>;\n");
    assert_eq!(count_key(&hidden_button, "javascript:S6825"), 1);

    let hidden_tabbable = jsx_keys("const el = <div aria-hidden=\"true\" tabIndex={0}/>;\n");
    assert_eq!(count_key(&hidden_tabbable, "javascript:S6825"), 1);

    let hidden_static = jsx_keys("const el = <div aria-hidden=\"true\">text</div>;\n");
    assert_eq!(count_key(&hidden_static, "javascript:S6825"), 0);

    let negative_index = jsx_keys("const el = <div aria-hidden=\"true\" tabIndex={-1}/>;\n");
    assert_eq!(count_key(&negative_index, "javascript:S6825"), 0);

    let visible_button = jsx_keys("const el = <button>Go</button>;\n");
    assert_eq!(count_key(&visible_button, "javascript:S6825"), 0);
}

#[test]
fn autocomplete_values_must_match_input_types() {
    let mismatched_scope = jsx_keys("const el = <input type=\"text\" autoComplete=\"email\"/>;\n");
    assert_eq!(count_key(&mismatched_scope, "javascript:S6840"), 1);

    let unknown_token = jsx_keys("const el = <input type=\"text\" autoComplete=\"banana\"/>;\n");
    assert_eq!(count_key(&unknown_token, "javascript:S6840"), 1);

    let matching_scope = jsx_keys("const el = <input type=\"email\" autoComplete=\"email\"/>;\n");
    assert_eq!(count_key(&matching_scope, "javascript:S6840"), 0);

    let general_token = jsx_keys("const el = <input autoComplete=\"on\"/>;\n");
    assert_eq!(count_key(&general_token, "javascript:S6840"), 0);

    let select_field = jsx_keys("const el = <select autoComplete=\"postal-code\"/>;\n");
    assert_eq!(count_key(&select_field, "javascript:S6840"), 0);

    let textarea_field = jsx_keys("const el = <textarea autoComplete=\"street-address\"/>;\n");
    assert_eq!(count_key(&textarea_field, "javascript:S6840"), 0);

    let other_tag = jsx_keys("const el = <div autoComplete=\"banana\"/>;\n");
    assert_eq!(count_key(&other_tag, "javascript:S6840"), 0);
}
#[test]
fn noninteractive_elements_reject_interactive_roles() {
    let div_button = jsx_keys("const el = <div role=\"button\" tabIndex={0}>OK</div>;\n");
    assert_eq!(count_key(&div_button, "javascript:S6842"), 1);

    let span_link = jsx_keys("const el = <span role=\"link\">x</span>;\n");
    assert_eq!(count_key(&span_link, "javascript:S6842"), 1);

    let native_button = jsx_keys("const el = <button>OK</button>;\n");
    assert_eq!(count_key(&native_button, "javascript:S6842"), 0);

    let structural_div = jsx_keys("const el = <div role=\"note\">x</div>;\n");
    assert_eq!(count_key(&structural_div, "javascript:S6842"), 0);
}

#[test]
fn interactive_elements_reject_structural_roles() {
    let button_list = jsx_keys("const el = <button role=\"list\">x</button>;\n");
    assert_eq!(count_key(&button_list, "javascript:S6843"), 1);

    let link_article = jsx_keys("const el = <a href=\"/docs\" role=\"article\">x</a>;\n");
    assert_eq!(count_key(&link_article, "javascript:S6843"), 1);

    let matching_button = jsx_keys("const el = <button role=\"checkbox\"/>;\n");
    assert_eq!(count_key(&matching_button, "javascript:S6843"), 0);

    let plain_button = jsx_keys("const el = <button/>;\n");
    assert_eq!(count_key(&plain_button, "javascript:S6843"), 0);
}

#[test]
fn interactive_roles_require_focusable_elements() {
    let unfocusable = jsx_keys("const el = <div role=\"button\"/>;\n");
    assert_eq!(count_key(&unfocusable, "javascript:S6852"), 1);

    let tabbable = jsx_keys("const el = <div role=\"button\" tabIndex={0}/>;\n");
    assert_eq!(count_key(&tabbable, "javascript:S6852"), 0);

    let negative_index = jsx_keys("const el = <div role=\"button\" tabIndex={-1}/>;\n");
    assert_eq!(count_key(&negative_index, "javascript:S6852"), 0);

    let native_control = jsx_keys("const el = <button/>;\n");
    assert_eq!(count_key(&native_control, "javascript:S6852"), 0);

    let anchor = jsx_keys("const el = <a href=\"/docs\">docs</a>;\n");
    assert_eq!(count_key(&anchor, "javascript:S6852"), 0);
}
#[test]
fn anchor_clicks_require_href_or_buttons() {
    let click_only = jsx_keys("const el = <a onClick={openMenu}>Menu</a>;\n");
    assert_eq!(count_key(&click_only, "javascript:S6844"), 1);

    let with_href = jsx_keys("const el = <a href=\"/menu\" onClick={openMenu}>Menu</a>;\n");
    assert_eq!(count_key(&with_href, "javascript:S6844"), 0);

    let plain_anchor = jsx_keys("const el = <a href=\"/docs\">docs</a>;\n");
    assert_eq!(count_key(&plain_anchor, "javascript:S6844"), 0);

    let button_click = jsx_keys("const el = <button onClick={openMenu}>Menu</button>;\n");
    assert_eq!(count_key(&button_click, "javascript:S6844"), 0);
}

#[test]
fn positive_tab_indices_need_interactive_elements() {
    let static_div = jsx_keys("const el = <div tabIndex={0}/>;\n");
    assert_eq!(count_key(&static_div, "javascript:S6845"), 1);

    let interactive_button = jsx_keys("const el = <button tabIndex={0}/>;\n");
    assert_eq!(count_key(&interactive_button, "javascript:S6845"), 0);

    let programmatic = jsx_keys("const el = <div tabIndex={-1}/>;\n");
    assert_eq!(count_key(&programmatic, "javascript:S6845"), 0);

    let interactive_role = jsx_keys("const el = <div role=\"button\" tabIndex={0}/>;\n");
    assert_eq!(count_key(&interactive_role, "javascript:S6845"), 0);

    let listbox_container =
        jsx_keys("const el = <div role=\"listbox\" aria-activedescendant=\"o1\" tabIndex={0}/>;\n");
    assert_eq!(count_key(&listbox_container, "javascript:S6845"), 0);
}

#[test]
fn interaction_handlers_belong_on_interactive_elements() {
    let div_click = jsx_keys("const el = <div onClick={f}/>;\n");
    assert_eq!(count_key(&div_click, "javascript:S6847"), 1);

    let div_change = jsx_keys("const el = <div onChange={f}/>;\n");
    assert_eq!(count_key(&div_change, "javascript:S6847"), 1);

    let two_handlers = jsx_keys("const el = <div onClick={f} onMouseDown={g}/>;\n");
    assert_eq!(count_key(&two_handlers, "javascript:S6847"), 2);

    let button_click = jsx_keys("const el = <button onClick={f}/>;\n");
    assert_eq!(count_key(&button_click, "javascript:S6847"), 0);

    let role_button = jsx_keys("const el = <div role=\"button\" onClick={f}/>;\n");
    assert_eq!(count_key(&role_button, "javascript:S6847"), 0);
}

#[test]
fn click_handlers_need_keyboard_counterparts() {
    let click_only = jsx_keys("const el = <div onClick={f}/>;\n");
    assert_eq!(count_key(&click_only, "javascript:S6848"), 1);

    let with_key = jsx_keys("const el = <div onClick={f} onKeyDown={k}/>;\n");
    assert_eq!(count_key(&with_key, "javascript:S6848"), 0);

    let interactive_button = jsx_keys("const el = <button onClick={f}/>;\n");
    assert_eq!(count_key(&interactive_button, "javascript:S6848"), 0);
}

#[test]
fn labels_need_text_and_control_association() {
    let orphan_label = jsx_keys("const el = <label>Surname</label>;\n");
    assert_eq!(count_key(&orphan_label, "javascript:S6853"), 1);

    let empty_label = jsx_keys("const el = <label htmlFor=\"q\"/>;\n");
    assert_eq!(count_key(&empty_label, "javascript:S6853"), 1);

    let bare_label = jsx_keys("const el = <label/>;\n");
    assert_eq!(count_key(&bare_label, "javascript:S6853"), 1);

    let for_attribute = jsx_keys("const el = <label htmlFor=\"q\">Query</label>;\n");
    assert_eq!(count_key(&for_attribute, "javascript:S6853"), 0);

    let nested_control = jsx_keys("const el = <label>Name<input/></label>;\n");
    assert_eq!(count_key(&nested_control, "javascript:S6853"), 0);
}

#[test]
fn computed_enum_members_are_flagged() {
    let violating = ts_keys("enum E { A = getValue(), B = 1 }\n");
    assert_eq!(count_key(&violating, "typescript:S6550"), 1);

    let clean = ts_keys("enum E { A = 1, B = -2, C = 'x', D }\n");
    assert_eq!(count_key(&clean, "typescript:S6550"), 0);
}

#[test]
fn enums_mixing_initialized_members_are_flagged() {
    let mixed = ts_keys("enum E { A = 1, B, C = 3 }\n");
    assert_eq!(count_key(&mixed, "typescript:S6572"), 1);

    let uniform_initialized = ts_keys("enum E { A = 1, B = 2 }\n");
    assert_eq!(count_key(&uniform_initialized, "typescript:S6572"), 0);

    let uniform_implicit = ts_keys("enum E { A, B }\n");
    assert_eq!(count_key(&uniform_implicit, "typescript:S6572"), 0);
}

#[test]
fn duplicate_enum_values_are_flagged() {
    let duplicates = ts_keys("enum E { A = 1, B = 1, C = 'x', D = 'x' }\n");
    assert_eq!(count_key(&duplicates, "typescript:S6578"), 2);

    let unique = ts_keys("enum E { A = 1, B = 2, C = 'x' }\n");
    assert_eq!(count_key(&unique, "typescript:S6578"), 0);
}

#[test]
fn enums_mixing_value_kinds_are_flagged() {
    let mixed = ts_keys("enum E { A = 1, B = 'x' }\n");
    assert_eq!(count_key(&mixed, "typescript:S6583"), 1);

    let numeric_only = ts_keys("enum E { A = 1, B = 2 }\n");
    assert_eq!(count_key(&numeric_only, "typescript:S6583"), 0);

    let text_only = ts_keys("enum E { A = 'x', B = 'y' }\n");
    assert_eq!(count_key(&text_only, "typescript:S6583"), 0);
}

#[test]
fn redundant_union_and_intersection_members_are_flagged() {
    let keywords = ts_keys("type T = string | number | string;\n");
    assert_eq!(count_key(&keywords, "typescript:S6571"), 1);

    let subsumed = ts_keys("type T = string | 'literal';\n");
    assert_eq!(count_key(&subsumed, "typescript:S6571"), 1);

    let clean = ts_keys("type T = string | number;\n");
    assert_eq!(count_key(&clean, "typescript:S6571"), 0);
}

#[test]
fn structurally_equal_type_members_are_flagged() {
    let duplicate_objects = ts_keys("type T = { a: string } | { a: string };\n");
    assert_eq!(count_key(&duplicate_objects, "typescript:S4621"), 1);

    let distinct_objects = ts_keys("type T = { a: string } | { b: string };\n");
    assert_eq!(count_key(&distinct_objects, "typescript:S4621"), 0);
}

#[test]
fn oversized_unions_are_flagged() {
    let oversized = ts_keys("type T = 'a' | 'b' | 'c' | 'd';\n");
    assert_eq!(count_key(&oversized, "typescript:S4622"), 1);

    let compact = ts_keys("type T = 'a' | 'b' | 'c';\n");
    assert_eq!(count_key(&compact, "typescript:S4622"), 0);
}

#[test]
fn meaningless_intersections_are_flagged() {
    let meaningless = ts_keys("type T = string & { a: number };\n");
    assert_eq!(count_key(&meaningless, "typescript:S4335"), 1);

    let branded = ts_keys("type Brand = { brand: 'id' };\ntype Tagged = Brand & { v: number };\n");
    assert_eq!(count_key(&branded, "typescript:S4335"), 0);
}

#[test]
fn alias_to_bare_reference_is_flagged() {
    let alias_chain = ts_keys("type A = { x: number };\ntype B = A;\n");
    assert_eq!(count_key(&alias_chain, "typescript:S6564"), 1);

    let concrete = ts_keys("type B = { x: number };\n");
    assert_eq!(count_key(&concrete, "typescript:S6564"), 0);

    let generic_reference = ts_keys("type Mapping = Record<string, number>;\n");
    assert_eq!(count_key(&generic_reference, "typescript:S6564"), 0);
}

#[test]
fn useless_generic_constraints_are_flagged() {
    let constrained = ts_keys("function f<T extends unknown>(x: T) { return x; }\n");
    assert_eq!(count_key(&constrained, "typescript:S6569"), 1);

    let unconstrained = ts_keys("function f<T>(x: T) { return x; }\n");
    assert_eq!(count_key(&unconstrained, "typescript:S6569"), 0);

    let meaningful = ts_keys("function f<T extends { id: number }>(x: T) { return x; }\n");
    assert_eq!(count_key(&meaningful, "typescript:S6569"), 0);
}

#[test]
fn typescript_only_type_rules_never_fire_for_javascript() {
    let findings = js_keys("type T = string | number | string;\nenum E { A = 1, B = 1 }\n");
    for key in ["javascript:S6550", "javascript:S6571", "javascript:S6578"] {
        assert_eq!(count_key(&findings, key), 0, "{key}");
    }
}

#[test]
fn non_null_assertions_are_flagged() {
    let violating = ts_keys("const x = value!;\n");
    assert_eq!(count_key(&violating, "typescript:S2966"), 1);

    let clean = ts_keys("const x = value;\n");
    assert_eq!(count_key(&clean, "typescript:S2966"), 0);
}

#[test]
fn primitive_annotations_with_initializers_are_flagged() {
    let violating = ts_keys("const X: number = 1;\nlet y: string = 'a';\n");
    assert_eq!(count_key(&violating, "typescript:S3257"), 2);

    let without_initializer = ts_keys("let y: string;\n");
    assert_eq!(count_key(&without_initializer, "typescript:S3257"), 0);

    let non_primitive = ts_keys("const P: Point = { x: 1, y: 2 };\n");
    assert_eq!(count_key(&non_primitive, "typescript:S3257"), 0);
}

#[test]
fn angle_bracket_assertions_are_flagged() {
    let violating = ts_keys("const x = <string>value;\n");
    assert_eq!(count_key(&violating, "typescript:S4137"), 1);

    let clean = ts_keys("const x = value as string;\n");
    assert_eq!(count_key(&clean, "typescript:S4137"), 0);
}

#[test]
fn module_keyword_is_flagged_over_namespace() {
    let violating = ts_keys("module Legacy { export const x = 1; }\n");
    assert_eq!(count_key(&violating, "typescript:S4156"), 1);

    let clean = ts_keys("namespace Modern { export const x = 1; }\n");
    assert_eq!(count_key(&clean, "typescript:S4156"), 0);
}

#[test]
fn redundant_type_parameter_defaults_are_flagged() {
    let violating = ts_keys("function f<T extends string = string>(x: T) { return x; }\n");
    assert_eq!(count_key(&violating, "typescript:S4157"), 1);

    let distinct_default =
        ts_keys("function f<T extends object = { id: number }>(x: T) { return x; }\n");
    assert_eq!(count_key(&distinct_default, "typescript:S4157"), 0);
}

#[test]
fn any_keywords_are_flagged() {
    let violating = ts_keys("let loose: any;\nfunction f(x: any) { return x; }\n");
    assert_eq!(count_key(&violating, "typescript:S4204"), 2);

    let clean = ts_keys("let tight: string;\n");
    assert_eq!(count_key(&clean, "typescript:S4204"), 0);
}

#[test]
fn optional_properties_with_undefined_in_union_are_flagged() {
    let violating = ts_keys("interface P { name?: string | undefined; }\n");
    assert_eq!(count_key(&violating, "typescript:S4782"), 1);

    let required_property = ts_keys("interface P { name: string | undefined; }\n");
    assert_eq!(count_key(&required_property, "typescript:S4782"), 0);

    let optional_without_undefined = ts_keys("interface P { name?: string; }\n");
    assert_eq!(
        count_key(&optional_without_undefined, "typescript:S4782"),
        0
    );
}

#[test]
fn optional_booleans_without_defaults_are_flagged() {
    let violating = ts_keys("function f(verbose?: boolean) { return verbose; }\n");
    assert_eq!(count_key(&violating, "typescript:S4798"), 1);

    let with_default = ts_keys("function f(verbose: boolean = false) { return verbose; }\n");
    assert_eq!(count_key(&with_default, "typescript:S4798"), 0);

    let optional_string = ts_keys("function f(label?: string) { return label; }\n");
    assert_eq!(count_key(&optional_string, "typescript:S4798"), 0);
}

#[test]
fn single_call_signatures_become_function_types() {
    let interface_form = ts_keys("interface Handler { (event: string): void; }\n");
    assert_eq!(count_key(&interface_form, "typescript:S6598"), 1);

    let alias_form = ts_keys("type Handler = { (event: string): void };\n");
    assert_eq!(count_key(&alias_form, "typescript:S6598"), 1);

    let multi_member = ts_keys("interface Handler { (event: string): void; done: boolean; }\n");
    assert_eq!(count_key(&multi_member, "typescript:S6598"), 0);
}

#[test]
fn separated_overloads_are_flagged() {
    let separated = ts_keys(
        "interface Api {\n  load(): void;\n  ready: boolean;\n  load(url: string): void;\n}\n",
    );
    assert_eq!(count_key(&separated, "typescript:S4136"), 1);

    let grouped = ts_keys(
        "interface Api {\n  load(): void;\n  load(url: string): void;\n  ready: boolean;\n}\n",
    );
    assert_eq!(count_key(&grouped, "typescript:S4136"), 0);
}

#[test]
fn typescript_node_rules_never_fire_for_javascript() {
    let findings = js_keys("const x = <string>value;\nmodule M { }\nlet loose: any;\n");
    for key in ["javascript:S4137", "javascript:S4156", "javascript:S4204"] {
        assert_eq!(count_key(&findings, key), 0, "{key}");
    }
}

#[test]
fn boolean_returns_suggest_type_predicates() {
    let violating = ts_keys("function isFoo(x: Foo): boolean { return true; }\n");
    assert_eq!(count_key(&violating, "typescript:S4322"), 1);

    let clean = ts_keys("function score(x: number): boolean { return x > 0; }\n");
    assert_eq!(count_key(&clean, "typescript:S4322"), 0);
}

#[test]
fn wrapper_return_types_are_flagged() {
    let violating = ts_keys("function f(): Number { return 1; }\n");
    assert_eq!(count_key(&violating, "typescript:S4324"), 1);

    let clean = ts_keys("function f(): number { return 1; }\n");
    assert_eq!(count_key(&clean, "typescript:S4324"), 0);
}

#[test]
fn class_typed_returns_prefer_this() {
    let violating = ts_keys("class Builder {\n  self(): Builder { return this; }\n}\n");
    assert_eq!(count_key(&violating, "typescript:S6565"), 1);

    let clean = ts_keys("class Builder {\n  build(): this { return this; }\n}\n");
    assert_eq!(count_key(&clean, "typescript:S6565"), 0);
}

#[test]
fn non_null_after_guards_are_flagged() {
    let violating = ts_keys("const x = a ?? b!;\n");
    assert_eq!(count_key(&violating, "typescript:S6568"), 1);

    let clean = ts_keys("const x = a.b!;\n");
    assert_eq!(count_key(&clean, "typescript:S6568"), 0);
}

#[test]
fn readonly_annotations_suggest_as_const() {
    let violating = ts_keys("const COLORS: readonly string[] = ['a', 'b'];\n");
    assert_eq!(count_key(&violating, "typescript:S6590"), 1);

    let clean = ts_keys("const MUTABLE: string[] = ['a', 'b'];\n");
    assert_eq!(count_key(&clean, "typescript:S6590"), 0);
}

#[test]
fn props_interfaces_require_readonly_fields() {
    let violating = ts_keys("interface ButtonProps { label: string; size: number; }\n");
    assert_eq!(count_key(&violating, "typescript:S6759"), 2);

    let readonly = ts_keys("interface ButtonProps { readonly label: string; }\n");
    assert_eq!(count_key(&readonly, "typescript:S6759"), 0);

    let not_props = ts_keys("interface Config { label: string; }\n");
    assert_eq!(count_key(&not_props, "typescript:S6759"), 0);
}

#[test]
fn static_properties_need_readonly_or_be_excluded() {
    let violating = ts_keys("class Registry { static instance = new Registry(); }\n");
    assert_eq!(count_key(&violating, "typescript:S1444"), 1);

    let readonly = ts_keys("class Registry { static readonly kind = 'reg'; }\n");
    assert_eq!(count_key(&readonly, "typescript:S1444"), 0);

    let private = ts_keys("class Registry { private static secret = 1; }\n");
    assert_eq!(count_key(&private, "typescript:S1444"), 0);
}

#[test]
fn constructor_async_work_is_flagged() {
    let awaiting = ts_keys(
        "class Server {\n  constructor() {\n    const data = load();\n    void data;\n  }\n}\nasync function load() { return 1; }\n",
    );
    assert_eq!(count_key(&awaiting, "typescript:S7059"), 0);

    let direct = ts_keys(
        "class Server {\n  async load() {}\n  constructor() {\n    const p = (async () => 1)();\n    void p;\n  }\n}\n",
    );
    assert_eq!(count_key(&direct, "typescript:S7059"), 1);
}

#[test]
fn nested_awaits_are_flagged_for_both_languages() {
    let typescript_findings =
        ts_keys("async function f(p: Promise<number>) { return await await p; }\n");
    assert_eq!(count_key(&typescript_findings, "typescript:S4326"), 1);

    let javascript_findings = js_keys("async function f(p) { return await await p; }\n");
    assert_eq!(count_key(&javascript_findings, "javascript:S4326"), 1);
}
// ---- Batch-5 security-hotspot fixtures ----

#[test]
fn weak_hash_algorithms_are_flagged() {
    let findings = js_keys("const hash = crypto.createHash('md5');\n");
    assert_eq!(count_key(&findings, "javascript:S2612"), 1);
    assert_eq!(count_key(&findings, "javascript:S4790"), 1);

    let strong = js_keys("const hash = crypto.createHash('sha256');\n");
    assert_eq!(count_key(&strong, "javascript:S2612"), 0);
    assert_eq!(count_key(&strong, "javascript:S4790"), 0);

    let family = js_keys("const h = crypto.createHash('ripemd160');\n");
    assert_eq!(count_key(&family, "javascript:S2612"), 0);
    assert_eq!(count_key(&family, "javascript:S4790"), 0);
}

#[test]
fn encryption_api_usage_is_a_hotspot() {
    let violating = js_keys("const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);\n");
    assert_eq!(count_key(&violating, "javascript:S4787"), 1);

    let clean = js_keys("const digest = crypto.createHash('sha256');\n");
    assert_eq!(count_key(&clean, "javascript:S4787"), 0);
}

#[test]
fn weak_tls_protocol_versions_are_flagged() {
    let findings = js_keys("const version = 'TLSv1';\n");
    assert_eq!(count_key(&findings, "javascript:S4423"), 1);

    let clean = js_keys("const version = 'TLSv1.2';\n");
    assert_eq!(count_key(&clean, "javascript:S4423"), 0);
}

#[test]
fn weak_key_generation_parameters_are_flagged() {
    let curve = js_keys("const dh = crypto.createECDH('secp112r1');\n");
    assert_eq!(count_key(&curve, "javascript:S4426"), 1);

    let modulus = js_keys("crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });\n");
    assert_eq!(count_key(&modulus, "javascript:S4426"), 1);

    let strong = js_keys("const dh = crypto.createECDH('secp256k1');\n");
    assert_eq!(count_key(&strong, "javascript:S4426"), 0);
}

#[test]
fn ecb_mode_and_missing_iv_are_flagged() {
    let ecb = js_keys("crypto.createCipheriv('aes-128-ecb', key, iv);\n");
    assert_eq!(count_key(&ecb, "javascript:S5542"), 1);

    let no_iv = js_keys("crypto.createCipheriv('aes-128-cbc', key, null);\n");
    assert_eq!(count_key(&no_iv, "javascript:S5542"), 1);

    let clean = js_keys("crypto.createCipheriv('aes-128-cbc', key, iv);\n");
    assert_eq!(count_key(&clean, "javascript:S5542"), 0);
}

#[test]
fn broken_cipher_families_are_flagged() {
    let violating = js_keys("crypto.createCipheriv('des-cbc', key, iv);\n");
    assert_eq!(count_key(&violating, "javascript:S5547"), 1);

    let clean = js_keys("crypto.createCipheriv('aes-128-cbc', key, iv);\n");
    assert_eq!(count_key(&clean, "javascript:S5547"), 0);
}

#[test]
fn shell_interpreters_and_path_lookup_are_flagged() {
    let exec = js_keys("const { exec } = require('child_process');\nexec('ls -la');\n");
    assert_eq!(count_key(&exec, "javascript:S4721"), 1);
    assert_eq!(count_key(&exec, "javascript:S4036"), 1);

    let absolute = js_keys("require('child_process').spawn('/bin/ls', ['-la']);\n");
    assert_eq!(count_key(&absolute, "javascript:S4036"), 0);
    assert_eq!(count_key(&absolute, "javascript:S4721"), 0);
}

#[test]
fn math_random_is_a_hotspot() {
    let findings = js_keys("const token = Math.random();\n");
    assert_eq!(count_key(&findings, "javascript:S2245"), 1);

    let clean: &str = "function random(min, max) { return min + max; }\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S2245"), 0);
}

#[test]
fn weak_jwt_algorithms_are_flagged() {
    let literal = js_keys("jwt.sign(payload, secret, 'none');\n");
    assert_eq!(count_key(&literal, "javascript:S5659"), 1);

    let option = js_keys("jwt.verify(token, key, { algorithm: 'none' });\n");
    assert_eq!(count_key(&option, "javascript:S5659"), 1);

    let clean = js_keys("jwt.sign(payload, secret, { algorithm: 'rs256' });\n");
    assert_eq!(count_key(&clean, "javascript:S5659"), 0);
}

#[test]
fn angular_sanitizer_bypasses_are_flagged() {
    let findings = js_keys("this.sanitizer.bypassSecurityTrustHtml(value);\n");
    assert_eq!(count_key(&findings, "javascript:S6268"), 1);

    let clean = js_keys("this.sanitizer.sanitize(value);\n");
    assert_eq!(count_key(&clean, "javascript:S6268"), 0);
}

#[test]
fn message_handlers_without_origin_check_are_flagged() {
    let findings =
        js_keys("window.addEventListener('message', (event) => {\n  handle(event.data);\n});\n");
    assert_eq!(count_key(&findings, "javascript:S2819"), 1);

    let checked = js_keys(
        "window.onmessage = (event) => {\n  if (event.origin !== 'https://a') return;\n  handle(event.data);\n};\n",
    );
    assert_eq!(count_key(&checked, "javascript:S2819"), 0);
}

#[test]
fn window_open_features_require_noopener() {
    let violating = js_keys("window.open(url, '_blank', 'width=200');\n");
    assert_eq!(count_key(&violating, "javascript:S5148"), 1);

    let clean = js_keys("window.open(url, '_blank', 'noopener');\n");
    assert_eq!(count_key(&clean, "javascript:S5148"), 0);
}

#[test]
fn sensitive_console_logging_is_flagged() {
    let findings = js_keys("console.log('password', password);\n");
    assert_eq!(count_key(&findings, "javascript:S5757"), 1);

    let clean: &str = "console.log('user loaded', user);\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S5757"), 0);
}

#[test]
fn forwarded_header_trust_is_a_hotspot() {
    let findings = js_keys("const ip = req.headers['x-forwarded-for'];\n");
    assert_eq!(count_key(&findings, "javascript:S5759"), 1);

    let clean: &str = "const agent = req.headers['user-agent'];\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S5759"), 0);
}

#[test]
fn sensitive_permission_access_is_flagged() {
    let findings = js_keys("const where = navigator.geolocation;\n");
    assert_eq!(count_key(&findings, "javascript:S5604"), 1);

    let clean: &str = "const storage = navigator.storage;\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S5604"), 0);
}

#[test]
fn unconditional_error_middleware_is_flagged() {
    let violating: &str = "app.use(errorHandler);\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S4507"), 1);

    let clean: &str = "app.use(router);\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S4507"), 0);
}

#[test]
fn wildcard_cors_configuration_is_flagged() {
    let violating: &str = "app.use(cors({ origin: '*' }));\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S5122"), 1);

    let clean: &str = "app.use(cors({ origin: 'https://example.com' }));\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S5122"), 0);
}

#[test]
fn cleartext_protocols_are_flagged() {
    let imported = js_keys("import http from 'http';\n");
    assert_eq!(count_key(&imported, "javascript:S5332"), 1);

    let required = js_keys("const ws = require('ws');\n");
    assert_eq!(count_key(&required, "javascript:S5332"), 1);

    let url: &str = "fetch('http://example.com/data');\n";
    assert_eq!(count_key(&js_keys(url), "javascript:S5332"), 1);

    let clean: &str = "import https from 'https';\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S5332"), 0);
}

#[test]
fn global_tls_validation_disable_is_flagged() {
    let violating: &str = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S4830"), 1);

    let clean: &str = "process.env.node_env = 'production';\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S4830"), 0);
}

#[test]
fn csrf_route_exemptions_are_flagged() {
    let violating: &str = "app.use(csrf({ ignoreRoutes: ['/webhook'] }));\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S4502"), 1);

    let clean: &str = "app.use(csrf());\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S4502"), 0);
}

#[test]
fn cookies_require_secure_and_httponly_flags() {
    let violating: &str = "res.cookie('sid', value, { httpOnly: false });\n";
    let findings = js_keys(violating);
    assert_eq!(count_key(&findings, "javascript:S2092"), 1);
    assert_eq!(count_key(&findings, "javascript:S3330"), 1);

    let clean: &str = "res.cookie('sid', value, { secure: true, httpOnly: true });\n";
    let clean = js_keys(clean);
    assert_eq!(count_key(&clean, "javascript:S2092"), 0);
    assert_eq!(count_key(&clean, "javascript:S3330"), 0);
}

#[test]
fn raw_set_cookie_headers_are_hotspots() {
    let violating: &str = "res.setHeader('Set-Cookie', 'sid=1');\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S2255"), 1);

    let clean: &str = "res.setHeader('Content-Type', 'text/html');\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S2255"), 0);
}

#[test]
fn upload_handlers_without_limits_are_flagged() {
    let call = js_keys("const upload = multer({ dest: 'uploads/' });\n");
    assert_eq!(count_key(&call, "javascript:S2598"), 1);

    let constructor = js_keys("const busboy = new Busboy({ headers: req.headers });\n");
    assert_eq!(count_key(&constructor, "javascript:S2598"), 1);

    let clean: &str = "const upload = multer({ limits: { fileSize: 1000000 } });\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S2598"), 0);
}

#[test]
fn xml_parsers_allowing_entity_expansion_are_flagged() {
    let violating: &str = "libxml.parseXml(xml, { noent: true, noxxe: true });\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S2755"), 1);

    let no_xxe_guard: &str = "libxml.parseXml(xml, { noent: false });\n";
    assert_eq!(count_key(&js_keys(no_xxe_guard), "javascript:S2755"), 1);

    let clean: &str = "libxml.parseXml(xml, { noent: false, noxxe: true });\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S2755"), 0);
}

#[test]
fn archive_extraction_is_a_hotspot() {
    let violating: &str = "zip.extractAllTo(target);\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S5042"), 1);

    let clean: &str = "zip.readFile(name);\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S5042"), 0);
}

#[test]
fn disabled_certificate_verification_options_are_flagged() {
    let violating: &str = "https.get(url, { rejectUnauthorized: false });\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S5527"), 1);

    let clean: &str = "https.get(url, { rejectUnauthorized: true });\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S5527"), 0);
}

#[test]
fn autoescaping_must_stay_enabled() {
    let violating: &str = "nunjucks.configure({ autoescape: false });\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S5247"), 1);

    let clean: &str = "nunjucks.configure({ autoescape: true });\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S5247"), 0);
}

#[test]
fn serving_dotfiles_is_flagged() {
    let violating: &str = "express.static('public', { dotfiles: 'allow' });\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S5691"), 1);

    let clean: &str = "express.static('public', { dotfiles: 'ignore' });\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S5691"), 0);
}

#[test]
fn body_parsers_need_size_limits() {
    let violating: &str = "app.use(express.json({ strict: true }));\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S5693"), 1);

    let clean: &str = "app.use(express.json({ limit: '100kb' }));\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S5693"), 0);
}

#[test]
fn helmet_csp_disabling_is_flagged() {
    let entire: &str = "app.use(helmet({ contentSecurityPolicy: false }));\n";
    assert_eq!(count_key(&js_keys(entire), "javascript:S5728"), 1);

    let directive: &str =
        "app.use(helmet({ contentSecurityPolicy: { directives: { scriptSrc: [] } } }));\n";
    assert_eq!(count_key(&js_keys(directive), "javascript:S5728"), 1);

    let clean: &str = "app.use(helmet({ contentSecurityPolicy: { directives: { scriptSrc: [\"'self'\"] } } }));\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S5728"), 0);
}

#[test]
fn security_header_values_are_validated() {
    let csp: &str = "res.setHeader('Content-Security-Policy', \"default-src 'self'\");\n";
    let findings = js_keys(csp);
    assert_eq!(count_key(&findings, "javascript:S5730"), 1);
    assert_eq!(count_key(&findings, "javascript:S5732"), 1);

    let referrer: &str = "res.setHeader('Referrer-Policy', 'unsafe-url');\n";
    assert_eq!(count_key(&js_keys(referrer), "javascript:S5736"), 1);

    let hsts: &str = "res.setHeader('Strict-Transport-Security', 'max-age=0');\n";
    assert_eq!(count_key(&js_keys(hsts), "javascript:S5739"), 1);

    let nosniff: &str = "res.setHeader('X-Content-Type-Options', 'sniff');\n";
    assert_eq!(count_key(&js_keys(nosniff), "javascript:S5734"), 1);

    let powered_by: &str = "res.setHeader('X-Powered-By', 'Express');\n";
    assert_eq!(count_key(&js_keys(powered_by), "javascript:S5689"), 1);

    let clean: &str = "res.setHeader('Referrer-Policy', 'no-referrer');\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S5736"), 0);
}

#[test]
fn command_line_arguments_are_hotspots() {
    let indexed: &str = "const first = process.argv[2];\n";
    assert_eq!(count_key(&js_keys(indexed), "javascript:S4823"), 1);

    let exec_argv: &str = "if (process.execArgv.length > 0) {}\n";
    assert_eq!(count_key(&js_keys(exec_argv), "javascript:S4823"), 1);

    let clean: &str = "const mode = process.env.NODE_ENV;\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S4823"), 0);
}

#[test]
fn standard_input_reads_are_hotspots() {
    let violating: &str = "process.stdin.on('data', handler);\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S4829"), 1);

    let clean: &str = "console.log(process.stdout.isTTY);\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S4829"), 0);
}

#[test]
fn xpath_evaluation_is_a_hotspot() {
    let evaluate: &str = "const node = document.evaluate(expr, ctx);\n";
    assert_eq!(count_key(&js_keys(evaluate), "javascript:S4817"), 1);

    let evaluator: &str = "const evaluator = new XPathEvaluator();\n";
    assert_eq!(count_key(&js_keys(evaluator), "javascript:S4817"), 1);

    let imported: &str = "import { evaluate } from 'xpath';\n";
    assert_eq!(count_key(&js_keys(imported), "javascript:S4817"), 1);

    let required: &str = "const xpath = require('xpath');\n";
    assert_eq!(count_key(&js_keys(required), "javascript:S4817"), 1);

    let clean: &str = "const score = evaluateAnswer(answer);\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S4817"), 0);
}

#[test]
fn raw_sockets_are_hotspots() {
    let imported: &str = "import * as net from 'net';\n";
    assert_eq!(count_key(&js_keys(imported), "javascript:S4818"), 1);

    let required: &str = "const dgram = require('dgram');\n";
    assert_eq!(count_key(&js_keys(required), "javascript:S4818"), 1);

    let constructed: &str = "const socket = new net.Socket();\n";
    assert_eq!(count_key(&js_keys(constructed), "javascript:S4818"), 1);

    let clean: &str = "import http from 'http';\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S4818"), 0);
}

#[test]
fn certificate_transparency_disabling_is_flagged() {
    let header: &str = "res.setHeader('Expect-CT', 'max-age=0');\n";
    assert_eq!(count_key(&js_keys(header), "javascript:S5742"), 1);

    let helmet: &str = "app.use(helmet({ expectCt: false }));\n";
    assert_eq!(count_key(&js_keys(helmet), "javascript:S5742"), 1);

    let enforcing: &str = "res.setHeader('Expect-CT', 'max-age=86400, enforce');\n";
    assert_eq!(count_key(&js_keys(enforcing), "javascript:S5742"), 0);
}

#[test]
fn dns_prefetch_control_is_flagged() {
    let header: &str = "res.setHeader('X-DNS-Prefetch-Control', 'on');\n";
    assert_eq!(count_key(&js_keys(header), "javascript:S5743"), 1);

    let helmet: &str = "app.use(helmet({ dnsPrefetch: false }));\n";
    assert_eq!(count_key(&js_keys(helmet), "javascript:S5743"), 1);

    let written: &str = "res.writeHead(200, { 'X-DNS-Prefetch-Control': 'on' });\n";
    assert_eq!(count_key(&js_keys(written), "javascript:S5743"), 1);

    let clean: &str = "res.setHeader('X-DNS-Prefetch-Control', 'off');\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S5743"), 0);
}

// ---- Batch-5 test-framework fixtures ----

fn test_file_keys(source: &str) -> Vec<(String, u32)> {
    analyze(
        PathBuf::from("app.test.js"),
        source,
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
    )
    .issues
    .into_iter()
    .map(|issue| (issue.rule_key, issue.range.start.line))
    .collect()
}

#[test]
fn test_files_without_tests_are_flagged() {
    let empty_suite: &str = "const helper = require('./helper');\n";
    assert_eq!(
        count_key(&test_file_keys(empty_suite), "javascript:S2187"),
        1
    );

    let with_tests: &str =
        "describe('suite', () => { it('works', () => { expect(1).to.equal(1); }); });\n";
    assert_eq!(
        count_key(&test_file_keys(with_tests), "javascript:S2187"),
        0
    );

    let not_a_test_file: &str = "console.log('plain module');\n";
    assert_eq!(count_key(&js_keys(not_a_test_file), "javascript:S2187"), 0);
}

#[test]
fn test_callbacks_need_assertions() {
    let without: &str = "it('calls home', () => { home.call(); });\n";
    assert_eq!(count_key(&test_file_keys(without), "javascript:S2699"), 1);

    let with: &str = "it('calls home', () => { expect(home.calls).to.equal(1); });\n";
    assert_eq!(count_key(&test_file_keys(with), "javascript:S2699"), 0);
}

#[test]
fn incomplete_chai_chains_are_flagged() {
    let incomplete: &str = "expect(value).to.be;\n";
    assert_eq!(
        count_key(&test_file_keys(incomplete), "javascript:S2970"),
        1
    );

    let complete: &str = "expect(value).to.be.true;\n";
    assert_eq!(count_key(&test_file_keys(complete), "javascript:S2970"), 0);
}

#[test]
fn swapped_chai_arguments_are_flagged() {
    let swapped: &str = "expect(5).to.equal(result);\n";
    assert_eq!(count_key(&test_file_keys(swapped), "javascript:S3415"), 1);

    let natural: &str = "expect(result).to.equal(5);\n";
    assert_eq!(count_key(&test_file_keys(natural), "javascript:S3415"), 0);
}

#[test]
fn self_comparing_assertions_are_flagged() {
    let same_value: &str = "expect(value).to.equal(value);\n";
    assert_eq!(
        count_key(&test_file_keys(same_value), "javascript:S5863"),
        1
    );

    let other: &str = "expect(value).to.equal(other);\n";
    assert_eq!(count_key(&test_file_keys(other), "javascript:S5863"), 0);
}

#[test]
fn catch_blocks_without_assertions_are_flagged() {
    let without: &str = "it('throws', () => {\n  try {\n    boom();\n  } catch (error) {\n    log(error);\n  }\n});\n";
    assert_eq!(count_key(&test_file_keys(without), "javascript:S5958"), 1);

    let with: &str = "it('throws', () => {\n  try {\n    boom();\n  } catch (error) {\n    expect(error).to.match(/bad/);\n  }\n});\n";
    assert_eq!(count_key(&test_file_keys(with), "javascript:S5958"), 0);
}

#[test]
fn nondeterministic_test_values_are_flagged() {
    let random: &str = "it('rolls', () => {\n  const roll = Math.random();\n  expect(roll).to.be.a('number');\n});\n";
    assert_eq!(count_key(&test_file_keys(random), "javascript:S5973"), 1);

    let fixed: &str = "it('rolls', () => {\n  const roll = 4;\n  expect(roll).to.equal(4);\n});\n";
    assert_eq!(count_key(&test_file_keys(fixed), "javascript:S5973"), 0);
}

#[test]
fn statements_after_done_are_flagged() {
    let after: &str =
        "it('finishes', function (done) {\n  run(done);\n  done();\n  verify();\n});\n";
    assert_eq!(count_key(&test_file_keys(after), "javascript:S6079"), 1);

    let last: &str = "it('finishes', function (done) {\n  verify();\n  done();\n});\n";
    assert_eq!(count_key(&test_file_keys(last), "javascript:S6079"), 0);
}

#[test]
fn disabled_timeouts_are_flagged() {
    let disabled: &str = "describe('slow', () => {\n  this.timeout(0);\n});\n";
    assert_eq!(count_key(&test_file_keys(disabled), "javascript:S6080"), 1);

    let limited: &str = "describe('slow', () => {\n  this.timeout(2000);\n});\n";
    assert_eq!(count_key(&test_file_keys(limited), "javascript:S6080"), 0);
}

#[test]
fn multi_matcher_chains_are_flagged() {
    let chained: &str = "expect(value).to.equal(1).and.equal(2);\n";
    assert_eq!(count_key(&test_file_keys(chained), "javascript:S6092"), 1);

    let single: &str = "expect(value).to.equal(1);\n";
    assert_eq!(count_key(&test_file_keys(single), "javascript:S6092"), 0);
}

#[test]
fn skipped_and_focused_tests_are_flagged() {
    let skipped: &str = "xit('later', () => { expect(1).to.equal(1); });\nit.skip('also later', () => { expect(1).to.equal(1); });\n";
    let findings = test_file_keys(skipped);
    assert_eq!(count_key(&findings, "javascript:S1607"), 2);

    let focused: &str =
        "fit('just this', () => { expect(1).to.equal(1); });\ndescribe.only('solo', () => {});\n";
    let focused = test_file_keys(focused);

    assert_eq!(count_key(&focused, "javascript:S6426"), 2);

    let normal: &str = "it('runs', () => { expect(1).to.equal(1); });\n";
    let normal = test_file_keys(normal);
    assert_eq!(count_key(&normal, "javascript:S1607"), 0);
    assert_eq!(count_key(&normal, "javascript:S6426"), 0);
}
#[test]
fn vue_v_html_bypasses_escaping() {
    let violating: &str = "const tpl = `<div v-html=\"userContent\"></div>`;\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S6299"), 1);

    let sfc: &str = "const template = '<span v-html=raw></span>';\n";
    assert_eq!(count_key(&js_keys(sfc), "javascript:S6299"), 1);

    let clean: &str = "const tpl = `<div>{{ userContent }}</div>`;\n";
    assert_eq!(count_key(&js_keys(clean), "javascript:S6299"), 0);
}

#[test]
fn s3_buckets_need_server_side_encryption() {
    let violating: &str = "const result = await s3.createBucket({ Bucket: 'name' });\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S6245"), 1);

    let command: &str = "await client.send(new CreateBucketCommand({ Bucket: 'name' }));\n";
    assert_eq!(count_key(&js_keys(command), "javascript:S6245"), 1);

    let encrypted: &str = "const r = await s3.createBucket({ Bucket: 'n', ServerSideEncryptionConfiguration: {} });\n";
    assert_eq!(count_key(&js_keys(encrypted), "javascript:S6245"), 0);
}

// ---- Batch-5 misc Tier-A fixtures ----

#[test]
fn top_level_var_and_function_declarations_are_flagged() {
    let globals: &str = "var counter = 1;\nfunction reset() {}\n";
    let javascript = js_keys(globals);
    assert_eq!(count_key(&javascript, "javascript:S3798"), 2);

    let typescript = ts_keys(globals);
    assert_eq!(count_key(&typescript, "typescript:S3798"), 0);
}

#[test]
fn misplaced_use_strict_is_flagged() {
    let misplaced: &str = "console.log(1);\n'use strict';\n";
    assert_eq!(count_key(&js_keys(misplaced), "javascript:S1539"), 1);

    let prologue: &str = "'use strict';\nconsole.log(1);\n";
    assert_eq!(count_key(&js_keys(prologue), "javascript:S1539"), 0);
}

#[test]
fn global_this_expressions_are_flagged() {
    let top_level: &str = "console.log(this);
";
    assert_eq!(count_key(&js_keys(top_level), "javascript:S2990"), 1);

    let in_function: &str = "function f() { return this; }\n";
    assert_eq!(count_key(&js_keys(in_function), "javascript:S2990"), 0);
}

#[test]
fn default_export_names_should_match_file_stems() {
    let mismatched = analyze(
        PathBuf::from("user-service.js"),
        "export default class Account {}\n",
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
    );
    assert_eq!(
        count_key(&mismatched_keys(&mismatched), "javascript:S3317"),
        1
    );

    let matched = analyze(
        PathBuf::from("user-service.js"),
        "export default class UserService {}\n",
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
    );
    assert_eq!(count_key(&matched_keys(&matched), "javascript:S3317"), 0);
}

fn mismatched_keys(report: &hoonarqube_ir::FileReport) -> Vec<(String, u32)> {
    report
        .issues
        .iter()
        .map(|i| (i.rule_key.clone(), i.range.start.line))
        .collect()
}

fn matched_keys(report: &hoonarqube_ir::FileReport) -> Vec<(String, u32)> {
    report
        .issues
        .iter()
        .map(|i| (i.rule_key.clone(), i.range.start.line))
        .collect()
}

#[test]
fn self_imports_are_flagged() {
    let self_import = analyze(
        PathBuf::from("app.js"),
        "import './app';\n",
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
    );
    let findings: Vec<_> = self_import
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "javascript:S7060")
        .collect();
    assert_eq!(findings.len(), 1);

    let other_import = analyze(
        PathBuf::from("app.js"),
        "import './other';\n",
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
    );
    assert!(
        other_import
            .issues
            .iter()
            .all(|issue| issue.rule_key != "javascript:S7060")
    );
}

// --- Tier B: scope/symbol table rules ---

fn filtered(report: &hoonarqube_ir::FileReport, rule: &str) -> Vec<String> {
    report
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(rule))
        .map(|issue| {
            format!(
                "{}:{}:{}",
                issue.rule_key, issue.range.start.line, issue.message
            )
        })
        .collect()
}

#[test]
fn shadowing_flagged_only_when_outer_used_after_inner_declaration() {
    let flagged = js("let x = 1;\nfunction g() {\n  let x = 2;\n}\ng(x);\n");
    assert_eq!(filtered(&flagged, "S1117").len(), 1);

    let clean = js("let x = 1;\nfunction g() {\n  let x = 2;\n}\ng();\n");
    assert_eq!(filtered(&clean, "S1117").len(), 0);
}

#[test]
fn unused_imports_flagged_in_javascript_only() {
    let source = "import { helper } from './helper';\n";
    assert_eq!(filtered(&js(source), "S1128").len(), 1);
    assert_eq!(filtered(&ts(source), "S1128").len(), 0);
    let used = "import { helper } from './helper';\nhelper();\n";
    assert_eq!(filtered(&js(used), "S1128").len(), 0);
}

#[test]
fn unused_locals_flagged_inside_functions_but_not_at_top_level() {
    let source = "const kept = 1;\nfunction f() {\n  const orphan = 2;\n}\nf();\n";
    let issues = filtered(&js(source), "S1481");
    assert_eq!(issues.len(), 1);
    assert!(issues[0].contains("orphan"));
}

#[test]
fn unused_parameters_flagged_but_setters_exempt() {
    let flagged = js("function f(unused) {\n  return 1;\n}\nf(2);\n");
    assert_eq!(filtered(&flagged, "S1172").len(), 1);
    let clean = js("const obj = { set value(next) { this.stored = next; } };\nobj.value = 3;\n");
    assert_eq!(filtered(&clean, "S1172").len(), 0);
}

#[test]
fn implicit_global_assignment_flagged_in_javascript_only() {
    let source = "function f() {\n  leaked = 1;\n}\nf();\n";
    assert_eq!(filtered(&js(source), "S2703").len(), 1);
    assert_eq!(
        filtered(&ts("function f() {\n  leaked = 1;\n}\nf();\n"), "S2703").len(),
        0
    );
}

#[test]
fn duplicate_var_declarations_in_same_scope_flagged() {
    let flagged = js("var dup = 1;\nvar dup = 2;\n");
    assert_eq!(filtered(&flagged, "S2814").len(), 1);
    let clean = js("var first = 1;\nvar second = 2;\n");
    assert_eq!(filtered(&clean, "S2814").len(), 0);
}

#[test]
fn const_reassignment_flagged() {
    let flagged = js("const fixed = 1;\nfixed = 2;\n");
    assert_eq!(filtered(&flagged, "S3500").len(), 1);
    let clean = js("const fixed = 1;\nconsole.log(fixed);\n");
    assert_eq!(filtered(&clean, "S3500").len(), 0);
}

#[test]
fn use_before_declaration_flagged_for_let_and_function_calls() {
    let source = "function f() {\n  early = 1;\n  let early = 2;\n}\nf();\n";
    assert_eq!(filtered(&js(source), "S3827").len(), 1);
    let calls = js("later();\nfunction later() {}\n");
    assert_eq!(filtered(&calls, "S3827").len(), 1);
}

#[test]
fn import_reassignment_flagged() {
    let flagged = js("import { helper } from './helper';\nhelper = null;\n");
    assert_eq!(filtered(&flagged, "S6522").len(), 1);
}

#[test]
fn var_read_before_its_declarator_flagged() {
    let flagged = js("function f() {\n  console.log(hoisted);\n  var hoisted = 1;\n}\nf();\n");
    assert_eq!(filtered(&flagged, "S1526").len(), 1);
    let clean = js("function f() {\n  var hoisted = 1;\n  console.log(hoisted);\n}\nf();\n");
    assert_eq!(filtered(&clean, "S1526").len(), 0);
}

#[test]
fn var_leaking_out_of_its_block_flagged_once() {
    let flagged = js("if (cond) {\n  var leaky = 1;\n}\nuse(leaky);\n");
    assert_eq!(filtered(&flagged, "S2392").len(), 1);
    let clean = js("if (cond) {\n  let scoped = 1;\n  use(scoped);\n}\n");
    assert_eq!(filtered(&clean, "S2392").len(), 0);
}

#[test]
fn arity_mismatch_against_local_function_flagged() {
    let flagged = js("function add(a, b) { return a + b; }\nadd(1);\nadd(1, 2, 3);\n");
    assert_eq!(filtered(&flagged, "S930").len(), 2);
    let rest_clean =
        js("function pick(first, ...rest) { return rest; }\npick(1);\npick(1, 2, 3);\n");
    assert_eq!(filtered(&rest_clean, "S930").len(), 0);
}

#[test]
fn new_on_non_constructor_binding_flagged() {
    let flagged = js("const make = () => 1;\nnew make();\n");
    assert_eq!(filtered(&flagged, "S2999").len(), 1);
    let clean = js("class Box {}\nnew Box();\nfunction Factory() {}\nnew Factory();\n");
    assert_eq!(filtered(&clean, "S2999").len(), 0);
}

#[test]
fn mixed_call_and_new_sites_flag_minority_form() {
    let flagged = js("function Thing() {}\nnew Thing();\nThing();\n");
    assert_eq!(filtered(&flagged, "S3686").len(), 1);
    let clean = js("function plain() {}\nplain();\nplain();\n");
    assert_eq!(filtered(&clean, "S3686").len(), 0);
}

#[test]
fn typescript_files_receive_tier_b_keys_with_typescript_prefix() {
    let source = "import { helper } from './helper';\nhelper = null;\n";
    let report = ts(source);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.rule_key == "typescript:S6522")
    );
}

// --- Tier B remainder group 1: dataflow-lite ---

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
    let caught = js("try {\n  risky();\n} catch (error) {\n  error = null;\n  log(error);\n}\n");
    assert_eq!(filtered(&caught, "S1226").len(), 1);
    let clean = js("function f(c) {\n  if (c) {\n    c = 1;\n  }\n  return c;\n}\nf(2);\n");
    assert_eq!(filtered(&clean, "S1226").len(), 0);
}

#[test]
fn constant_boolean_conditions_flagged() {
    let flagged = js("if (true) {\n  work();\n}\nwhile (false) {\n  skip();\n}\n");
    assert_eq!(filtered(&flagged, "S2589").len(), 2);
    let clean = js("if (cond) {\n  work();\n}\nwhile (running) {\n  skip();\n}\n");
    assert_eq!(filtered(&clean, "S2589").len(), 0);
}

#[test]
fn null_member_access_is_javascript_only() {
    let sources = ["null.foo();\n", "undefined.bar;\n", "value(null.x);\n"];
    for source in sources {
        assert_eq!(filtered(&js(source), "S2259").len(), 1, "{source}");
        assert_eq!(filtered(&ts(source), "S2259").len(), 0, "{source}");
    }
    assert_eq!(filtered(&js("null?.foo;\n"), "S2259").len(), 0);
}

#[test]
fn never_reassigned_let_suggested_as_const() {
    let flagged = js("let fixed = compute();\nuse(fixed);\n");
    assert_eq!(filtered(&flagged, "S3353").len(), 1);
    let reassigned = js("let moving = 1;\nmoving = 2;\nuse(moving);\n");
    assert_eq!(filtered(&reassigned, "S3353").len(), 0);
    let for_head = js("for (let item of list) {\n  use(item);\n}\n");
    assert_eq!(filtered(&for_head, "S3353").len(), 0);
    let exported = js("export let exportedValue = compute();\nuse(exportedValue);\n");
    assert_eq!(filtered(&exported, "S3353").len(), 0);
    let late_init = js("let late;\nlate = 1;\nuse(late);\n");
    assert_eq!(filtered(&late_init, "S3353").len(), 0);
}

#[test]
fn identical_repeated_write_prefers_redundant_assignment_key() {
    let flagged =
        js("function f() {\n  let size = width();\n  size = width();\n  return size;\n}\nf();\n");
    assert_eq!(filtered(&flagged, "S4165").len(), 1);
    assert_eq!(filtered(&flagged, "S1854").len(), 0);
}

// --- Tier B remainder group 2: targeted dataflow queries ---

#[test]
fn sql_sinks_reject_dynamic_strings_only() {
    let flagged = js(
        "db.query(`SELECT * FROM users WHERE name = ${name}`);\ndb.execute('SELECT ' + column);\n",
    );
    assert_eq!(filtered(&flagged, "S2077").len(), 2);
    let clean = js("db.query('SELECT 1');\ndb.query(staticQuery);\n");
    assert_eq!(filtered(&clean, "S2077").len(), 0);
}

#[test]
fn write_only_collections_flagged() {
    let map = js("const cache = new Map();\ncache.set('a', 1);\n");
    assert_eq!(filtered(&map, "S4030").len(), 1);
    let array = js("const out = [];\nout.push(2);\nout.unshift(3);\n");
    assert_eq!(filtered(&array, "S4030").len(), 1);
    let read = js("const kept = [];\nkept.push(1);\nuse(kept);\n");
    assert_eq!(filtered(&read, "S4030").len(), 0);
    let indexed = js("const mixed = [];\nmixed[0] = 1;\n");
    assert_eq!(filtered(&indexed, "S4030").len(), 0);
}

#[test]
fn in_place_capture_needs_later_original_use() {
    let flagged = js(
        "function f(list) {\n  const sorted = list.sort();\n  return list.length + sorted.length;\n}\nf(items);\n",
    );
    assert_eq!(filtered(&flagged, "S4043").len(), 1);
    let clean = js("const ordered = items.sort();\nreturn ordered;\n");
    assert_eq!(filtered(&clean, "S4043").len(), 0);
}

#[test]
fn map_set_after_get_round_trip_flagged() {
    let flagged = js(
        "function f(map) {\n  const current = map.get('key');\n  map.set('key', current);\n}\nf(m);\n",
    );
    assert_eq!(filtered(&flagged, "S4143").len(), 1);
    let other_key = js("const v = map.get('a');\nmap.set('b', v);\n");
    assert_eq!(filtered(&other_key, "S4143").len(), 0);
    let deleted_between = js("const v = map.get('k');\nmap.delete('k');\nmap.set('k', v);\n");
    assert_eq!(filtered(&deleted_between, "S4143").len(), 0);
}

#[test]
fn permissive_modes_and_tmp_paths_flagged() {
    let modes = js("fs.open(path, 'w', 0o777);\nfs.writeFile(file, data, 511);\n");
    assert_eq!(filtered(&modes, "S5443").len(), 2);
    let safe_mode = js("fs.open(path, 'w', 0o644);\n");
    assert_eq!(filtered(&safe_mode, "S5443").len(), 0);
    let tmp = js("fs.writeFile(os.tmpdir() + '/out.txt', data);\n");
    assert_eq!(filtered(&tmp, "S5443").len(), 1);
    let exclusive =
        js("fs.writeFile('/tmp/out.txt', data, { flag: 'wx' });\nfs.open('/tmp/x', 'ax');\n");
    assert_eq!(filtered(&exclusive, "S5443").len(), 0);
}

#[test]
fn constructor_only_fields_suggested_readonly_in_typescript() {
    let source = "class C {\n  name;\n  constructor(value) {\n    this.name = value;\n  }\n}\n";
    assert_eq!(filtered(&ts(source), "S2933").len(), 1);
    assert_eq!(filtered(&js(source), "S2933").len(), 0);
    let method_written = "class C {\n  count;\n  tick() {\n    this.count = 1;\n  }\n}\n";
    assert_eq!(filtered(&ts(method_written), "S2933").len(), 0);
    let already_readonly =
        "class C {\n  readonly id;\n  constructor() {\n    this.id = 1;\n  }\n}\n";
    assert_eq!(filtered(&ts(already_readonly), "S2933").len(), 0);
    let initialized = "class C {\n  preset = 1;\n  constructor() {\n    this.preset = 2;\n  }\n}\n";
    assert_eq!(filtered(&ts(initialized), "S2933").len(), 0);
}

#[test]
fn dynamic_regex_construction_flagged() {
    let flagged = js(
        "new RegExp('a' + userInput);\nnew RegExp(`^${prefix}`);\nconst p = buildPattern();\nnew RegExp(p);\n",
    );
    assert_eq!(filtered(&flagged, "S4784").len(), 3);
    let static_binding = js("const digits = '\\\\d+';\nnew RegExp(digits);\n");
    assert_eq!(filtered(&static_binding, "S4784").len(), 0);
    let literal = js("new RegExp('abc');\n");
    assert_eq!(filtered(&literal, "S4784").len(), 0);
}

// --- Tier B remainder group 3: CFG-lite ---

fn jsx(source: &str) -> hoonarqube_ir::FileReport {
    analyze(
        PathBuf::from("test.jsx"),
        source,
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
    )
}

#[test]
fn login_without_session_regeneration_flagged() {
    let flagged = js(
        "app.post('/login', (req, res) => {\n  req.session.user = req.body.user;\n  res.redirect('/');\n});\n",
    );
    assert_eq!(filtered(&flagged, "S5876").len(), 1);
    let regenerated = js(
        "app.post('/login', (req, res) => {\n  req.session.regenerate(() => {});\n  res.redirect('/');\n});\n",
    );
    assert_eq!(filtered(&regenerated, "S5876").len(), 0);
    let other_path = js("app.post('/profile', (req, res) => {\n  res.send('ok');\n});\n");
    assert_eq!(filtered(&other_path, "S5876").len(), 0);
}

#[test]
fn unstable_jsx_keys_flagged() {
    let flagged =
        jsx("const rows = items.map((item) => (\n  <li key={Math.random()}>{item}</li>\n));\n");
    assert_eq!(filtered(&flagged, "S6486").len(), 1);
    let date_key = jsx("<li key={Date.now()}>{item}</li>\n");
    assert_eq!(filtered(&date_key, "S6486").len(), 1);
    let stable = jsx("const rows = items.map((item) => (\n  <li key={item.id}>{item}</li>\n));\n");
    assert_eq!(filtered(&stable, "S6486").len(), 0);
}

#[test]
fn valueless_then_callback_in_chain_flagged() {
    let flagged =
        js("fetchData().then((response) => {\n  console.log(response);\n}).catch(fail);\n");
    assert_eq!(filtered(&flagged, "S6544").len(), 1);
    let returns_value =
        js("fetchData().then((response) => {\n  return response.json();\n}).catch(fail);\n");
    assert_eq!(filtered(&returns_value, "S6544").len(), 0);
    let unchained = js("fetchData().then((response) => {\n  console.log(response);\n});\n");
    assert_eq!(filtered(&unchained, "S6544").len(), 0);
}

// --- Tier B remainder group 4: trivia ---

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
fn shell_commands_flag_http_downloads_and_unpinned_installs() {
    let flagged = js("exec('curl http://example.com/install.sh');\nspawn('npm install lodash');\n");
    assert_eq!(filtered(&flagged, "S5725").len(), 2);
    let clean = js(
        "exec('curl https://example.com/install.sh');\nspawn('npm install lodash@4.17.21');\nexecFile('git', ['status']);\n",
    );
    assert_eq!(filtered(&clean, "S5725").len(), 0);
}

#[test]
fn strings_and_non_strings_are_not_added() {
    let violating: &str = "const mix = 'value' + 42;\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S3402"), 1);

    let reversed: &str = "const mix = true + 'value';\n";
    assert_eq!(count_key(&js_keys(reversed), "javascript:S3402"), 1);

    let array: &str = "const label = 'items: ' + [1, 2];\n";
    assert_eq!(count_key(&js_keys(array), "javascript:S3402"), 1);

    let clean_concat: &str = "const ok = 'a' + 'b';\n";
    assert_eq!(count_key(&js_keys(clean_concat), "javascript:S3402"), 0);

    let clean_number: &str = "const sum = 1 + 2;\n";
    assert_eq!(count_key(&js_keys(clean_number), "javascript:S3402"), 0);
}

#[test]
fn strict_equality_between_dissimilar_literals_is_flagged() {
    const CLEAN_STRING: &str = "const str = 'a' === 'b';\n";
    const CLEAN_UNKNOWN: &str = "const unknown = input === 'x';\n";
    let violating: &str = "const same = '1' === 1;\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S3403"), 1);

    let inequality: &str = "const diff = true !== 'true';\n";
    assert_eq!(count_key(&js_keys(inequality), "javascript:S3403"), 1);

    let null_undefined: &str = "const never = null === undefined;\n";
    assert_eq!(count_key(&js_keys(null_undefined), "javascript:S3403"), 1);

    assert_eq!(count_key(&js_keys(CLEAN_STRING), "javascript:S3403"), 0);

    assert_eq!(count_key(&js_keys(CLEAN_UNKNOWN), "javascript:S3403"), 0);

    // TypeScript's catalog has no S3403; the JsOnly scope suppresses it.
    assert_eq!(count_key(&ts_keys(violating), "typescript:S3403"), 0);
}

#[test]
fn operations_that_always_yield_nan_are_flagged() {
    const INFINITY_TIMES_ZERO: &str = "const nan = Infinity * 0;\n";
    const PARSE_GARBAGE: &str = "const nan = parseInt('abc');\n";
    const NUMBER_UNDEFINED: &str = "const nan = Number(undefined);\n";
    const CLEAN_RATIO: &str = "const ratio = width / height;\n";
    const CLEAN_PARSE: &str = "const parsed = parseInt('42');\n";
    let zero_division: &str = "const nan = 0 / 0;\n";
    assert_eq!(count_key(&js_keys(zero_division), "javascript:S3757"), 1);

    assert_eq!(
        count_key(&js_keys(INFINITY_TIMES_ZERO), "javascript:S3757"),
        1
    );

    assert_eq!(count_key(&js_keys(PARSE_GARBAGE), "javascript:S3757"), 1);

    assert_eq!(count_key(&js_keys(NUMBER_UNDEFINED), "javascript:S3757"), 1);

    assert_eq!(count_key(&js_keys(CLEAN_RATIO), "javascript:S3757"), 0);

    assert_eq!(count_key(&js_keys(CLEAN_PARSE), "javascript:S3757"), 0);
}

#[test]
fn in_operator_rejects_primitive_right_hand_sides() {
    const CLEAN: &str = "const has = 'length' in [];\n";
    const CLEAN_OBJECT: &str = "const has = 'a' in { a: 1 };\n";
    let violating: &str = "const has = 'length' in 'abc';\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S3785"), 1);

    let number: &str = "const has = 0 in 42;\n";
    assert_eq!(count_key(&js_keys(number), "javascript:S3785"), 1);

    assert_eq!(count_key(&js_keys(CLEAN), "javascript:S3785"), 0);

    assert_eq!(count_key(&js_keys(CLEAN_OBJECT), "javascript:S3785"), 0);
}

#[test]
fn array_indexes_should_be_numeric() {
    const CLEAN_OBJECT: &str = "const value = obj[\"key\"];\n";
    const CLEAN_NUMBER: &str = "const second = [10, 20][1];\n";
    let violating: &str = "const first = 'a,b'.split(',')[\"0\"];\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S3579"), 1);

    let literal: &str = "const second = [10, 20][\"1\"];\n";
    assert_eq!(count_key(&js_keys(literal), "javascript:S3579"), 1);

    assert_eq!(count_key(&js_keys(CLEAN_OBJECT), "javascript:S3579"), 0);

    assert_eq!(count_key(&js_keys(CLEAN_NUMBER), "javascript:S3579"), 0);
}

#[test]
fn relational_comparisons_reject_object_operands() {
    const CLEAN: &str = "const ordered = 'a' < 'b';\n";
    let violating: &str = "const ordered = {} < {};\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S3758"), 1);

    let array: &str = "const ordered = [1] >= [2];\n";
    assert_eq!(count_key(&js_keys(array), "javascript:S3758"), 1);

    assert_eq!(count_key(&js_keys(CLEAN), "javascript:S3758"), 0);
}

#[test]
fn arithmetic_operands_must_be_numbers() {
    const CLEAN_CONCAT: &str = "const ok = 'a' + 'b';\n";
    const CLEAN_SUM: &str = "const ok = 1 + 2;\n";
    let subtract_string: &str = "const nan = '5' - 3;\n";
    assert_eq!(count_key(&js_keys(subtract_string), "javascript:S3760"), 1);

    let boolean_addition: &str = "const sum = true + 1;\n";
    assert_eq!(count_key(&js_keys(boolean_addition), "javascript:S3760"), 1);

    assert_eq!(count_key(&js_keys(CLEAN_CONCAT), "javascript:S3760"), 0);

    assert_eq!(count_key(&js_keys(CLEAN_SUM), "javascript:S3760"), 0);
}

#[test]
fn await_should_only_apply_to_promises() {
    const SYNC_BUILTIN: &str = "async function run() { const data = await JSON.parse('{}'); }\n";
    const LOCAL_SYNC: &str = "function compute() {\n  return 1;\n}\nasync function main() {\n  const v = await compute();\n}\n";
    const CLEAN_ASYNC_LOCAL: &str = "async function load() {\n  return fetch(url);\n}\nasync function main() {\n  const r = await load();\n}\n";
    const CLEAN_UNKNOWN: &str = "async function main() {\n  const r = await mystery();\n}\n";
    let literal: &str = "async function run() { const value = await 42; }\n";
    assert_eq!(count_key(&js_keys(literal), "javascript:S4123"), 1);

    assert_eq!(count_key(&js_keys(SYNC_BUILTIN), "javascript:S4123"), 1);

    assert_eq!(count_key(&js_keys(LOCAL_SYNC), "javascript:S4123"), 1);

    assert_eq!(
        count_key(&js_keys(CLEAN_ASYNC_LOCAL), "javascript:S4123"),
        0
    );

    assert_eq!(count_key(&js_keys(CLEAN_UNKNOWN), "javascript:S4123"), 0);
}
#[test]
fn builtin_arguments_match_documented_types() {
    const BAD_RADIX: &str = "const n = parseInt('ff', 'hex');\n";
    const CHARCODE_STRING: &str = "const c = String.fromCharCode('65');\n";
    const CLEAN_RADIX: &str = "const n = parseInt('ff', 16);\n";
    const CLEAN_PARSE: &str = "const n = parseInt('42');\n";
    const CLEAN_CHARCODE: &str = "const c = String.fromCharCode(65);\n";
    const PARSE_OBJECT: &str = "const n = parseInt({});\n";
    assert_eq!(count_key(&js_keys(PARSE_OBJECT), "javascript:S3782"), 1);

    assert_eq!(count_key(&js_keys(BAD_RADIX), "javascript:S3782"), 1);

    assert_eq!(count_key(&js_keys(CHARCODE_STRING), "javascript:S3782"), 1);

    assert_eq!(count_key(&js_keys(CLEAN_RADIX), "javascript:S3782"), 0);

    assert_eq!(count_key(&js_keys(CLEAN_PARSE), "javascript:S3782"), 0);

    assert_eq!(count_key(&js_keys(CLEAN_CHARCODE), "javascript:S3782"), 0);
}

#[test]
fn functions_should_return_one_type() {
    const CONSISTENT: &str = "function pick(flag) {\n  return flag ? 'a' : 'b';\n}\n";
    const VOID_FN: &str = "function run() {\n  doWork();\n}\n";
    let mixed: &str =
        "function pick(flag) {\n  if (flag) {\n    return 'yes';\n  }\n  return 0;\n}\n";
    assert_eq!(count_key(&js_keys(mixed), "javascript:S3800"), 1);

    assert_eq!(count_key(&js_keys(CONSISTENT), "javascript:S3800"), 0);

    assert_eq!(count_key(&js_keys(VOID_FN), "javascript:S3800"), 0);
}

#[test]
fn void_function_results_should_not_be_used() {
    const RETURNED: &str =
        "function run() {\n  doWork();\n}\nfunction main() {\n  return run();\n}\n";
    const BARE: &str = "function run() {\n  doWork();\n}\nrun();\n";
    const ASYNC_FN: &str = "async function load() {}\nconst r = load();\n";
    const USED: &str = "function run() {\n  doWork();\n}\nconst total = run();\n";
    assert_eq!(count_key(&js_keys(USED), "javascript:S3699"), 1);

    assert_eq!(count_key(&js_keys(RETURNED), "javascript:S3699"), 1);

    assert_eq!(count_key(&js_keys(BARE), "javascript:S3699"), 0);

    assert_eq!(count_key(&js_keys(ASYNC_FN), "javascript:S3699"), 0);
}

#[test]
fn mixed_optional_chains_are_flagged() {
    const CLEAN_ALL_OPTIONAL: &str = "const value = a?.b?.c;\n";
    const CLEAN_OPTIONAL_LAST: &str = "const value = a.b.c?.d;\n";
    let violating: &str = "const value = a?.b.c;\n";
    assert_eq!(count_key(&js_keys(violating), "javascript:S6523"), 1);

    let deep: &str = "const value = a.b?.c.d;\n";
    assert_eq!(count_key(&js_keys(deep), "javascript:S6523"), 1);

    let computed: &str = "const value = a?.b[0].c;\n";
    assert_eq!(count_key(&js_keys(computed), "javascript:S6523"), 1);

    assert_eq!(
        count_key(&js_keys(CLEAN_ALL_OPTIONAL), "javascript:S6523"),
        0
    );

    assert_eq!(
        count_key(&js_keys(CLEAN_OPTIONAL_LAST), "javascript:S6523"),
        0
    );

    // Both catalog scopes carry S6523.
    assert_eq!(count_key(&ts_keys(violating), "typescript:S6523"), 1);
}

#[test]
fn instances_of_classes_without_to_string_are_flagged_when_coerced() {
    const WITH_TOSTRING: &str = "class Point {\n  toString() {\n    return 'p';\n  }\n}\nconst p = new Point();\nconst label = `at ${p}`;\n";
    const UNRELATED: &str = "class Point {}\nconst label = `at ${other}`;\n";

    let template: &str = "class Point {}\nconst p = new Point();\nconst label = `at ${p}`;\n";
    assert_eq!(count_key(&js_keys(template), "javascript:S6551"), 1);

    let concat: &str = "class Point {}\nconst p = new Point();\nconst label = 'at ' + p;\n";
    assert_eq!(count_key(&js_keys(concat), "javascript:S6551"), 1);

    let concat_left: &str = "class Point {}\nconst p = new Point();\nconst label = p + '!';\n";
    assert_eq!(count_key(&js_keys(concat_left), "javascript:S6551"), 1);

    assert_eq!(count_key(&js_keys(WITH_TOSTRING), "javascript:S6551"), 0);

    assert_eq!(count_key(&js_keys(UNRELATED), "javascript:S6551"), 0);

    // Both catalog scopes carry S6551.
    assert_eq!(count_key(&ts_keys(template), "typescript:S6551"), 1);
}

#[test]
fn selector_parameters_are_flagged_when_driving_branches() {
    const SWITCH_VIOLATION: &str = "function render(type) {\n  switch (type) {\n    case 'a':\n      return 'A';\n    case 'b':\n      return 'B';\n    default:\n      return '?';\n  }\n}\n";
    const COMPARISON_VIOLATION: &str = "function move(mode) {\n  if (mode === 'fast') {\n    return 1;\n  }\n  return mode === 'slow' ? 2 : 0;\n}\n";
    const CLEAN_NON_SELECTOR: &str = "function pick(flag) {\n  switch (flag) {\n    case true:\n      return 'yes';\n    default:\n      return 'no';\n  }\n}\n";
    const CLEAN_UNUSED_SELECTOR: &str = "function describe(kind) {\n  return kind;\n}\n";

    assert_eq!(count_key(&js_keys(SWITCH_VIOLATION), "javascript:S2301"), 1);

    assert_eq!(
        count_key(&js_keys(COMPARISON_VIOLATION), "javascript:S2301"),
        1
    );

    assert_eq!(
        count_key(&js_keys(CLEAN_NON_SELECTOR), "javascript:S2301"),
        0
    );

    assert_eq!(
        count_key(&js_keys(CLEAN_UNUSED_SELECTOR), "javascript:S2301"),
        0
    );

    // Both catalog scopes carry S2301.
    assert_eq!(count_key(&ts_keys(SWITCH_VIOLATION), "typescript:S2301"), 1);
}
