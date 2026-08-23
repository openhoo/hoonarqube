use std::path::PathBuf;

use super::{AnalyzerOptions, analyze};

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

#[test]
fn parsing_errors_are_recovered_from_tolerantly() {
    let report = analyze(
        PathBuf::from("test.py"),
        "def f(:\n    pass",
        &AnalyzerOptions::default(),
    );
    let parsing: Vec<_> = report
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:ParsingError")
        .collect();
    // Ruff 0.0.10 tolerant recovery emits exactly these two errors for
    // this input; the analyzer reports one issue per `errors()` entry.
    assert_eq!(parsing.len(), 2);
    assert!(parsing[0].message.contains("Expected"));
}

#[test]
fn nosonar_comment_is_flagged_case_sensitively() {
    let report = analyze(
        PathBuf::from("test.py"),
        "x = 1  # NOSONAR\nstr(x)\n",
        &AnalyzerOptions::default(),
    );
    assert_eq!(
        report.issues,
        vec![issue(
            "python:NoSonar",
            "Remove this usage of 'NOSONAR'.",
            (1, 7),
            (1, 16),
        )]
    );

    let lowercase = analyze(
        PathBuf::from("test.py"),
        "x = 1  # nosonar\nstr(x)\n",
        &AnalyzerOptions::default(),
    );
    assert!(lowercase.issues.is_empty());
}

#[test]
fn one_statement_per_line_flags_only_second_onwards() {
    let report = analyze(
        PathBuf::from("test.py"),
        "a = 1\nb = 2\nc = 3; d = 4\n",
        &AnalyzerOptions::default(),
    );
    assert_eq!(
        report.issues,
        vec![
            issue(
                "python:S1481",
                "Remove this unused local variable 'a'.",
                (1, 0),
                (1, 1),
            ),
            issue(
                "python:S1481",
                "Remove this unused local variable 'b'.",
                (2, 0),
                (2, 1),
            ),
            issue(
                "python:S1481",
                "Remove this unused local variable 'c'.",
                (3, 0),
                (3, 1),
            ),
            issue(
                "python:S1481",
                "Remove this unused local variable 'd'.",
                (3, 7),
                (3, 8),
            ),
            issue(
                "python:OneStatementPerLine",
                "Only one statement per line is allowed.",
                (3, 7),
                (3, 12),
            ),
        ]
    );
}
#[test]
fn line_length_honors_option() {
    let long_121 = format!("x = {}\nstr(x)\n", "1".repeat(117));
    // 4 + 117 content characters on line 1, plus a short reader line.
    assert_eq!(
        long_121.lines().next().map(str::chars).map(Iterator::count),
        Some(121)
    );
    let report = analyze(
        PathBuf::from("test.py"),
        &long_121,
        &AnalyzerOptions::default(),
    );
    assert_eq!(report.issues.len(), 1);
    assert_eq!(report.issues[0].rule_key, "python:LineLength");
    assert_eq!(report.issues[0].range.start, pos(1, 0));
    assert_eq!(report.issues[0].range.end, pos(1, 121));

    let long_120 = format!("x = {}\nstr(x)\n", "1".repeat(116));
    let clean = analyze(
        PathBuf::from("test.py"),
        &long_120,
        &AnalyzerOptions::default(),
    );
    assert!(clean.issues.is_empty());

    let strict = AnalyzerOptions {
        maximum_line_length: 10,
        ..AnalyzerOptions::default()
    };
    let flagged = analyze(PathBuf::from("test.py"), "x = 12345678\nstr(x)\n", &strict);
    assert_eq!(flagged.issues.len(), 1);
    assert_eq!(
        flagged.issues[0].message,
        "This line exceeds the maximum allowed length of 10 characters."
    );
}

#[test]
fn exec_and_print_calls_are_flagged_but_not_attributes() {
    let source = "exec(\"x\")\nprint(\"y\")\nmy_print(\"z\")\nmy_exec(\"w\")\n";
    let report = analyze(
        PathBuf::from("test.py"),
        source,
        &AnalyzerOptions::default(),
    );
    assert_eq!(
        report
            .issues
            .iter()
            .map(|issue| issue.rule_key.as_str())
            .collect::<Vec<_>>(),
        vec!["python:ExecStatementUsage", "python:PrintStatementUsage"]
    );
}

#[test]
fn metrics_count_code_comment_and_blank_lines() {
    let report = analyze(
        PathBuf::from("test.py"),
        "x = 1\n# only a comment\n\n",
        &AnalyzerOptions::default(),
    );
    assert_eq!(
        report.metrics,
        hoonarqube_ir::FileMetrics {
            lines: 3,
            code_lines: 1,
            comment_lines: 1,
        }
    );
}

#[test]
fn issue_positions_are_one_based_line_zero_based_column() {
    let report = analyze(
        PathBuf::from("test.py"),
        "if x:\n  exec(y)\n",
        &AnalyzerOptions::default(),
    );
    let exec_issues: Vec<_> = report
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:ExecStatementUsage")
        .collect();
    assert_eq!(exec_issues.len(), 1);
    assert_eq!(exec_issues[0].range.start, pos(2, 2));
}

#[test]
fn integration_assembles_full_report_sorted() {
    let source = concat!(
        "import os\n",
        "\n",
        "def greet(name):\n",
        "    # greeting comment\n",
        "    print(\"hello\")\n",
        "    x = 1; y = 2\n",
        "    if name:\n",
        "        exec(\"z = 1\")\n",
        "\n",
        "greet(\"world\")  # NOSONAR here\n",
    );
    let report = analyze(
        PathBuf::from("demo.py"),
        source,
        &AnalyzerOptions::default(),
    );
    assert_eq!(
        report,
        hoonarqube_ir::FileReport {
            path: PathBuf::from("demo.py"),
            language: "python".to_string(),
            issues: vec![
                issue(
                    "python:S1720",
                    "Add a docstring to this function.",
                    (3, 4),
                    (3, 9),
                ),
                issue(
                    "python:PrintStatementUsage",
                    "Remove this usage of 'print'.",
                    (5, 4),
                    (5, 9),
                ),
                issue(
                    "python:OneStatementPerLine",
                    "Only one statement per line is allowed.",
                    (6, 11),
                    (6, 16),
                ),
                issue(
                    "python:ExecStatementUsage",
                    "Remove this usage of 'exec'.",
                    (8, 8),
                    (8, 12),
                ),
                issue(
                    "python:NoSonar",
                    "Remove this usage of 'NOSONAR'.",
                    (10, 16),
                    (10, 30),
                ),
            ],
            metrics: hoonarqube_ir::FileMetrics {
                lines: 10,
                code_lines: 7,
                comment_lines: 1,
            },
        }
    );
}
#[test]
fn file_must_end_with_newline() {
    let missing = analyze(PathBuf::from("t.py"), "x = 1", &AnalyzerOptions::default());
    let newline_issues: Vec<_> = missing
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:S113")
        .collect();
    assert_eq!(newline_issues.len(), 1);
    assert_eq!(
        newline_issues[0].message,
        "Add a newline character at the end of this file."
    );
    assert_eq!(newline_issues[0].range.start, pos(1, 0));
    assert_eq!(newline_issues[0].range.end, pos(1, 5));
    assert!(
        analyze(PathBuf::from("t.py"), "", &AnalyzerOptions::default())
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S113")
    );
    assert!(
        analyze(
            PathBuf::from("t.py"),
            "x = 1\n",
            &AnalyzerOptions::default()
        )
        .issues
        .iter()
        .all(|issue| issue.rule_key != "python:S113")
    );
}

#[test]
fn trailing_whitespace_is_flagged_per_line() {
    let report = analyze(
        PathBuf::from("t.py"),
        "a \nb\t\nc\n",
        &AnalyzerOptions::default(),
    );
    let flagged: Vec<_> = report
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:S1131")
        .collect();
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start, pos(1, 1));
    assert_eq!(flagged[0].range.end, pos(1, 2));
    assert_eq!(flagged[1].range.start, pos(2, 1));
    assert_eq!(flagged[1].range.end, pos(2, 2));
}

#[test]
fn todo_and_fixme_tags_are_tracked_with_person_reference() {
    let report = analyze(
        PathBuf::from("t.py"),
        "# FIXME fix later\n# TODO (jane) improve\n",
        &AnalyzerOptions::default(),
    );
    assert_eq!(
        report.issues,
        vec![
            issue(
                "python:S1134",
                "Resolve this FIXME comment or clarify it with a person reference.",
                (1, 0),
                (1, 17),
            ),
            issue(
                "python:S1707",
                "Add a person reference such as '(jane)' to this TODO/FIXME comment.",
                (1, 0),
                (1, 17),
            ),
            issue(
                "python:S1135",
                "Resolve this TODO comment or clarify it with a person reference.",
                (2, 0),
                (2, 21),
            ),
        ]
    );
}

#[test]
fn noqa_comments_are_tracked_and_validated() {
    let well_formed = ["# noqa", "# noqa: E501", "# noqa: E501,F841"];
    for source in well_formed {
        let report = analyze(
            PathBuf::from("t.py"),
            &format!("{source}\n"),
            &AnalyzerOptions::default(),
        );
        assert_eq!(report.issues.len(), 1, "source: {source}");
        assert_eq!(report.issues[0].rule_key, "python:S1309");
    }
    for source in ["#noqa", "# noqa : E501", "# noqa: e501"] {
        let report = analyze(
            PathBuf::from("t.py"),
            &format!("{source}\n"),
            &AnalyzerOptions::default(),
        );
        let keys: Vec<_> = report
            .issues
            .iter()
            .map(|issue| issue.rule_key.as_str())
            .collect();
        assert_eq!(
            keys,
            vec!["python:S1309", "python:S7632"],
            "source: {source}"
        );
    }
}

#[test]
fn license_header_is_enforced_only_when_configured() {
    let options = AnalyzerOptions {
        copyright_header_format: "Copyright 2026".to_string(),
        ..AnalyzerOptions::default()
    };
    assert!(
        analyze(
            PathBuf::from("t.py"),
            "# Copyright 2026\nfor _ in []:\n    _ = None\n",
            &options
        )
        .issues
        .is_empty()
    );
    assert!(
        analyze(
            PathBuf::from("t.py"),
            "#!/usr/bin/env python3\n# Copyright 2026\nfor _ in []:\n    _ = None\n",
            &options
        )
        .issues
        .is_empty()
    );
    let missing = analyze(
        PathBuf::from("t.py"),
        "for _ in []:\n    _ = None\n",
        &options,
    );
    assert_eq!(
        missing.issues,
        vec![issue(
            "python:S1451",
            "Add or update the copyright header of this file.",
            (1, 0),
            (1, 0)
        )]
    );
    assert!(
        analyze(
            PathBuf::from("t.py"),
            "for _ in []:\n    _ = None\n",
            &AnalyzerOptions::default()
        )
        .issues
        .is_empty()
    );
}

#[test]
fn module_names_must_follow_convention() {
    let flagged = analyze(
        PathBuf::from("my-mod.py"),
        "x = 1\n",
        &AnalyzerOptions::default(),
    );
    assert_eq!(
        flagged
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "python:S1578")
            .count(),
        1
    );
    for name in ["good_mod.py", "GoodMod.py", "__init__.py"] {
        assert!(
            analyze(PathBuf::from(name), "x = 1\n", &AnalyzerOptions::default())
                .issues
                .iter()
                .all(|issue| issue.rule_key != "python:S1578"),
            "name: {name}"
        );
    }
}

fn findings<'a>(report: &'a hoonarqube_ir::FileReport, key: &str) -> Vec<&'a hoonarqube_ir::Issue> {
    report
        .issues
        .iter()
        .filter(|issue| issue.rule_key == key)
        .collect()
}

fn scan(source: &str) -> hoonarqube_ir::FileReport {
    analyze(PathBuf::from("t.py"), source, &AnalyzerOptions::default())
}

#[test]
fn s2772_flags_only_redundant_pass() {
    let flagged = scan("def f():\n    pass\n    return 1\n");
    let found = findings(&flagged, "python:S2772");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 2);
    for clean in ["def f():\n    pass\n", "class A:\n    pass\n    x = 1\n"] {
        assert!(
            findings(&scan(clean), "python:S2772").is_empty(),
            "clean: {clean}"
        );
    }
}

#[test]
fn s2823_requires_string_literals_in_dunder_all() {
    let flagged = scan("__all__ = [\"a\", b]\n");
    let found = findings(&flagged, "python:S2823");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 1);
    for clean in ["__all__ = [\"a\", \"b\"]\n", "__all__ += [\"c\"]\n"] {
        assert!(findings(&scan(clean), "python:S2823").is_empty(), "{clean}");
    }
}

#[test]
fn s2836_flags_loop_else_without_break() {
    let flagged = scan("while x:\n    drain()\nelse:\n    close()\n");
    let found = findings(&flagged, "python:S2836");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 4);
    let clean = "while x:\n    if done(x):\n        break\nelse:\n    close()\n";
    assert!(findings(&scan(clean), "python:S2836").is_empty());
}

#[test]
fn s3358_flags_nested_conditional_expressions() {
    let flagged = scan("v = a if b else c if d else e\n");
    assert_eq!(findings(&flagged, "python:S3358").len(), 1);
    assert!(findings(&scan("v = a if b else e\n"), "python:S3358").is_empty());
}

#[test]
fn s3626_flags_trailing_jump_statements() {
    let cases = [
        ("def f():\n    setup()\n    return\n", 3),
        ("for i in xs:\n    step(i)\n    continue\n", 3),
        ("match x:\n    case 1:\n        break\n", 3),
    ];
    for (source, line) in cases {
        let report = scan(source);
        let found = findings(&report, "python:S3626");
        assert_eq!(found.len(), 1, "{source}");
        assert_eq!(found[0].range.start.line, line);
    }
    let clean = "def f():\n    if a:\n        return 0\n    return 1\n";
    assert!(findings(&scan(clean), "python:S3626").is_empty());
}

#[test]
fn s3923_flags_identical_if_else_branches() {
    let flagged = scan("if a:\n    run()\nelse:\n    run()\n");
    assert_eq!(findings(&flagged, "python:S3923").len(), 1);
    let clean = "if a:\n    run()\nelse:\n    walk()\n";
    assert!(findings(&scan(clean), "python:S3923").is_empty());
}

#[test]
fn s3981_len_zero_comparison_table() {
    for source in [
        "if len(xs) >= 0:\n    show()\n",
        "if 0 <= len(xs):\n    show()\n",
    ] {
        assert_eq!(findings(&scan(source), "python:S3981").len(), 1, "{source}");
    }
    for clean in [
        "if len(xs) == 0:\n    show()\n",
        "if len(xs) < 5:\n    show()\n",
    ] {
        assert!(findings(&scan(clean), "python:S3981").is_empty(), "{clean}");
    }
}

#[test]
fn s1763_flags_statements_after_terminator() {
    let flagged = scan("def f():\n    return 1\n    print(x)\n    y()\n");
    let found = findings(&flagged, "python:S1763");
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].range.start.line, 3);
    assert_eq!(found[1].range.start.line, 4);
    let clean = "def f():\n    if a:\n        return 1\n    return 2\n";
    assert!(findings(&scan(clean), "python:S1763").is_empty());
}

#[test]
fn s1764_flags_identical_operands_except_small_ints() {
    assert_eq!(findings(&scan("z = x - x\n"), "python:S1764").len(), 1);
    assert_eq!(findings(&scan("q = x == x\n"), "python:S1764").len(), 1);
    for clean in ["z = x * 2\n", "q = 1 - 1\n"] {
        assert!(findings(&scan(clean), "python:S1764").is_empty(), "{clean}");
    }
}

#[test]
fn s1862_flags_duplicate_conditions_in_chain() {
    let flagged = scan("if a == 1:\n    f()\nelif a == 1:\n    g()\n");
    let found = findings(&flagged, "python:S1862");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 3);
    let clean = "if a == 1:\n    f()\nelif a == 2:\n    g()\n";
    assert!(findings(&scan(clean), "python:S1862").is_empty());
}

#[test]
fn s1871_flags_duplicate_branch_bodies() {
    let chain = scan("if a == 1:\n    do(x)\nelif a == 2:\n    do(x)\n");
    let found = findings(&chain, "python:S1871");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 4);
    let handlers = scan("try:\n    risky()\nexcept A:\n    handle()\nexcept B:\n    handle()\n");
    assert_eq!(findings(&handlers, "python:S1871").len(), 1);
    let clean = "if a == 1:\n    do(x)\nelif a == 2:\n    do(y)\n";
    assert!(findings(&scan(clean), "python:S1871").is_empty());
}

#[test]
fn s1940_flags_negated_comparisons() {
    assert_eq!(
        findings(&scan("ok = not (a == b)\n"), "python:S1940").len(),
        1
    );
    assert!(findings(&scan("fine = not (a and b)\n"), "python:S1940").is_empty());
}

#[test]
fn s1656_flags_self_assignment() {
    assert_eq!(findings(&scan("x = x\n"), "python:S1656").len(), 1);
    assert_eq!(findings(&scan("x.y = x.y\n"), "python:S1656").len(), 1);
    assert!(findings(&scan("x = y\n"), "python:S1656").is_empty());
}

#[test]
fn s2208_flags_wildcard_imports() {
    assert_eq!(
        findings(&scan("from m import *\n"), "python:S2208").len(),
        1
    );
    assert!(findings(&scan("from m import thing\n"), "python:S2208").is_empty());
}

#[test]
fn s2761_flags_doubled_prefix_operators() {
    assert_eq!(
        findings(&scan("b = not not flag\n"), "python:S2761").len(),
        1
    );
    assert_eq!(findings(&scan("c = ~~bits\n"), "python:S2761").len(), 1);
    assert!(findings(&scan("flip = -(-amount)\n"), "python:S2761").is_empty());
}

#[test]
fn s5685_flags_confusing_walrus_positions() {
    assert_eq!(
        findings(&scan("vals = [y := get(y) for y in ys]\n"), "python:S5685").len(),
        1
    );
    assert_eq!(
        findings(&scan("mid = a < (b := c) < d\n"), "python:S5685").len(),
        1
    );
    assert!(
        findings(
            &scan("kept = [y for y in ys if (mark := y)]\n"),
            "python:S5685"
        )
        .is_empty()
    );
}

#[test]
fn s5727_flags_constant_none_comparisons() {
    assert_eq!(
        findings(&scan("same = None == None\n"), "python:S5727").len(),
        1
    );
    assert_eq!(
        findings(&scan("odd = \"x\" == None\n"), "python:S5727").len(),
        1
    );
    assert!(findings(&scan("maybe = x == None\n"), "python:S5727").is_empty());
}

#[test]
fn s5796_flags_identity_on_fresh_objects() {
    assert_eq!(
        findings(&scan("never = [] is []\n"), "python:S5796").len(),
        1
    );
    assert_eq!(
        findings(&scan("fresh = list() is other\n"), "python:S5796").len(),
        1
    );
    assert!(findings(&scan("ref = a is b\n"), "python:S5796").is_empty());
}

#[test]
fn s5905_flags_nonempty_tuple_assertions() {
    let flagged = scan("assert (False, \"why\")\n");
    assert_eq!(findings(&flagged, "python:S5905").len(), 1);
    for clean in ["assert ()\n", "assert condition\n"] {
        assert!(findings(&scan(clean), "python:S5905").is_empty(), "{clean}");
    }
}

#[test]
fn s6660_prefers_isinstance_over_type_equality() {
    assert_eq!(
        findings(&scan("exact = type(x) is int\n"), "python:S6660").len(),
        1
    );
    assert!(findings(&scan("safe = isinstance(x, int)\n"), "python:S6660").is_empty());
}

#[test]
fn s6661_flags_lambdas_assigned_to_names() {
    assert_eq!(
        findings(&scan("handler = lambda e: str(e)\n"), "python:S6661").len(),
        1
    );
    assert!(
        findings(
            &scan("def handler(e):\n    return str(e)\n"),
            "python:S6661"
        )
        .is_empty()
    );
}

#[test]
fn s6659_prefers_startswith_endswith_over_slices() {
    assert_eq!(
        findings(&scan("head = name[:2] == \"ab\"\n"), "python:S6659").len(),
        1
    );
    assert_eq!(
        findings(&scan("tail = name[-2:] == \"cd\"\n"), "python:S6659").len(),
        1
    );
    assert!(findings(&scan("mid = name[1:2] == \"b\"\n"), "python:S6659").is_empty());
}

#[test]
fn s1244_flags_exact_float_equality_only() {
    assert_eq!(
        findings(&scan("close = 0.1 + 0.2 == 0.3\n"), "python:S1244").len(),
        1
    );
    for clean in ["cmp = 0.1 < 0.2\n", "ieq = 1 == 2\n"] {
        assert!(findings(&scan(clean), "python:S1244").is_empty(), "{clean}");
    }
}

#[test]
fn s905_flags_pure_expression_statements_but_not_docstrings() {
    let flagged = scan("\"\"\"Module doc.\"\"\"\n42\nx == 1\nrun(x)\n");
    let found = findings(&flagged, "python:S905");
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].range.start.line, 2);
    assert_eq!(found[1].range.start.line, 3);
}

#[test]
fn s2733_checks_exit_signature_completeness() {
    let flagged = scan("class C:\n    def __exit__(self, kind, value):\n        return False\n");
    assert_eq!(findings(&flagged, "python:S2733").len(), 1);
    let clean = "class C:\n    def __exit__(self, kind, value, trace):\n        return False\n";
    assert!(findings(&scan(clean), "python:S2733").is_empty());
}

#[test]
fn s2734_flags_init_returning_value() {
    let flagged = scan("class C:\n    def __init__(self):\n        self.x = 1\n        return 5\n");
    let found = findings(&flagged, "python:S2734");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 4);
    let clean = "class C:\n    def __init__(self):\n        self.x = 1\n        return None\n";
    assert!(findings(&scan(clean), "python:S2734").is_empty());
}

#[test]
fn s2737_flags_handlers_that_only_reraise() {
    let flagged = scan("try:\n    risky()\nexcept ValueError:\n    raise\n");
    assert_eq!(findings(&flagged, "python:S2737").len(), 1);
    let clean = "try:\n    risky()\nexcept ValueError:\n    log()\n    raise\n";
    assert!(findings(&scan(clean), "python:S2737").is_empty());
}

#[test]
fn s5712_prefers_returning_notimplemented() {
    let flagged =
        scan("class P:\n    def __eq__(self, other):\n        raise NotImplementedError\n");
    assert_eq!(findings(&flagged, "python:S5712").len(), 1);
    let clean = "class P:\n    def __eq__(self, other):\n        return NotImplemented\n";
    assert!(findings(&scan(clean), "python:S5712").is_empty());
}

#[test]
fn s5719_requires_positional_parameter_on_methods() {
    let flagged = scan("class C:\n    def method():\n        return 1\n");
    assert_eq!(findings(&flagged, "python:S5719").len(), 1);
    let static_clean = "class C:\n    @staticmethod\n    def util():\n        return 1\n";
    assert!(findings(&scan(static_clean), "python:S5719").is_empty());
    let bound_clean = "class C:\n    def method(self):\n        return 1\n";
    assert!(findings(&scan(bound_clean), "python:S5719").is_empty());
}

#[test]
fn s5720_requires_self_first_for_instance_methods() {
    let flagged = scan("class C:\n    def show(this_one):\n        return this_one\n");
    assert_eq!(findings(&flagged, "python:S5720").len(), 1);
    let classmethod_clean = "class C:\n    @classmethod\n    def build(cls):\n        return cls\n";
    assert!(findings(&scan(classmethod_clean), "python:S5720").is_empty());
}

#[test]
fn s5722_flags_missing_special_method_parameters() {
    let flagged = scan("class C:\n    def __lt__(self):\n        return NotImplemented\n");
    assert_eq!(findings(&flagged, "python:S5722").len(), 1);
    let clean = "class C:\n    def __lt__(self, other):\n        return NotImplemented\n";
    assert!(findings(&scan(clean), "python:S5722").is_empty());
}

#[test]
fn s5724_checks_property_accessor_arity_exactly() {
    let flagged = scan("class C:\n    @property\n    def size(self, extra):\n        return 1\n");
    assert_eq!(findings(&flagged, "python:S5724").len(), 1);
    for clean in [
        "class C:\n    @property\n    def size(self):\n        return 1\n",
        "class C:\n    @size.setter\n    def size(self, value):\n        self._size = value\n",
    ] {
        assert!(findings(&scan(clean), "python:S5724").is_empty(), "{clean}");
    }
}

#[test]
fn s5709_requires_exception_base_for_exception_named_classes() {
    assert_eq!(
        findings(&scan("class AppError:\n    pass\n"), "python:S5709").len(),
        1
    );
    for clean in [
        "class AppError(Exception):\n    pass\n",
        "class Plain:\n    pass\n",
    ] {
        assert!(findings(&scan(clean), "python:S5709").is_empty(), "{clean}");
    }
}

#[test]
fn s5714_flags_boolean_except_specifications() {
    let flagged = scan("try:\n    run()\nexcept (A or B):\n    stop()\n");
    assert_eq!(findings(&flagged, "python:S5714").len(), 1);
    let clean = "try:\n    run()\nexcept (A, B):\n    stop()\n";
    assert!(findings(&scan(clean), "python:S5714").is_empty());
}

#[test]
fn s5704_and_s5747_classify_bare_raise_by_context() {
    let in_finally = scan(
        "def f():\n    try:\n        work()\n    finally:\n        cleanup()\n        raise\n",
    );
    assert_eq!(findings(&in_finally, "python:S5704").len(), 1);
    let outside = scan("def f():\n    if ready:\n        raise\n");
    assert_eq!(findings(&outside, "python:S5747").len(), 1);
    let in_except = scan("try:\n    work()\nexcept ValueError:\n    raise\n");
    assert!(findings(&in_except, "python:S5704").is_empty());
    assert!(findings(&in_except, "python:S5747").is_empty());
}

#[test]
fn s1143_flags_jump_statements_inside_finally() {
    let flagged = scan("def f():\n    try:\n        load()\n    finally:\n        return 1\n");
    assert_eq!(findings(&flagged, "python:S1143").len(), 1);
    let clean = "def f():\n    try:\n        load()\n    finally:\n        release()\n";
    assert!(findings(&scan(clean), "python:S1143").is_empty());
}

#[test]
fn s1716_flags_break_continue_without_enclosing_loop() {
    assert_eq!(
        findings(&scan("def f():\n    break\n"), "python:S1716").len(),
        1
    );
    let clean = "for _ in xs:\n    break\n";
    assert!(findings(&scan(clean), "python:S1716").is_empty());
}

#[test]
fn s5706_flags_exit_reraising_its_arguments() {
    let flagged = scan(concat!(
        "class C:\n",
        "    def __exit__(self, kind, value, trace):\n",
        "        cleanup(value)\n",
        "        raise value\n"
    ));
    assert_eq!(findings(&flagged, "python:S5706").len(), 1);
    let clean = concat!(
        "class C:\n",
        "    def __exit__(self, kind, value, trace):\n",
        "        cleanup(value)\n",
        "        return False\n"
    );
    assert!(findings(&scan(clean), "python:S5706").is_empty());
}

#[test]
fn s5754_requires_systemexit_reraise() {
    let flagged = scan("try:\n    run_app()\nexcept SystemExit:\n    cleanup()\n");
    assert_eq!(findings(&flagged, "python:S5754").len(), 1);
    let clean = "try:\n    run_app()\nexcept ValueError:\n    cleanup()\n";
    assert!(findings(&scan(clean), "python:S5754").is_empty());
}

#[test]
fn s1515_flags_closures_capturing_loop_variables() {
    let flagged = scan("callbacks = []\nfor i in range(3):\n    callbacks.append(lambda: i)\n");
    let found = findings(&flagged, "python:S1515");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 3);
    let clean = "callbacks = []\nfor i in range(3):\n    callbacks.append(lambda v: v)\n";
    assert!(findings(&scan(clean), "python:S1515").is_empty());
}

#[test]
fn s2710_requires_cls_naming_for_classmethods() {
    let flagged = scan("class C:\n    @classmethod\n    def make(other):\n        return other\n");
    assert_eq!(findings(&flagged, "python:S2710").len(), 1);
    let clean = "class C:\n    @classmethod\n    def make(cls):\n        return cls\n";
    assert!(findings(&scan(clean), "python:S2710").is_empty());
}

#[test]
fn s2711_flags_yield_outside_functions() {
    let flagged = scan("yield 1\n");
    assert_eq!(findings(&flagged, "python:S2711").len(), 1);
    let clean = "def g():\n    yield 1\n";
    assert!(findings(&scan(clean), "python:S2711").is_empty());
}

#[test]
fn s2712_flags_generator_returning_value() {
    let flagged = scan("def gen():\n    yield 1\n    return 5\n");
    let found = findings(&flagged, "python:S2712");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 3);
    let clean = "def gen():\n    yield 1\n    return\n";
    assert!(findings(&scan(clean), "python:S2712").is_empty());
}

#[test]
fn s5899_flags_test_methods_runners_cannot_discover() {
    let flagged = scan("class T(TestCase):\n    def my_test(self):\n        pass\n");
    assert_eq!(findings(&flagged, "python:S5899").len(), 1);
    for clean in [
        "class T(TestCase):\n    def test_it(self):\n        pass\n",
        "class U:\n    def my_test(self):\n        pass\n",
    ] {
        assert!(findings(&scan(clean), "python:S5899").is_empty(), "{clean}");
    }
}

#[test]
fn s5915_flags_unittest_assertion_closing_except_block() {
    let flagged =
        scan("try:\n    parse(raw)\nexcept ValueError:\n    self.assertEqual(got, want)\n");
    assert_eq!(findings(&flagged, "python:S5915").len(), 1);
    let clean = "try:\n    parse(raw)\nexcept ValueError:\n    log(got)\nassert want == got\n";
    assert!(findings(&scan(clean), "python:S5915").is_empty());
}

#[test]
fn s5780_flags_duplicate_dict_literal_keys() {
    let flagged = scan("cfg = {\"retries\": 1, \"retries\": 2}\n");
    assert_eq!(findings(&flagged, "python:S5780").len(), 1);
    let clean = "cfg = {\"retries\": 1, \"timeout\": 2}\n";
    assert!(findings(&scan(clean), "python:S5780").is_empty());
}

#[test]
fn s5781_flags_duplicate_set_literal_elements() {
    assert_eq!(
        findings(&scan("singles = {1, 1}\n"), "python:S5781").len(),
        1
    );
    assert!(findings(&scan("pair = {1, 2}\n"), "python:S5781").is_empty());
}

#[test]
fn s7498_prefers_literal_syntax_for_empty_collections() {
    let flagged = scan("empty = dict()\nnamed = dict(a=1)\nseq = list()\n");
    assert_eq!(findings(&flagged, "python:S7498").len(), 3);
    for clean in ["first = {}\n", "second = []\n"] {
        assert!(findings(&scan(clean), "python:S7498").is_empty(), "{clean}");
    }
}

#[test]
fn s7496_flags_redundant_wrapping_constructors() {
    let flagged = scan(
        "wrapped = list([1, 2])\nsets = set({1})\nmaps = dict({\"a\": 1})\nconv = list((4, 5))\nstr(conv)\n",
    );
    assert_eq!(findings(&flagged, "python:S7496").len(), 3);
    // The tuple conversion is a real type change and stays unflagged.
    assert_eq!(
        flagged
            .issues
            .iter()
            .filter(|i| i.range.start.line == 4)
            .count(),
        0
    );
}

#[test]
fn s7494_prefers_comprehension_over_wrapped_generator() {
    assert_eq!(
        findings(&scan("evens = list(x for x in xs)\n"), "python:S7494").len(),
        1
    );
    assert!(findings(&scan("odds = [x for x in xs]\n"), "python:S7494").is_empty());
}

#[test]
fn s7500_flags_only_element_renaming_comprehensions() {
    assert_eq!(
        findings(&scan("copy = [item for item in items]\n"), "python:S7500").len(),
        1
    );
    for clean in [
        "shaped = [render(item) for item in items]\n",
        "kept = [item for item in items if item]\n",
    ] {
        assert!(findings(&scan(clean), "python:S7500").is_empty(), "{clean}");
    }
}

#[test]
fn s7504_flags_iteration_over_list_wrapped_iterable() {
    let flagged = scan("for item in list(items):\n    show(item)\n");
    assert_eq!(findings(&flagged, "python:S7504").len(), 1);
    let clean = "for item in items:\n    show(item)\n";
    assert!(findings(&scan(clean), "python:S7504").is_empty());
}

#[test]
fn s7505_flags_map_calls_with_lambda() {
    assert_eq!(
        findings(
            &scan("doubled = map(lambda v: v * 2, values)\n"),
            "python:S7505"
        )
        .len(),
        1
    );
    assert!(findings(&scan("names = map(str, values)\n"), "python:S7505").is_empty());
}

#[test]
fn s7506_prefers_fromkeys_for_constant_values() {
    assert_eq!(
        findings(
            &scan("labels = {k: \"default\" for k in keys}\n"),
            "python:S7506"
        )
        .len(),
        1
    );
    assert!(
        findings(
            &scan("computed = {k: render(k) for k in keys}\n"),
            "python:S7506"
        )
        .is_empty()
    );
}

#[test]
fn s7507_flags_defaultdict_default_factory_keyword() {
    assert_eq!(
        findings(
            &scan("registry = defaultdict(default_factory=list)\n"),
            "python:S7507"
        )
        .len(),
        1
    );
    assert!(findings(&scan("registry = defaultdict(list)\n"), "python:S7507").is_empty());
}

#[test]
fn s7508_flags_nested_identical_constructors() {
    assert_eq!(
        findings(&scan("twice = list(list(rows))\n"), "python:S7508").len(),
        1
    );
    assert!(findings(&scan("mixed = list(set(rows))\n"), "python:S7508").is_empty());
}

#[test]
fn s7510_prefers_reverse_sorting_in_place() {
    assert_eq!(
        findings(
            &scan("descending = reversed(sorted(scores))\n"),
            "python:S7510"
        )
        .len(),
        1
    );
    assert!(
        findings(
            &scan("top = sorted(scores, reverse=True)\n"),
            "python:S7510"
        )
        .is_empty()
    );
}

#[test]
fn s7511_flags_discarded_and_doubled_reversed_calls() {
    let flagged = scan(concat!(
        "lost = set(reversed(stream))\n",
        "kept = sorted(reversed(stream))\n",
        "twice = reversed(reversed(path))\n",
        "meaningful = reversed(sorted(path))\n"
    ));
    let found = findings(&flagged, "python:S7511");
    assert_eq!(found.len(), 3);
    assert_eq!(
        found
            .iter()
            .map(|issue| issue.range.start.line)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
}

#[test]
fn s7516_flags_sorting_before_set_construction() {
    assert_eq!(
        findings(&scan("unique = set(sorted(entries))\n"), "python:S7516").len(),
        1
    );
    assert!(findings(&scan("ordered = list(sorted(entries))\n"), "python:S7516").is_empty());
}

#[test]
fn s7517_flags_manual_key_lookups_by_loop_variable() {
    let flagged = scan("for k in prices:\n    total[k] = prices[k]\n");
    let found = findings(&flagged, "python:S7517");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 2);
    let clean = "for k in prices:\n    show(k)\n";
    assert!(findings(&scan(clean), "python:S7517").is_empty());
}

#[test]
fn s7519_prefers_fromkeys_for_constant_loops() {
    let flagged = scan("flags = {}\nfor name in nodes:\n    flags[name] = True\n");
    let found = findings(&flagged, "python:S7519");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 2);
    let clean = "sizes = {}\nfor name in nodes:\n    sizes[name] = len(name)\n";
    assert!(findings(&scan(clean), "python:S7519").is_empty());
}

#[test]
fn s7512_flags_items_pairs_when_only_keys_used() {
    let flagged = scan("for key, value in record.items():\n    audit(key)\n");
    assert_eq!(findings(&flagged, "python:S7512").len(), 1);
    let clean = "for key, value in record.items():\n    audit(key, value)\n";
    assert!(findings(&scan(clean), "python:S7512").is_empty());
}

#[test]
fn s1192_flags_duplicated_literals_only_past_threshold() {
    let flagged = scan("a = \"dup\"\nb = \"dup\"\nc = \"dup\"\n");
    assert_eq!(findings(&flagged, "python:S1192").len(), 2);
    assert!(findings(&scan("a = \"dup\"\nb = \"dup\"\n"), "python:S1192").is_empty());
}

#[test]
fn s1192_exclusion_regex_suppresses_matches() {
    let options = AnalyzerOptions {
        duplicate_literal_exclusion_regex: "dup".to_string(),
        ..AnalyzerOptions::default()
    };
    let report = analyze(
        PathBuf::from("t.py"),
        "a = \"dup\"\nb = \"dup\"\nc = \"dup\"\n",
        &options,
    );
    assert!(findings(&report, "python:S1192").is_empty());
}

#[test]
fn s5828_flags_invalid_open_modes_only() {
    let flagged = scan("open(\"d\", \"q\")\nopen(\"d\", mode=\"rr\")\nopen(\"d\", \"rb\")\n");
    assert_eq!(findings(&flagged, "python:S5828").len(), 2);
}

#[test]
fn s4790_flags_weak_hashes_unless_not_used_for_security() {
    let flagged = scan(concat!(
        "hashlib.md5(b\"x\")\n",
        "hashlib.new(\"sha1\")\n",
        "hashlib.sha1(b\"y\", usedforsecurity=False)\n"
    ));
    assert_eq!(findings(&flagged, "python:S4790").len(), 2);
}

#[test]
fn s5445_flags_insecure_temp_file_apis() {
    let flagged = scan("import tempfile\ntempfile.mktemp()\nos.tmpnam()\n");
    assert_eq!(findings(&flagged, "python:S5445").len(), 2);
}

#[test]
fn s5042_requires_members_filter_on_extractall() {
    let flagged = scan(concat!(
        "tarfile.open(\"a\").extractall()\n",
        "tarfile.open(\"b\").extractall(members=[])\n"
    ));
    assert_eq!(findings(&flagged, "python:S5042").len(), 1);
}

#[test]
fn s4507_flags_debug_hooks_and_debug_flags() {
    let flagged = scan("breakpoint()\npdb.set_trace()\nrun(app, debug=True)\n");
    assert_eq!(findings(&flagged, "python:S4507").len(), 3);
}

#[test]
fn s5361_flags_metacharacter_free_re_sub_patterns() {
    let flagged = scan("re.sub(\"abc\", \"x\", s)\nre.sub(\"a.c\", \"x\", s)\n");
    assert_eq!(findings(&flagged, "python:S5361").len(), 1);
}

#[test]
fn s2612_flags_group_and_world_writable_modes() {
    let flagged = scan("os.chmod(\"f\", 0o777)\nos.chmod(\"g\", 0o644)\npath.chmod(0o664)\n");
    assert_eq!(findings(&flagged, "python:S2612").len(), 2);
}

#[test]
fn s6903_flags_deprecated_utc_helpers() {
    let flagged = scan("datetime.utcnow()\ndatetime.now(tz=None)\n");
    assert_eq!(findings(&flagged, "python:S6903").len(), 1);
}

#[test]
fn s6725_flags_equality_against_numpy_nan() {
    let flagged = scan("if x == np.nan:\n    pass\nif y <= np.nan:\n    pass\n");
    assert_eq!(findings(&flagged, "python:S6725").len(), 1);
}

#[test]
fn s6727_requires_abs_tol_for_zero_comparisons() {
    let flagged = scan(concat!(
        "math.isclose(a, 0)\n",
        "math.isclose(a, b)\n",
        "math.isclose(0, tiny, abs_tol=1e-12)\n"
    ));
    assert_eq!(findings(&flagged, "python:S6727").len(), 1);
}

#[test]
fn s6729_prefers_nonzero_for_single_arg_where() {
    let flagged = scan("np.where(mask)\nnp.where(mask, a, b)\n");
    assert_eq!(findings(&flagged, "python:S6729").len(), 1);
}

#[test]
fn s6730_flags_deprecated_numpy_aliases() {
    let flagged = scan("np.int(x)\nz = np.float_\nq = np.int64\n");
    assert_eq!(findings(&flagged, "python:S6730").len(), 2);
}

#[test]
fn s6711_flags_random_state_usage() {
    let flagged = scan("np.random.RandomState(0)\nrng = np.random.default_rng(0)\n");
    assert_eq!(findings(&flagged, "python:S6711").len(), 1);
}

#[test]
fn s6714_rejects_generators_into_np_array() {
    let flagged = scan("np.array(x for x in xs)\nnp.array([1, 2])\n");
    assert_eq!(findings(&flagged, "python:S6714").len(), 1);
}

#[test]
fn s6734_flags_inplace_pandas_methods() {
    let flagged = scan("df.sort_values(\"a\", inplace=True)\ndf.drop(\"b\", axis=1)\n");
    assert_eq!(findings(&flagged, "python:S6734").len(), 1);
}

#[test]
fn s6735_requires_explicit_merge_keys() {
    let flagged = scan("left.merge(right)\nleft.merge(right, on=\"k\")\n");
    assert_eq!(findings(&flagged, "python:S6735").len(), 1);
}

#[test]
fn s6740_requires_dtype_on_csv_reads() {
    let flagged = scan("pd.read_csv(\"f.csv\")\npd.read_csv(\"f.csv\", dtype={\"a\": int})\n");
    assert_eq!(findings(&flagged, "python:S6740").len(), 1);
}

#[test]
fn s6741_prefers_to_numpy_over_values() {
    let flagged = scan("df = pd.DataFrame({\"a\": [1]})\nv = df.values\nw = qq.values\n");
    assert_eq!(findings(&flagged, "python:S6741").len(), 1);
}

#[test]
fn s6742_flags_long_dataframe_chains() {
    let flagged = scan(concat!(
        "df = pd.DataFrame({\"a\": [1]})\n",
        "r = df.groupby(\"a\").sum().reset_index().dropna()\n",
        "s = df.groupby(\"a\").sum().reset_index()\n"
    ));
    assert_eq!(findings(&flagged, "python:S6742").len(), 1);
}

#[test]
fn s6894_demands_format_when_dayfirst_set() {
    let flagged = scan("pd.to_datetime(col, dayfirst=True)\npd.to_datetime(col, format=\"%Y\")\n");
    assert_eq!(findings(&flagged, "python:S6894").len(), 1);
}

#[test]
fn s6900_validates_weekmask_grammar() {
    let flagged =
        scan("np.busday(day, weekmask=\"1111100\")\nnumpy.busday_count(start, end, \"11111\")\n");
    assert_eq!(findings(&flagged, "python:S6900").len(), 1);
}

#[test]
fn s6882_bounds_datetime_components() {
    let flagged = scan("date(2020, 13, 1)\ndate(2020, 12, 31)\ntime(24, 0)\ntime(23, 59)\n");
    assert_eq!(findings(&flagged, "python:S6882").len(), 2);
}

#[test]
fn s6883_pairs_hour_specifiers_with_ampm() {
    let flagged = scan(concat!(
        "t.strftime(\"%H:%M\")\n",
        "u.strftime(\"%I:%M %p\")\n",
        "v.strftime(\"%I:%M\")\n",
        "w.strftime(\"%H:%M %p\")\n"
    ));
    assert_eq!(findings(&flagged, "python:S6883").len(), 2);
}

#[test]
fn s6887_rejects_pytz_in_datetime_constructor() {
    let flagged = scan(concat!(
        "datetime.datetime(2020, 1, 1, tzinfo=pytz.timezone(\"US/Eastern\"))\n",
        "datetime.datetime(2020, 1, 1, tzinfo=zoneinfo.ZoneInfo(\"X\"))\n"
    ));
    assert_eq!(findings(&flagged, "python:S6887").len(), 1);
}

#[test]
fn s6890_prefers_zoneinfo_over_pytz() {
    let flagged = scan("import pytz\nzone = pytz.timezone(\"UTC\")\n");
    assert_eq!(findings(&flagged, "python:S6890").len(), 1);
}

#[test]
fn s6929_requires_explicit_reduction_axis() {
    let flagged = scan("tf.reduce_sum(x)\ntf.reduce_sum(x, axis=0)\nnp.sum(y)\nnp.sum(y, 0)\n");
    assert_eq!(findings(&flagged, "python:S6929").len(), 2);
}

#[test]
fn s6925_flags_deprecated_gather_argument() {
    let flagged = scan("tf.gather(p, i, validate_indices=True)\ntf.gather(p, i)\n");
    assert_eq!(findings(&flagged, "python:S6925").len(), 1);
}

#[test]
fn s6919_rejects_input_shape_on_model_subclasses() {
    let flagged = scan(concat!(
        "class Net(keras.Model):\n",
        "    def __init__(self):\n",
        "        super().__init__(input_shape=(28,))\n",
        "class Fine(keras.Model):\n",
        "    def __init__(self):\n",
        "        super().__init__()\n"
    ));
    assert_eq!(findings(&flagged, "python:S6919").len(), 1);
}

#[test]
fn s6969_requires_memory_on_pipelines() {
    let flagged = scan("Pipeline(steps)\nPipeline(steps, memory=\"./cache\")\n");
    assert_eq!(findings(&flagged, "python:S6969").len(), 1);
}

#[test]
fn s6973_flags_estimators_missing_required_hyperparameters() {
    let flagged = scan("KMeans(3)\nKMeans(n_clusters=3)\nPCA(4)\nSGDClassifier(max_iter=5)\n");
    assert_eq!(findings(&flagged, "python:S6973").len(), 3);
}

#[test]
fn s6974_flags_trailing_underscore_attributes_in_init() {
    let flagged = scan(concat!(
        "class E(BaseEstimator):\n",
        "    def __init__(self):\n",
        "        self.x_ = 1\n",
        "        self.y = 2\n"
    ));
    assert_eq!(findings(&flagged, "python:S6974").len(), 1);
}

#[test]
fn s6978_requires_super_init_in_module_subclasses() {
    let flagged = scan(concat!(
        "class M(nn.Module):\n",
        "    def __init__(self):\n",
        "        self.layer = 1\n",
        "class Ok(nn.Module):\n",
        "    def __init__(self):\n",
        "        super().__init__()\n"
    ));
    assert_eq!(findings(&flagged, "python:S6978").len(), 1);
}

#[test]
fn s6979_flags_autograd_variable_usage() {
    let flagged = scan("torch.autograd.Variable(x)\n");
    assert_eq!(findings(&flagged, "python:S6979").len(), 1);
}

#[test]
fn s6983_requires_num_workers_on_dataloaders() {
    let flagged = scan("DataLoader(ds, batch_size=2)\nDataLoader(ds, num_workers=4)\n");
    assert_eq!(findings(&flagged, "python:S6983").len(), 1);
}

#[test]
fn s6985_requires_weights_only_on_torch_load() {
    let flagged = scan("torch.load(\"m.pt\")\ntorch.load(\"m.pt\", weights_only=True)\n");
    assert_eq!(findings(&flagged, "python:S6985").len(), 1);
}

#[test]
fn s6984_validates_einops_patterns() {
    let flagged = scan(concat!(
        "rearrange(img, \"b h w -> b w h\")\n",
        "rearrange(img, \"b h -> b w h\")\n",
        "rearrange(img, \"b (h h2 w -> b h w\")\n"
    ));
    assert_eq!(findings(&flagged, "python:S6984").len(), 2);
}

#[test]
fn s6971_flags_named_steps_bypass_on_cached_pipelines() {
    let flagged = scan(concat!(
        "pipe = Pipeline(steps, memory=\"./c\")\n",
        "step = pipe.named_steps[\"s\"]\n",
        "plain = other.named_steps[\"s\"]\n"
    ));
    assert_eq!(findings(&flagged, "python:S6971").len(), 1);
}

#[test]
fn s6553_rejects_null_on_string_fields() {
    let flagged = scan(
        "CharField(max_length=10, null=True)\nCharField(max_length=10)\nIntegerField(null=True)\n",
    );
    assert_eq!(findings(&flagged, "python:S6553").len(), 1);
}

#[test]
fn s6554_requires_str_on_django_models() {
    let flagged = scan(concat!(
        "class Book(models.Model):\n",
        "    title = models.CharField(max_length=5)\n",
        "class Shelf(models.Model):\n",
        "    def __str__(self):\n",
        "        return \"s\"\n"
    ));
    assert_eq!(findings(&flagged, "python:S6554").len(), 1);
}

#[test]
fn s6556_rejects_locals_in_render() {
    let flagged = scan("render(req, \"t.html\", locals())\nrender(req, \"t.html\", {})\n");
    assert_eq!(findings(&flagged, "python:S6556").len(), 1);
}

#[test]
fn s6559_requires_meta_field_declarations() {
    let flagged = scan(concat!(
        "class FormF(forms.ModelForm):\n",
        "    class Meta:\n",
        "        model = M\n",
        "class Good(forms.ModelForm):\n",
        "    class Meta:\n",
        "        fields = [\"a\"]\n"
    ));
    assert_eq!(findings(&flagged, "python:S6559").len(), 1);
}

#[test]
fn s6560_requires_safe_flag_for_non_dict_payloads() {
    let flagged =
        scan("JsonResponse([1, 2])\nJsonResponse({\"a\": 1})\nJsonResponse([1], safe=False)\n");
    assert_eq!(findings(&flagged, "python:S6560").len(), 1);
}

#[test]
fn s6552_requires_route_decorator_outermost() {
    let flagged = scan(concat!(
        "@app.get(\"/x\")\n",
        "@log_call\n",
        "def handler():\n",
        "    return 1\n",
        "@app.get(\"/y\")\n",
        "def good():\n",
        "    return 2\n"
    ));
    assert_eq!(findings(&flagged, "python:S6552").len(), 1);
}

#[test]
fn s6779_flags_disclosed_secret_keys() {
    let flagged = scan("SECRET_KEY = \"hunter2\"\napp.secret_key = \"abc123\"\nDEBUG_KEY = 42\n");
    assert_eq!(findings(&flagged, "python:S6779").len(), 2);
}

#[test]
fn s6781_flags_hardcoded_jwt_secrets() {
    let flagged = scan("jwt.encode(payload, \"secret\")\njwt.encode(payload, key_from_env)\n");
    assert_eq!(findings(&flagged, "python:S6781").len(), 1);
}

#[test]
fn s7483_flags_timeout_parameters_on_async_functions_only() {
    let flagged = scan(concat!(
        "async def fetch(client, timeout_s):\n",
        "    await client.get(\"/\")\n",
        "def sync(timeout_s):\n",
        "    return timeout_s\n"
    ));
    let found = findings(&flagged, "python:S7483");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 1);
}

#[test]
fn s7484_flags_sleep_awaits_inside_async_loops() {
    let flagged = scan(concat!(
        "async def poll(client):\n",
        "    while True:\n",
        "        await asyncio.sleep(1)\n",
        "async def once(client):\n",
        "    await asyncio.sleep(1)\n"
    ));
    let found = findings(&flagged, "python:S7484");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 3);
}

#[test]
fn s7486_flags_only_long_sleeps() {
    let flagged = scan("await asyncio.sleep(59)\nawait asyncio.sleep(60)\n");
    let found = findings(&flagged, "python:S7486");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 2);
}

#[test]
fn s7487_flags_sync_subprocess_in_async_functions() {
    let flagged = scan(concat!(
        "async def run_cmd():\n",
        "    subprocess.run([\"ls\"])\n",
        "    await asyncio.sleep(1)\n"
    ));
    assert_eq!(findings(&flagged, "python:S7487").len(), 1);
}

#[test]
fn s7488_flags_blocking_time_sleep_in_async_functions() {
    let flagged = scan("async def tick():\n    time.sleep(1)\n    await asyncio.sleep(1)\n");
    assert_eq!(findings(&flagged, "python:S7488").len(), 1);
}

#[test]
fn s7489_flags_sync_os_calls_in_async_functions() {
    let flagged = scan("async def sh():\n    os.system(\"ls\")\n    await asyncio.sleep(1)\n");
    assert_eq!(findings(&flagged, "python:S7489").len(), 1);
}

#[test]
fn s7491_prefers_checkpoint_over_sleep_zero() {
    let flagged = scan("await asyncio.sleep(0)\nawait asyncio.sleep(1)\n");
    let found = findings(&flagged, "python:S7491");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 1);
}

#[test]
fn s7492_prefers_generator_expressions_for_any_all() {
    let flagged = scan("any([x for x in xs])\nany(x for x in xs)\n");
    assert_eq!(findings(&flagged, "python:S7492").len(), 1);
}

#[test]
fn s7493_flags_blocking_file_operations_in_async_functions() {
    let flagged = scan(concat!(
        "async def rd():\n",
        "    data = open(\"f\").read()\n",
        "    text = p.read_text()\n",
        "    await asyncio.sleep(1)\n"
    ));
    assert_eq!(findings(&flagged, "python:S7493").len(), 2);
}

#[test]
fn s7499_flags_sync_http_clients_in_async_functions() {
    let flagged =
        scan("async def web():\n    requests.get(\"http://x\")\n    await asyncio.sleep(1)\n");
    assert_eq!(findings(&flagged, "python:S7499").len(), 1);
}

#[test]
fn s7501_flags_blocking_input_in_async_functions() {
    let flagged = scan("async def ask():\n    name = input()\n    await asyncio.sleep(1)\n");
    assert_eq!(findings(&flagged, "python:S7501").len(), 1);
}

#[test]
fn s7503_flags_async_functions_without_awaits() {
    let flagged = scan(concat!(
        "async def noop():\n",
        "    return 1\n",
        "async def real():\n",
        "    await asyncio.sleep(1)\n"
    ));
    let found = findings(&flagged, "python:S7503");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 1);
}

#[test]
fn s7513_flags_nurseries_starting_single_tasks() {
    let flagged = scan(concat!(
        "async def one():\n",
        "    async with trio.open_nursery() as nursery:\n",
        "        nursery.start_soon(work)\n",
        "async def many():\n",
        "    async with trio.open_nursery() as nursery:\n",
        "        nursery.start_soon(a)\n",
        "        nursery.start_soon(b)\n"
    ));
    assert_eq!(findings(&flagged, "python:S7513").len(), 1);
}

#[test]
fn s7514_flags_control_flow_out_of_nurseries() {
    let flagged = scan(concat!(
        "async def esc():\n",
        "    async with trio.open_nursery() as nursery:\n",
        "        nursery.start_soon(a)\n",
        "        nursery.start_soon(b)\n",
        "        return\n"
    ));
    let found = findings(&flagged, "python:S7514");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 5);
}

#[test]
fn s6538_gated_return_annotations() {
    let source = "def add(a, b):\n    return a\n";
    assert!(findings(&scan(source), "python:S6538").is_empty());
    let options = AnalyzerOptions {
        require_type_hints: true,
        ..AnalyzerOptions::default()
    };
    let report = analyze(PathBuf::from("t.py"), source, &options);
    assert_eq!(findings(&report, "python:S6538").len(), 1);
}

#[test]
fn s6540_gated_parameter_annotations() {
    let source = "def add(a, b):\n    return a\ndef tagged(a: int):\n    return a\n";
    let options = AnalyzerOptions {
        require_type_hints: true,
        ..AnalyzerOptions::default()
    };
    let report = analyze(PathBuf::from("t.py"), source, &options);
    assert_eq!(findings(&report, "python:S6540").len(), 2);
    assert!(findings(&scan(source), "python:S6540").is_empty());
}

#[test]
fn s6542_flags_any_type_hints() {
    let flagged = scan("def f(x: Any) -> int:\n    return 1\n");
    assert_eq!(findings(&flagged, "python:S6542").len(), 1);
}

#[test]
fn s6543_flags_bare_generic_hints() {
    let flagged = scan(
        "def first(xs: list) -> int:\n    return 1\ndef second(xs: list[int]) -> int:\n    return 1\n",
    );
    assert_eq!(findings(&flagged, "python:S6543").len(), 1);
}

#[test]
fn s6545_prefers_builtin_generics_over_typing_aliases() {
    let flagged =
        scan("def f() -> List[int]:\n    return []\ndef g() -> list[int]:\n    return []\n");
    assert_eq!(findings(&flagged, "python:S6545").len(), 1);
}

#[test]
fn s6546_prefers_pep604_unions() {
    let flagged = scan(
        "def f(x: Union[int, str]) -> int:\n    return 1\ndef g(x: int | str) -> int:\n    return 1\n",
    );
    assert_eq!(findings(&flagged, "python:S6546").len(), 1);
}

#[test]
fn s6792_prefers_pep695_generic_classes() {
    let flagged = scan("class Box(Generic[T]):\n    pass\nclass Plain:\n    pass\n");
    assert_eq!(findings(&flagged, "python:S6792").len(), 1);
}

#[test]
fn s6794_prefers_type_statement_aliases() {
    let flagged = scan("X: TypeAlias = int\nY = int\n");
    assert_eq!(findings(&flagged, "python:S6794").len(), 1);
}

#[test]
fn s6795_flags_typevars_alongside_pep695_syntax() {
    let flagged = scan("T = TypeVar(\"T\")\ntype PairOf[T] = tuple[T, T]\n");
    assert_eq!(findings(&flagged, "python:S6795").len(), 1);
}

#[test]
fn s6796_prefers_pep695_parameters_over_typevar_hints() {
    let flagged = scan(concat!(
        "T = TypeVar(\"T\")\n",
        "def identity(x: T) -> T:\n",
        "    return x\n",
        "def plain(x: int) -> int:\n",
        "    return x\n"
    ));
    assert_eq!(findings(&flagged, "python:S6796").len(), 1);
}

#[test]
fn s6468_flags_except_star_on_exception_groups() {
    let flagged = scan("try:\n    pass\nexcept* ExceptionGroup:\n    pass\n");
    assert_eq!(findings(&flagged, "python:S6468").len(), 1);
}

#[test]
fn s3984_flags_exceptions_created_without_raising() {
    let flagged =
        scan("ValueError(\"bad\")\nraise ValueError(\"good\")\nstored = ValueError(\"kept\")\n");
    assert_eq!(findings(&flagged, "python:S3984").len(), 1);
}

#[test]
fn s5845_flags_incompatible_assert_literal_types() {
    let flagged = scan(
        "case.assertEqual(\"1\", 2)\ncase.assertEqual(1, 2)\ncase.assertEqual(\"1\", \"2\")\n",
    );
    assert_eq!(findings(&flagged, "python:S5845").len(), 1);
}

#[test]
fn s5549_flags_repeated_nontrivial_arguments() {
    let flagged = scan("f(a, a)\nf(None, None)\ng(1, 1)\nh(a, b)\n");
    assert_eq!(findings(&flagged, "python:S5549").len(), 1);
}

#[test]
fn s1607_requires_reasons_for_skips() {
    let flagged = scan(
        "@unittest.skip()\ndef t1():\n    pass\n@unittest.skip(\"flaky\")\ndef t2():\n    pass\n",
    );
    assert_eq!(findings(&flagged, "python:S1607").len(), 1);
}

#[test]
fn s5906_suggests_specific_assertions() {
    let flagged = scan(concat!(
        "case.assertEqual(x, True)\n",
        "case.assertTrue(x == y)\n",
        "case.assertFalse(a in b)\n",
        "case.assertEqual(x, y)\n"
    ));
    assert_eq!(findings(&flagged, "python:S5906").len(), 3);
}

#[test]
fn s5914_flags_unconditional_assertions() {
    let flagged = scan(
        "case.assertEqual(a, a)\ncase.assertTrue(True)\ncase.assertFalse(True)\ncase.assertEqual(a, b)\n",
    );
    assert_eq!(findings(&flagged, "python:S5914").len(), 3);
}

#[test]
fn s6709_flags_files_using_unseeded_randomness() {
    let unseeded = scan("import random\nvalue = random.random()\n");
    let found = findings(&unseeded, "python:S6709");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start, pos(1, 0));
    let seeded = scan("random.seed(7)\nvalue = random.random()\n");
    assert!(findings(&seeded, "python:S6709").is_empty());
}

#[test]
fn s139_flags_trailing_comments_except_whitelisted_shapes() {
    let flagged = scan(concat!(
        "x = 1  # step one\n",
        "y = 2  # fmt: off\n",
        "# standalone comment\n",
        "z = 3  # NOSONAR anywhere\n"
    ));
    let found = findings(&flagged, "python:S139");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 1);
}

#[test]
fn s4143_flags_consecutive_same_slot_writes() {
    let flagged = scan("items[0] = 1\nitems[0] = 2\nitems[1] = 3\n");
    let found = findings(&flagged, "python:S4143");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 2);
}

#[test]
fn s4144_flags_identical_sibling_implementations() {
    let flagged = scan(concat!(
        "def alpha():\n",
        "    setup()\n",
        "    return 1\n",
        "def beta():\n",
        "    setup()\n",
        "    return 1\n",
        "def gamma():\n",
        "    return 2\n"
    ));
    let found = findings(&flagged, "python:S4144");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 4);
}

#[test]
fn s5717_flags_mutated_defaults_and_assigned_parameters() {
    let flagged = scan(concat!(
        "def collect(bucket=[]):\n",
        "    bucket.append(1)\n",
        "    return bucket\n",
        "def rename(name=\"x\"):\n",
        "    name = \"y\"\n",
        "    return name\n",
        "def safe(items=None):\n",
        "    return items\n"
    ));
    assert_eq!(findings(&flagged, "python:S5717").len(), 2);
}

#[test]
fn s5797_flags_constant_conditions_but_not_while_true() {
    let flagged = scan(
        "if True:\n    pass\nwhile False:\n    pass\nwhile True:\n    pass\nif flag:\n    pass\n",
    );
    let found = findings(&flagged, "python:S5797");
    assert_eq!(found.len(), 2);
    assert_eq!(
        found
            .iter()
            .map(|issue| issue.range.start.line)
            .collect::<Vec<_>>(),
        vec![1, 3]
    );
}
// ------------------------------------------------------------------
// Tier B — symbol group.
// ------------------------------------------------------------------

#[test]
fn s1128_flags_unused_module_imports() {
    let flagged = scan("import os\nimport sys\nprint(os.getcwd())\n");
    assert_eq!(findings(&flagged, "python:S1128").len(), 1);
    assert_eq!(
        findings(
            &scan("import os\nimport sys\nprint(os.getcwd(), sys.path)\n"),
            "python:S1128"
        )
        .len(),
        0
    );
}

#[test]
fn s1144_flags_unreferenced_private_methods() {
    let flagged = scan("class C:\n    def _hidden(self):\n        return 7\n\n\nc = C()\n");
    assert_eq!(findings(&flagged, "python:S1144").len(), 1);
    let referenced = scan(
        "class C:\n    def _hidden(self):\n        return 7\n\n\nc = C()\nprint(c._hidden())\n",
    );
    assert!(findings(&referenced, "python:S1144").is_empty());
}

#[test]
fn s1172_flags_unused_function_parameters() {
    let flagged = scan("def scale(value, factor):\n    return value\n\n\nscale(2, 3)\n");
    assert_eq!(findings(&flagged, "python:S1172").len(), 1);
    let used = scan("def scale(value, factor):\n    return value * factor\n\n\nscale(2, 3)\n");
    assert!(findings(&used, "python:S1172").is_empty());
}

#[test]
fn s1481_flags_unused_local_variables() {
    let flagged = scan("def run():\n    total = 1\n    result = 2\n    return result\n\n\nrun()\n");
    let found = findings(&flagged, "python:S1481");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 2);
    let clean = scan("def run():\n    total = 1\n    return total\n\n\nrun()\n");
    assert!(findings(&clean, "python:S1481").is_empty());
}

#[test]
fn s3827_flags_module_uses_before_definition() {
    let flagged = scan("handler()\n\n\ndef handler():\n    pass\n");
    let found = findings(&flagged, "python:S3827");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 1);
    let ordered = scan("def handler():\n    pass\n\n\nhandler()\n");
    assert!(findings(&ordered, "python:S3827").is_empty());
}

#[test]
fn s3985_flags_unused_private_nested_classes() {
    let flagged =
        scan("def outer():\n    class _Inner:\n        pass\n\n    return 1\n\n\nouter()\n");
    assert_eq!(findings(&flagged, "python:S3985").len(), 1);
    let exported =
        scan("def outer():\n    class _Inner:\n        pass\n\n    return _Inner\n\n\nouter()\n");
    assert!(findings(&exported, "python:S3985").is_empty());
}

#[test]
fn s5603_flags_unused_nested_definitions() {
    let flagged =
        scan("def outer():\n    def helper():\n        pass\n\n    return 1\n\n\nouter()\n");
    assert_eq!(findings(&flagged, "python:S5603").len(), 1);
    let called =
        scan("def outer():\n    def helper():\n        pass\n\n    return helper()\n\n\nouter()\n");
    assert!(findings(&called, "python:S5603").is_empty());
}

#[test]
fn s5806_flags_bindings_shadowing_builtins() {
    let flagged =
        scan("def process(items):\n    len = len(items)\n    return len\n\n\nprocess([1])\n");
    assert_eq!(findings(&flagged, "python:S5806").len(), 1);
    let renamed =
        scan("def process(items):\n    length = len(items)\n    return length\n\n\nprocess([1])\n");
    assert!(findings(&renamed, "python:S5806").is_empty());
}

#[test]
fn s5807_requires_all_names_to_exist() {
    let flagged = scan("__all__ = [\"alpha\", \"missing_one\"]\nalpha = 1\n");
    let found = findings(&flagged, "python:S5807");
    assert_eq!(found.len(), 1);
    let defined = scan("__all__ = [\"alpha\"]\nalpha = 1\n");
    assert!(findings(&defined, "python:S5807").is_empty());
}

#[test]
fn s5953_flags_undefined_name_loads() {
    let flagged = scan("value = undefined_thing + 1\nprint(value)\n");
    let found = findings(&flagged, "python:S5953");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 1);
    let defined = scan("thing = 1\nvalue = thing + 1\nprint(value)\n");
    assert!(findings(&defined, "python:S5953").is_empty());
}

#[test]
fn s4487_flags_written_but_unread_private_attributes() {
    let flagged = scan(concat!(
        "class Holder:\n",
        "    def setup(self):\n",
        "        self.__orphan = 1\n",
        "\n",
        "    def keep(self):\n",
        "        self.__kept = 2\n",
        "        return self.__kept\n",
        "\n",
        "holder = Holder()\n",
        "holder.setup()\n",
        "holder.keep()\n"
    ));
    assert_eq!(findings(&flagged, "python:S4487").len(), 1);
    let read = scan(concat!(
        "class Holder:\n",
        "    def setup(self):\n",
        "        self.__orphan = 1\n",
        "        return self.__orphan\n",
        "\n",
        "holder = Holder()\n",
        "holder.setup()\n"
    ));
    assert!(findings(&read, "python:S4487").is_empty());
}

// ------------------------------------------------------------------
// Tier B — flow group.
// ------------------------------------------------------------------

#[test]
fn s1045_flags_unreachable_except_blocks() {
    let flagged = scan(
        "try:\n    step()\nexcept Exception:\n    handle_wide()\nexcept ValueError:\n    handle_narrow()\n",
    );
    assert_eq!(findings(&flagged, "python:S1045").len(), 1);
    let ordered = scan(
        "try:\n    step()\nexcept ValueError:\n    handle_narrow()\nexcept Exception:\n    handle_wide()\n",
    );
    assert!(findings(&ordered, "python:S1045").is_empty());
}

#[test]
fn s2190_flags_straight_line_infinite_recursion() {
    let flagged = scan("def spin():\n    return spin()\n\n\nspin()\n");
    assert_eq!(findings(&flagged, "python:S2190").len(), 1);
    let guarded = scan(
        "def spin(count):\n    if count <= 0:\n        return 1\n    return spin(count - 1)\n\n\nspin(3)\n",
    );
    assert!(findings(&guarded, "python:S2190").is_empty());
}

#[test]
fn s1751_flags_loops_with_trailing_break() {
    let flagged = scan("for item in items_source:\n    prepare(item)\n    break\n");
    assert_eq!(findings(&flagged, "python:S1751").len(), 1);
    let full = scan("for item in items_source:\n    prepare(item)\n");
    assert!(findings(&full, "python:S1751").is_empty());
}

#[test]
fn s5918_prefers_explicit_test_skips_over_guards() {
    let flagged =
        scan("def test_upload(self):\n    if upload_ready:\n        return\n    verify_upload()\n");
    assert_eq!(findings(&flagged, "python:S5918").len(), 1);
    let direct = scan("def test_upload(self):\n    verify_upload()\n");
    assert!(findings(&direct, "python:S5918").is_empty());
}

#[test]
fn s6908_flags_recursion_inside_tf_function() {
    let flagged = scan(
        "import tensorflow as tf\n\n\n@tf.function\ndef train(step):\n    return train(step - 1)\n",
    );
    assert_eq!(findings(&flagged, "python:S6908").len(), 1);
    let flat =
        scan("import tensorflow as tf\n\n\n@tf.function\ndef train(step):\n    return step * 2\n");
    assert!(findings(&flat, "python:S6908").is_empty());
}

// ------------------------------------------------------------------
// Tier B — value group.
// ------------------------------------------------------------------

#[test]
fn s1226_flags_parameters_overwritten_before_read() {
    let flagged =
        scan("def render(mode):\n    mode = \"fast\"\n    return mode\n\n\nrender(\"slow\")\n");
    assert_eq!(findings(&flagged, "python:S1226").len(), 1);
    let respected = scan(
        "def render(mode):\n    prefix = mode or \"fast\"\n    return prefix\n\n\nrender(\"slow\")\n",
    );
    assert!(findings(&respected, "python:S1226").is_empty());
}

#[test]
fn s1854_flags_dead_final_stores() {
    let flagged = scan(concat!(
        "def tally(items):\n",
        "    total = 0\n",
        "    for item in items:\n",
        "        total += item\n",
        "    report(total)\n",
        "    total = 0\n"
    ));
    let found = findings(&flagged, "python:S1854");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range.start.line, 6);
    let alive = scan(concat!(
        "def tally(items):\n",
        "    total = 0\n",
        "    for item in items:\n",
        "        total += item\n",
        "    report(total)\n"
    ));
    assert!(findings(&alive, "python:S1854").is_empty());
}

#[test]
fn s2159_flags_comparisons_with_known_values() {
    let flagged = scan(
        "def decide(flag):\n    expected = True\n    if expected == True:\n        return 1\n    return 0\n\n\ndecide(True)\n",
    );
    assert_eq!(findings(&flagged, "python:S2159").len(), 1);
    let unknown = scan(
        "def decide(flag):\n    expected = compute_flag()\n    if expected == True:\n        return 1\n    return 0\n\n\ndecide(True)\n",
    );
    assert!(findings(&unknown, "python:S2159").is_empty());
}

#[test]
fn s2275_flags_percent_format_count_mismatches() {
    let flagged = scan("label = \"point: %d %s\" % (x_axis,)\nprint(label)\n");
    assert_eq!(findings(&flagged, "python:S2275").len(), 1);
    let matched = scan("label = \"point: %d %s\" % (x_axis, y_axis)\nprint(label)\n");
    assert!(findings(&matched, "python:S2275").is_empty());
}

#[test]
fn s3457_flags_printf_type_mismatches() {
    let flagged = scan("label = \"age: %d\" % (\"old\",)\nprint(label)\n");
    assert_eq!(findings(&flagged, "python:S3457").len(), 1);
    let typed = scan("label = \"age: %d years\" % (42,)\nprint(label)\n");
    assert!(findings(&typed, "python:S3457").is_empty());
}

#[test]
fn s3516_flags_identical_constant_returns() {
    let flagged =
        scan("def pick(mode):\n    if mode:\n        return 7\n    return 7\n\n\npick(1)\n");
    assert_eq!(findings(&flagged, "python:S3516").len(), 1);
    let varied =
        scan("def pick(mode):\n    if mode:\n        return 7\n    return 8\n\n\npick(1)\n");
    assert!(findings(&varied, "python:S3516").is_empty());
}

#[test]
fn s3801_flags_mixed_value_and_none_returns() {
    let flagged =
        scan("def fetch(flag):\n    if flag:\n        return 5\n    return None\n\n\nfetch(1)\n");
    assert_eq!(findings(&flagged, "python:S3801").len(), 1);
    let consistent =
        scan("def fetch(flag):\n    if flag:\n        return 5\n    return 0\n\n\nfetch(1)\n");
    assert!(findings(&consistent, "python:S3801").is_empty());
}

#[test]
fn s5864_flags_confusing_type_checks() {
    let flagged = scan("matches = isinstance(value_item, [int, str])\nprint(matches)\n");
    assert_eq!(findings(&flagged, "python:S5864").len(), 1);
    let proper = scan("matches = isinstance(value_item, (int, str))\nprint(matches)\n");
    assert!(findings(&proper, "python:S5864").is_empty());
}

// ------------------------------------------------------------------
// Tier B — effect group.
// ------------------------------------------------------------------

#[test]
fn s2325_flags_methods_never_using_self() {
    let flagged = scan(concat!(
        "class Math:\n",
        "    def combine(self, left, right):\n",
        "        return left + right\n",
        "\n",
        "math_tool = Math()\n",
        "print(math_tool.combine(1, 2))\n"
    ));
    assert_eq!(findings(&flagged, "python:S2325").len(), 1);
    let stateful = scan(concat!(
        "class Math:\n",
        "    def combine(self, left, right):\n",
        "        return self.scale(left) + right\n",
        "\n",
        "        return self.factor * value\n",
        "\n",
        "math_tool = Math()\n",
        "print(math_tool.combine(1, 2))\n"
    ));
    assert!(findings(&stateful, "python:S2325").is_empty());
}

#[test]
fn s6911_flag_tf_functions_capturing_module_state() {
    let flagged = scan(
        "import tensorflow as tf\n\nrate = 0.1\n\n\n@tf.function\ndef step(value):\n    return value * rate\n",
    );
    assert_eq!(findings(&flagged, "python:S6911").len(), 1);
    let parameterized = scan(
        "import tensorflow as tf\n\n\n@tf.function\ndef step(value, rate):\n    return value * rate\n",
    );
    assert!(findings(&parameterized, "python:S6911").is_empty());
}

#[test]
fn s6918_flags_variables_created_inside_tf_functions() {
    let flagged = scan(
        "import tensorflow as tf\n\n\n@tf.function\ndef build():\n    return tf.Variable(1.0)\n",
    );
    assert_eq!(findings(&flagged, "python:S6918").len(), 1);
    let outside = scan(
        "import tensorflow as tf\n\nweight = tf.Variable(1.0)\n\n\n@tf.function\ndef build():\n    return weight\n",
    );
    assert!(findings(&outside, "python:S6918").is_empty());
}

#[test]
fn s6928_flags_python_side_effects_inside_tf_functions() {
    let flagged = scan(
        "import tensorflow as tf\n\n\n@tf.function\ndef run(batch):\n    print(\"tracing\")\n    return batch * 2\n",
    );
    assert_eq!(findings(&flagged, "python:S6928").len(), 1);
    let pure =
        scan("import tensorflow as tf\n\n\n@tf.function\ndef run(batch):\n    return batch * 2\n");
    assert!(findings(&pure, "python:S6928").is_empty());
}

#[test]
fn s6982_requires_eval_before_loaded_model_inference() {
    let flagged = scan("model = load_model(weights_path)\nmodel.train()\nmodel(input_tensor)\n");
    assert_eq!(findings(&flagged, "python:S6982").len(), 1);
    let evaluated = scan(
        "model = load_model(weights_path)\nmodel.eval()\nmodel.train()\nmodel(input_tensor)\n",
    );
    assert!(findings(&evaluated, "python:S6982").is_empty());
}

#[test]
fn s7502_flags_discarded_asyncio_tasks() {
    let flagged = scan(
        "import asyncio\n\n\nasync def worker():\n    pass\n\n\nasyncio.create_task(worker())\n",
    );
    assert_eq!(findings(&flagged, "python:S7502").len(), 1);
    let retained = scan(
        "import asyncio\n\n\nasync def worker():\n    pass\n\n\ntask_handle = asyncio.create_task(worker())\n",
    );
    assert!(findings(&retained, "python:S7502").is_empty());
}

#[test]
fn s7515_flags_sync_open_context_managers_in_async_functions() {
    let flagged = scan(
        "async def read_config():\n    with open(config_path) as handle:\n        return handle.read()\n",
    );
    assert_eq!(findings(&flagged, "python:S7515").len(), 1);
    let sync_caller = scan(
        "def read_config():\n    with open(config_path) as handle:\n        return handle.read()\n",
    );
    assert!(findings(&sync_caller, "python:S7515").is_empty());
}

#[test]
fn s6972_validates_nested_estimator_parameter_prefixes() {
    let flagged = scan(
        "from sklearn.pipeline import Pipeline\n\npipe = Pipeline(steps=[(\"scale\", scaler_value)])\npipe.set_params(bogus__alpha=0.5)\n",
    );
    assert_eq!(findings(&flagged, "python:S6972").len(), 1);
    let known_step = scan(
        "from sklearn.pipeline import Pipeline\n\npipe = Pipeline(steps=[(\"scale\", scaler_value)])\npipe.set_params(scaler__alpha=0.5)\n",
    );
    assert!(findings(&known_step, "python:S6972").is_empty());
}

#[test]
fn s7490_requires_checkpoints_inside_cancellation_scopes() {
    let flagged =
        scan("async def guarded():\n    with move_on_after(5):\n        finish_loading()\n");
    assert_eq!(findings(&flagged, "python:S7490").len(), 1);
    let checkpointed =
        scan("async def guarded():\n    with move_on_after(5):\n        await sleep_short()\n");
    assert!(findings(&checkpointed, "python:S7490").is_empty());
}

#[test]
fn s7497_requires_reraise_of_cancellation_exceptions() {
    let flagged = scan(
        "async def shielded():\n    try:\n        await work()\n    except CancelledError:\n        release_lock()\n",
    );
    assert_eq!(findings(&flagged, "python:S7497").len(), 1);
    let reraised = scan(
        "async def shielded():\n    try:\n        await work()\n    except CancelledError:\n        release_lock()\n        raise\n",
    );
    assert!(findings(&reraised, "python:S7497").is_empty());
}

// ------------------------------------------------------------------
// Tier B — option knobs.
// ------------------------------------------------------------------

#[test]
fn s1481_honors_the_ignore_pattern_option() {
    let defaults = scan("def run():\n    dummy = 1\n    return 1\n\n\nrun()\n");
    assert!(findings(&defaults, "python:S1481").is_empty());
    let options = AnalyzerOptions {
        unused_local_ignore_pattern: String::from("scratch_*"),
        ..AnalyzerOptions::default()
    };
    let custom_clean = analyze(
        PathBuf::from("t.py"),
        "def run():\n    scratch_pad = 1\n    leftover = 2\n    return leftover\n\n\nrun()\n",
        &options,
    );
    assert!(findings(&custom_clean, "python:S1481").is_empty());
    let custom_flagged = analyze(
        PathBuf::from("t.py"),
        "def run():\n    scratch_pad = 1\n    leftover = 2\n    return leftover\n\n\nrun()\n",
        &AnalyzerOptions::default(),
    );
    assert_eq!(findings(&custom_flagged, "python:S1481").len(), 1);
}

#[test]
fn s4487_single_underscore_issues_are_opt_in() {
    let source = concat!(
        "class Holder:\n",
        "    def prep(self):\n",
        "        self._ghost = 1\n",
        "\n",
        "holder = Holder()\n",
        "holder.prep()\n"
    );
    assert!(
        findings(&scan(source), "python:S4487").is_empty(),
        "single-underscore attributes stay silent by default"
    );
    let options = AnalyzerOptions {
        enable_single_underscore_attribute_issues: true,
        ..AnalyzerOptions::default()
    };
    let enabled = analyze(PathBuf::from("t.py"), source, &options);
    assert_eq!(findings(&enabled, "python:S4487").len(), 1);
}
// -----------------------------------------------------------------------
// regex engine + Tier-B regex rules.
// -----------------------------------------------------------------------

use super::{RxNode, RxParser, RxUnit, decode_string_part};

fn rx_units(source: &str) -> Vec<RxUnit> {
    decode_string_part(&format!("r\"{source}\""), ruff_text_size::TextSize::new(0))
}

fn rx_errors(source: &str) -> usize {
    let units = rx_units(source);
    // Re-parse through the public helper the battery uses.
    match super::parse_regex(&units) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn findings_of(source: &str, key: &str) -> Vec<String> {
    findings(&scan(source), key)
        .into_iter()
        .map(|issue| issue.message.clone())
        .collect()
}

#[test]
fn tmp_debug4() {
    let report = scan("import re\nre.search(r'Jack|Peter|', s)\n");
    eprintln!(
        "JACK {:?}",
        report
            .issues
            .iter()
            .map(|i| i.rule_key.clone())
            .collect::<Vec<_>>()
    );
    let u = rx_units(r"Jack|Peter|");
    match super::parse_regex(&u) {
        Ok(p) => eprintln!(
            "JACKPARSE ok root={:?} cap={}",
            match p.root {
                RxNode::Alternation(ref b) => format!("alt{}", b.len()),
                RxNode::Seq(ref q) => format!("seq{}", q.items.len()),
            },
            p.capture_count
        ),
        Err(e) => eprintln!("JACKPARSE err {:?}", e.span),
    }
}

#[test]
fn regex_parser_accepts_the_full_python_grammar() {
    for pattern in [
        r"a|bc",
        r"(a(b))c\2",
        r"(?P<year>\d{4})-(?P=year)",
        r"(?:x)+",
        r"a*?b++c{2,}",
        r"[a-z\d\-]]?",
        r"(?=look)(?!nope)(?<=back)(?<!noback)",
        r"(?#comment)abc",
        r"(?i)MiXeD(?s:.)*",
        r"\x41\u0042\U00000043\N{BULLET}",
        r"\p{Greek}\P{Latin}",
        r"a{,5}b{3,7}?",
        r"[\]\[^\\-]",
    ] {
        assert_eq!(rx_errors(pattern), 0, "pattern should parse: {pattern}");
    }
}

#[test]
fn regex_parser_rejects_python_syntax_errors() {
    for pattern in [
        r"a(b",       // unclosed group
        r"a)b",       // unbalanced parenthesis
        r"*x",        // nothing to repeat
        r"a**",       // multiple repeat
        r"a{2,1}",    // min greater than max
        r"a\",        // trailing backslash
        r"\q",        // bad escape (ASCII letter)
        r"[abc",      // unterminated class
        r"[z-a]",     // reversed range
        r"(?P<1x>a)", // invalid group name
    ] {
        assert_eq!(rx_errors(pattern), 1, "pattern should fail: {pattern}");
    }
}

#[test]
fn regex_decoder_keeps_source_offsets_and_raw_semantics() {
    // Cooked: \n collapses to one unit placed at the backslash offset;
    // unknown escapes stay verbatim so `\d` reaches the parser intact.
    let raw = r#""a\n\d""#;
    let units = decode_string_part(raw, ruff_text_size::TextSize::new(0));
    let text: String = units.iter().map(|unit| unit.ch).collect();
    assert_eq!(text.chars().count(), 4); // 'a', '\n', then verbatim '\\' + 'd'
    assert_eq!(
        u32::from(units[0].at) + u32::try_from(units[0].ch.len_utf8()).unwrap_or(0),
        2
    );
    // Raw: every character maps one-to-one.
    let raw_units = decode_string_part(r#"r"\n\d""#, ruff_text_size::TextSize::new(0));
    assert_eq!(raw_units.iter().map(|u| u.ch).collect::<String>(), r"\n\d");
}

#[test]
fn regex_group_numbers_follow_open_order_and_visibility() {
    let units = rx_units(r"(a)|((b)\2)");
    let Ok(parsed) = super::parse_regex(&units) else {
        panic!("should parse");
    };
    assert_eq!(parsed.capture_count, 3);
    // The \2 reference sits after two captures on its path: valid.
    assert!(parsed.backrefs.iter().all(|record| {
        record
            .number
            .is_none_or(|number| record.visible_numbers.contains(&number))
    }));
    // `(.)|\1`: the reference is on a sibling branch and must be flagged.
    let sibling = rx_units(r"(.)|\1");
    let parsed_sibling = super::parse_regex(&sibling).expect("parses");
    assert_eq!(parsed_sibling.backrefs.len(), 1);
    assert!(!parsed_sibling.backrefs[0].visible_numbers.contains(&1));
    let _ = RxNode::Seq;
    let _ = |parser: &RxParser| {
        let _ = &parser.pos;
    };
}

fn regex_finds(source: &str, key: &str) -> bool {
    !findings(&scan(source), key).is_empty()
}

#[test]
fn s4784_flags_every_regex_entry_point() {
    let flagged = "import re\nre.search(r'x', t)\nre.sub(r'y', '', t)\n";
    assert_eq!(findings_of(flagged, "python:S4784").len(), 2);
    assert!(!regex_finds("import re\nvalue = 'x'\n", "python:S4784"));
}

#[test]
fn s5856_reports_syntactically_invalid_patterns_only() {
    assert!(regex_finds(
        "import re\nre.compile(r'a(b')\n",
        "python:S5856"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'(ab)')\n",
        "python:S5856"
    ));
}

#[test]
fn s6323_flags_empty_alternatives_with_optional_maker_exempt() {
    assert_eq!(
        findings_of("import re\nre.search(r'Jack|Peter|', s)\n", "python:S6323").len(),
        1
    );
    assert!(regex_finds(
        "import re\nre.search(r'a||b', s)\n",
        "python:S6323"
    ));
    assert!(!regex_finds(
        "import re\nre.search(r'mandatory(-optional|)', s)\n",
        "python:S6323"
    ));
    // A quantifier after the group makes both redundant again.
    assert!(regex_finds(
        "import re\nre.search(r'mandatory(-optional|)?', s)\n",
        "python:S6323"
    ));
}

#[test]
fn s6331_flags_empty_groups() {
    assert!(regex_finds(
        "import re\nre.compile(r'foo()')\n",
        "python:S6331"
    ));
    assert!(regex_finds(
        "import re\nre.compile(r'(?:)')\n",
        "python:S6331"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'foo\\(\\)')\n",
        "python:S6331"
    ));
}

#[test]
fn s6396_flags_superfluous_curly_quantifiers() {
    for pattern in [r"ab{1}c", r"ab{1,1}c", r"ab{0}c"] {
        assert!(
            regex_finds(
                &format!("import re\nre.compile(r'{pattern}')\n"),
                "python:S6396"
            ),
            "{pattern}"
        );
    }
    assert!(!regex_finds(
        "import re\nre.compile(r'abc')\n",
        "python:S6396"
    ));
}

#[test]
fn s6353_suggests_concise_quantifiers_and_classes() {
    for pattern in [
        "[0-9]",
        "[^0-9]",
        "[A-Za-z0-9_]",
        r"[\w\W]",
        "a{0,}",
        "a{1,}",
        "a{0,1}",
        "a{2,2}",
    ] {
        assert!(
            regex_finds(
                &format!("import re\nre.compile(r'{pattern}')\n"),
                "python:S6353"
            ),
            "{pattern}"
        );
    }
    assert!(!regex_finds(
        "import re\nre.compile(r'\\d')\n",
        "python:S6353"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'[ab]')\n",
        "python:S6353"
    ));
}

#[test]
fn s6397_flags_single_character_classes_with_metachar_exception() {
    assert!(regex_finds(
        "import re\nre.compile(r'a[b]c')\n",
        "python:S6397"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'a[.]c')\n",
        "python:S6397"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'[ab]')\n",
        "python:S6397"
    ));
}

#[test]
fn s6537_flags_octal_escapes_at_both_levels() {
    assert!(regex_finds(
        "import re\nre.match(r'\\101', s)\n",
        "python:S6537"
    ));
    // Non-raw string: the octal escape happens at the string level.
    assert!(regex_finds(
        "import re\nre.match('\\101', s)\n",
        "python:S6537"
    ));
    assert!(!regex_finds(
        "import re\nre.match(r'\\x41', s)\n",
        "python:S6537"
    ));
}

#[test]
fn s5869_flags_duplicate_class_members() {
    assert!(regex_finds(
        "import re\nre.compile(r'[aa]')\n",
        "python:S5869"
    ));
    assert!(regex_finds(
        "import re\nre.compile(r'[a-c,c-e]')\n",
        "python:S5869"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'[abc]')\n",
        "python:S5869"
    ));
}

#[test]
fn s5868_flags_grapheme_clusters_in_classes() {
    // combining acute accent inside a class
    let source = "import re\nre.compile(\"[e\u{301}]\")\n";
    assert!(regex_finds(source, "python:S5868"));
    assert!(!regex_finds(
        "import re\nre.compile('[ea]')\n",
        "python:S5868"
    ));
}

#[test]
fn s5842_flags_repetitions_that_match_empty() {
    for pattern in [r"(?:x?)*", r"(?:)*", r"(?:x|)*"] {
        assert!(
            regex_finds(
                &format!("import re\nre.compile(r'{pattern}')\n"),
                "python:S5842"
            ),
            "{pattern}"
        );
    }
    assert!(!regex_finds(
        "import re\nre.compile(r'(?:x)+')\n",
        "python:S5842"
    ));
}

#[test]
fn s5852_flags_catastrophic_backtracking_shapes() {
    assert!(regex_finds(
        "import re\nre.compile(r'(a+)+b')\n",
        "python:S5852"
    ));
    assert!(regex_finds(
        "import re\nre.compile(r'.*_.*')\n",
        "python:S5852"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'(ba+)+b')\n",
        "python:S5852"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'a*_a*')\n",
        "python:S5852"
    ));
}

#[test]
fn s5850_flags_ungrouped_anchored_alternations() {
    assert!(regex_finds(
        "import re\nre.compile(r'^alt1|alt2$')\n",
        "python:S5850"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'^(?:alt1|alt2)$')\n",
        "python:S5850"
    ));
}

#[test]
fn s5855_flags_alternatives_covered_by_earlier_ones() {
    assert!(regex_finds(
        "import re\nre.compile(r'[ab]|a')\n",
        "python:S5855"
    ));
    assert!(regex_finds(
        "import re\nre.compile(r'.*|a')\n",
        "python:S5855"
    ));
    assert!(regex_finds(
        "import re\nre.compile(r'foo|foo')\n",
        "python:S5855"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'foo|bar')\n",
        "python:S5855"
    ));
}

#[test]
fn s5994_flags_patterns_that_fail_after_possessive_quantifiers() {
    assert!(regex_finds(
        "import re\nre.compile(r'a++abc')\n",
        "python:S5994"
    ));
    assert!(regex_finds(
        "import re\nre.compile(r'\\d*+[02468]')\n",
        "python:S5994"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'a++b')\n",
        "python:S5994"
    ));
}

#[test]
fn s5996_flags_boundaries_that_can_never_match() {
    assert!(regex_finds(
        "import re\nre.compile(r'$[a-z]+^')\n",
        "python:S5996"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'^[a-z]+$')\n",
        "python:S5996"
    ));
}

#[test]
fn s6001_flags_back_references_to_unmatched_groups() {
    for pattern in [r"\1(.)", r"(.)\2", r"(.)|\1", r"(?P<x>.)|(?P=x)"] {
        assert!(
            regex_finds(
                &format!("import re\nre.compile(r'{pattern}')\n"),
                "python:S6001"
            ),
            "{pattern}"
        );
    }
    assert!(!regex_finds(
        "import re\nre.compile(r'(.)\\1')\n",
        "python:S6001"
    ));
}

#[test]
fn s6002_flags_contradictory_lookaheads() {
    assert!(regex_finds(
        "import re\nre.compile(r'(?=a)b')\n",
        "python:S6002"
    ));
    assert!(regex_finds(
        "import re\nre.compile(r'(?=a)(?!a)')\n",
        "python:S6002"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'a(?=b)')\n",
        "python:S6002"
    ));
}

#[test]
fn s6019_flags_lazy_quantifiers_before_empty_matches() {
    assert!(regex_finds(
        "import re\nre.match(r'^\\d*?$', s)\n",
        "python:S6019"
    ));
    assert!(regex_finds(
        "import re\nre.sub(r'start\\w*?(end)?', 'x', s)\n",
        "python:S6019"
    ));
    // The sanctioned lazy-terminator idiom is exempt.
    assert!(!regex_finds(
        "import re\nre.sub(r'start\\w*?(end|$)', 'x', s)\n",
        "python:S6019"
    ));
}

#[test]
fn s6035_flags_single_character_alternations() {
    assert!(regex_finds(
        "import re\nre.compile(r'a|b|c')\n",
        "python:S6035"
    ));
    assert!(regex_finds(
        "import re\nre.compile(r'gr(a|e)y')\n",
        "python:S6035"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'[abc]')\n",
        "python:S6035"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'ab|cd')\n",
        "python:S6035"
    ));
}

#[test]
fn s6326_flags_multiple_spaces_unless_verbose_flag_set() {
    assert!(regex_finds(
        "import re\nre.compile(r'Hello,   world!')\n",
        "python:S6326"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'Hello,   world!', re.X)\n",
        "python:S6326"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'Hello world!')\n",
        "python:S6326"
    ));
}

#[test]
fn s6328_validates_group_references_in_replacements() {
    let flagged = "import re\nre.sub(r'(a)(b)(c)', r'\\1, \\9, \\3', s)\n";
    assert_eq!(findings_of(flagged, "python:S6328").len(), 1);
    assert!(!regex_finds(
        "import re\nre.sub(r'(a)(b)(c)', r'\\1, \\2, \\3', s)\n",
        "python:S6328"
    ));
    assert!(regex_finds(
        "import re\nre.sub(r'(?P<a>x)', r'\\g<b>', s)\n",
        "python:S6328"
    ));
}

#[test]
fn s6395_flags_pointless_non_capturing_groups() {
    assert!(regex_finds(
        "import re\nre.compile(r'(?:number)\\d{2}')\n",
        "python:S6395"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'(?:number|string)')\n",
        "python:S6395"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'(?:number)?\\d{2}')\n",
        "python:S6395"
    ));
}

#[test]
fn s5857_flags_reluctant_wildcard_quantifiers() {
    assert!(regex_finds(
        "import re\nre.compile(r'<.+?>')\n",
        "python:S5857"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'<[^>]*>')\n",
        "python:S5857"
    ));
}

#[test]
fn s5843_enforces_the_complexity_budget() {
    let complex = "import re\nre.compile(r'(a|b|c|d|e|f|g|h|i|j)+(k|l|m|n|o|p|q|r|s|t)+(u|v|x|y|z|A|B|C|D|E)+')\n";
    assert!(regex_finds(complex, "python:S5843"));
    assert!(!regex_finds(
        "import re\nre.compile(r'\\d{4}-\\d{2}')\n",
        "python:S5843"
    ));
    // Raising the budget silences the finding.
    let options = AnalyzerOptions {
        regex_maximum_complexity: 500,
        ..AnalyzerOptions::default()
    };
    let report = analyze(PathBuf::from("t.py"), complex, &options);
    assert!(
        report
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S5843")
    );
}

#[test]
fn s5860_flags_unknown_named_group_references() {
    let flagged = concat!(
        "import re\n",
        "pattern = re.compile(r'(?P<a>.)')\n",
        "matches = pattern.match(s)\n",
        "g = matches.group('b')\n"
    );
    assert!(regex_finds(flagged, "python:S5860"));
    let compliant = concat!(
        "import re\n",
        "pattern = re.compile(r'(?P<a>.)')\n",
        "matches = pattern.match(s)\n",
        "g = matches.group('a')\n"
    );
    assert!(!regex_finds(compliant, "python:S5860"));
    // Without any named groups in the file there is no signal.
    assert!(!regex_finds("matches.group('anything')\n", "python:S5860"));
}

#[test]
fn s4792_flags_logger_configuration_apis() {
    let flagged = concat!(
        "import logging.config\n",
        "logging.config.dictConfig({})\n",
        "logging.config.fileConfig(\"log.ini\")\n",
        "logging.basicConfig(handlers=[h])\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S4792").len(), 3);
    let clean = concat!(
        "import logging\n",
        "logging.basicConfig(level=\"INFO\")\n",
        "logging.info(\"hello\")\n"
    );
    assert!(findings(&scan(clean), "python:S4792").is_empty());
}

#[test]
fn s4823_flags_command_line_argument_access() {
    let flagged = "import sys\nprint(sys.argv[1])\nfrom sys import argv\n";
    assert_eq!(findings(&scan(flagged), "python:S4823").len(), 2);
    assert!(findings(&scan("print(sys.version)\n"), "python:S4823").is_empty());
}

#[test]
fn s4829_flags_standard_input_reads() {
    let flagged = "name = input()\ndata = sys.stdin.read()\n";
    assert_eq!(findings(&scan(flagged), "python:S4829").len(), 2);
    assert!(
        findings(
            &scan("sys.stdout.write(\"x\")\nsys.stderr.flush()\n"),
            "python:S4829"
        )
        .is_empty()
    );
}

#[test]
fn s4787_flags_encryption_api_constructions() {
    let flagged = concat!(
        "aes = AES.new(key)\n",
        "f = Fernet(secret)\n",
        "c = cryptography.hazmat.primitives.ciphers.Cipher(a, b)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S4787").len(), 3);
    assert!(
        findings(
            &scan("digest = hashlib.sha256(b\"data\")\n"),
            "python:S4787"
        )
        .is_empty()
    );
}

#[test]
fn s5300_flags_email_sending_apis() {
    let flagged = concat!(
        "client = smtplib.SMTP(host)\n",
        "client.sendmail(sender, to, msg)\n",
        "server.send_message(msg)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S5300").len(), 3);
    assert!(findings(&scan("sock.sendall(b\"x\")\n"), "python:S5300").is_empty());
}

#[test]
fn s4721_flags_shell_interpreter_usage() {
    let flagged = concat!(
        "subprocess.run(cmd, shell=True)\n",
        "os.system(cmd)\n",
        "os.popen(cmd)\n",
        "subprocess.Popen(cmd, shell=True)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S4721").len(), 4);
    assert!(
        findings(
            &scan(concat!(
                "subprocess.run([\"ls\"], shell=False)\n",
                "os.getcwd()\n"
            )),
            "python:S4721"
        )
        .is_empty()
    );
}

#[test]
fn s4830_flags_disabled_certificate_verification() {
    let flagged = concat!(
        "requests.get(url, verify=False)\n",
        "ctx = ssl._create_unverified_context()\n",
        "ctx.verify_mode = ssl.CERT_NONE\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S4830").len(), 3);
    assert!(findings(&scan("requests.get(url)\n"), "python:S4830").is_empty());
}

#[test]
fn s5527_flags_disabled_hostname_verification() {
    let flagged = concat!(
        "ctx.check_hostname = False\n",
        "http.post(url, verify=False)\n",
        "wrap(sock, check_hostname=False)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S5527").len(), 3);
    let clean = concat!("ctx.check_hostname = True\n", "http.post(url)\n");
    assert!(findings(&scan(clean), "python:S5527").is_empty());
}

#[test]
fn s4423_flags_weak_ssl_protocol_constants() {
    let flagged = concat!(
        "ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)\n",
        "wrap(sock, ssl_version=ssl.PROTOCOL_TLSv1)\n",
        "v = ssl.PROTOCOL_SSLv2\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S4423").len(), 3);
    let clean = concat!(
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n",
        "v2 = ssl.PROTOCOL_TLSv1_2\n"
    );
    assert!(findings(&scan(clean), "python:S4423").is_empty());
}

#[test]
fn s4426_flags_weak_key_generation_parameters() {
    let flagged = concat!(
        "RSA.generate(1024)\n",
        "DSA.generate(1024)\n",
        "ec.generate_private_key(ec.SECP192R1())\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S4426").len(), 3);
    let clean = concat!(
        "RSA.generate(4096)\n",
        "ec.generate_private_key(ec.SECP384R1())\n"
    );
    assert!(findings(&scan(clean), "python:S4426").is_empty());
}

#[test]
fn s2092_requires_secure_cookie_flag() {
    let flagged = concat!(
        "resp.set_cookie(\"k\", \"v\")\n",
        "resp.set_cookie(\"k\", \"v\", secure=False)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S2092").len(), 2);
    assert!(
        findings(
            &scan("resp.set_cookie(\"k\", \"v\", secure=True)\n"),
            "python:S2092"
        )
        .is_empty()
    );
}

#[test]
fn s3330_requires_httponly_cookie_flag() {
    let flagged = "resp.set_cookie(\"k\", \"v\")\nresp.set_cookie(\"k\", \"v\", httponly=False)\n";
    assert_eq!(findings(&scan(flagged), "python:S3330").len(), 2);
    assert!(
        findings(
            &scan("resp.set_cookie(\"k\", \"v\", httponly=True)\n"),
            "python:S3330"
        )
        .is_empty()
    );
}

#[test]
fn s4502_flags_csrf_exempt_decorators() {
    let flagged = "@csrf_exempt\ndef view(request):\n    return None\n";
    assert_eq!(findings(&scan(flagged), "python:S4502").len(), 1);
    let clean = "@login_required\ndef view(request):\n    return None\n";
    assert!(findings(&scan(clean), "python:S4502").is_empty());
}

#[test]
fn s5122_flags_wildcard_cors_origins() {
    let flagged = concat!(
        "CORS(app, origins=\"*\")\n",
        "headers = {\"Access-Control-Allow-Origin\": \"*\"}\n",
        "resp.headers[\"Access-Control-Allow-Origin\"] = \"*\"\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S5122").len(), 3);
    let clean = concat!(
        "CORS(app, origins=\"https://example.com\")\n",
        "headers = {\"Access-Control-Allow-Origin\": \"https://example.com\"}\n"
    );
    assert!(findings(&scan(clean), "python:S5122").is_empty());
}

#[test]
fn s5247_flags_autoescaping_disabled_calls() {
    let flagged = concat!(
        "env = Environment(autoescape=False)\n",
        "sa = select_autoescape(enabled=False)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S5247").len(), 2);
    let clean = concat!(
        "env = Environment(autoescape=True)\n",
        "env2 = Environment(loader=loader)\n"
    );
    assert!(findings(&scan(clean), "python:S5247").is_empty());
}

#[test]
fn s5439_flags_only_global_autoescape_disable() {
    let module_level = "env = Environment(autoescape=False)\n";
    assert_eq!(findings(&scan(module_level), "python:S5439").len(), 1);
    let nested = "def build():\n    return Environment(autoescape=False)\n";
    assert!(findings(&scan(nested), "python:S5439").is_empty());
}

#[test]
fn s4433_flags_unauthenticated_ldap_searches() {
    let flagged = "con = ldap.initialize(url)\ncon.search_s(base, scope)\n";
    assert_eq!(findings(&scan(flagged), "python:S4433").len(), 1);
    let clean = concat!(
        "con = ldap.initialize(url)\n",
        "con.simple_bind_s(\"user\", \"secret\")\n",
        "con.search_s(base, scope)\n"
    );
    assert!(findings(&scan(clean), "python:S4433").is_empty());
    assert_eq!(
        findings(&scan("ldap.simple_bind(\"\", \"\")\n"), "python:S4433").len(),
        1
    );
}

#[test]
fn s2115_flags_empty_database_passwords() {
    let flagged = concat!(
        "psycopg2.connect(dsn, password=\"\")\n",
        "mysql.connector.connect(passwd=\"\")\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S2115").len(), 2);
    assert!(
        findings(
            &scan("psycopg2.connect(dsn, password=\"s3cret\")\n"),
            "python:S2115"
        )
        .is_empty()
    );
}

#[test]
fn s2077_flags_formatted_sql_queries() {
    let flagged = concat!(
        "q = \"SELECT * FROM t WHERE id=%s\" % uid\n",
        "q2 = \"SELECT * FROM u WHERE n='{}'\".format(name)\n",
        "q3 = f\"SELECT * FROM t WHERE id={uid}\"\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S2077").len(), 3);
    let clean = concat!(
        "cursor.execute(\"SELECT * FROM t\")\n",
        "msg = \"hi %s\" % name\n"
    );
    assert!(findings(&scan(clean), "python:S2077").is_empty());
}

#[test]
fn s2053_flags_short_static_salts() {
    let flagged = concat!(
        "hashlib.pbkdf2_hmac(\"sha256\", pw, b\"salt\", 100000)\n",
        "hashlib.scrypt(pw, salt=b\"staticsalt\")\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S2053").len(), 2);
    let clean = concat!(
        "hashlib.pbkdf2_hmac(\"sha256\", pw, os.urandom(16), 100000)\n",
        "hashlib.pbkdf2_hmac(\"sha256\", pw, b\"a-32-byte-salt-of-random-data!!\", 100000)\n"
    );
    assert!(findings(&scan(clean), "python:S2053").is_empty());
}

#[test]
fn s3329_flags_static_cbc_ivs() {
    let flagged = concat!(
        "AES.new(k, AES.MODE_CBC, iv=b\"0123456789abcdef\")\n",
        "c = Cipher(a, modes.CBC(b\"staticiv12345\"))\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S3329").len(), 2);
    assert!(
        findings(
            &scan("AES.new(k, AES.MODE_CBC, iv=os.urandom(16))\n"),
            "python:S3329"
        )
        .is_empty()
    );
}

#[test]
fn s5542_flags_ecb_mode_and_weak_padding() {
    let flagged = "c = AES.new(k, AES.MODE_ECB)\np = padding.PKCS1v15()\n";
    assert_eq!(findings(&scan(flagged), "python:S5542").len(), 2);
    let clean = "g = AES.new(k, AES.MODE_GCM)\no = padding.OAEP(mgf=mgf1)\n";
    assert!(findings(&scan(clean), "python:S5542").is_empty());
}

#[test]
fn s5547_flags_weak_cipher_imports_and_constructors() {
    let flagged = concat!(
        "from Crypto.Cipher import DES\n",
        "c = DES.new(key, mode)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S5547").len(), 2);
    let clean = concat!(
        "from Crypto.Cipher import AES\n",
        "c = AES.new(key, mode)\n"
    );
    assert!(findings(&scan(clean), "python:S5547").is_empty());
}

#[test]
fn s5659_flags_unsigned_and_unverified_jwt() {
    let flagged = concat!(
        "t = jwt.encode(p, k, algorithm=\"none\")\n",
        "c = jwt.decode(t, k)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S5659").len(), 2);
    let clean = concat!(
        "t = jwt.encode(p, k, algorithm=\"HS256\")\n",
        "c = jwt.decode(t, k, algorithms=[\"HS256\"])\n"
    );
    assert!(findings(&scan(clean), "python:S5659").is_empty());
}

#[test]
fn s5344_flags_plaintext_and_fast_hashed_passwords() {
    let flagged = concat!(
        "password = \"hunter2\"\n",
        "digest = md5(password_bytes)\n",
        "h = hashlib.sha1(user_password)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S5344").len(), 3);
    let clean = concat!(
        "digest = hashlib.sha256(data)\n",
        "token = secrets.token_hex(32)\n"
    );
    assert!(findings(&scan(clean), "python:S5344").is_empty());
}

#[test]
fn s2245_flags_prng_in_security_named_functions() {
    let flagged = concat!(
        "def make_token(user):\n",
        "    return random.randint(0, 999999)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S2245").len(), 1);
    let clean = concat!(
        "def make_token(user):\n",
        "    return secrets.token_hex(32)\n",
        "def stats(sample):\n",
        "    return random.randint(0, 10)\n"
    );
    assert!(findings(&scan(clean), "python:S2245").is_empty());
}

#[test]
fn s5443_flags_temp_files_in_public_directories() {
    let flagged = concat!(
        "open(\"/tmp/app.log\", \"w\")\n",
        "open(\"/var/tmp/data.csv\")\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S5443").len(), 2);
    let clean = concat!("open(\"app.log\")\n", "tempfile.NamedTemporaryFile()\n");
    assert!(findings(&scan(clean), "python:S5443").is_empty());
}

#[test]
fn s2755_flags_unsafe_xml_parsers() {
    let flagged = concat!(
        "doc = ET.parse(path)\n",
        "node = lxml.etree.fromstring(text)\n",
        "xml.sax.parse(file, handler)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S2755").len(), 3);
    let clean = concat!(
        "doc = defusedxml.ElementTree.parse(path)\n",
        "data = json.load(file)\n"
    );
    assert!(findings(&scan(clean), "python:S2755").is_empty());
}

#[test]
fn s6377_flags_weak_xml_signature_digests() {
    let flagged = concat!(
        "t = xmlsec.constants.TransformMd5\n",
        "uri = \"http://www.w3.org/2001/04/xmldsig-more#md5\"\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6377").len(), 2);
    let clean = concat!(
        "t2 = xmlsec.constants.TransformSha256\n",
        "uri2 = \"http://www.w3.org/2001/04/xmlenc#sha256\"\n"
    );
    assert!(findings(&scan(clean), "python:S6377").is_empty());
}

#[test]
fn s4828_flags_raw_numeric_signal_parameters() {
    let flagged = "signal.signal(9, handler)\nos.kill(pid, 15)\n";
    assert_eq!(findings(&scan(flagged), "python:S4828").len(), 2);
    let clean = "signal.signal(signal.SIGTERM, handler)\nos.kill(pid, signal.SIGKILL)\n";
    assert!(findings(&scan(clean), "python:S4828").is_empty());
}

#[test]
fn s1523_flags_dynamic_code_execution_on_variables() {
    let flagged = "result = eval(user_input)\nexec(code_var)\n";
    assert_eq!(findings(&scan(flagged), "python:S1523").len(), 2);
    assert!(findings(&scan("value = eval(\"2 + 2\")\n"), "python:S1523").is_empty());
}

#[test]
fn s2257_flags_hand_rolled_cipher_functions() {
    let flagged = concat!(
        "def xor_encrypt(data, key):\n",
        "    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S2257").len(), 1);
    let clean = "def hash_password(pw):\n    return sha256(pw).hexdigest()\n";
    assert!(findings(&scan(clean), "python:S2257").is_empty());
}

#[test]
fn s6785_flags_graphql_schemas_without_depth_limiting() {
    let flagged = "schema = Schema(query=Query, mutation=Mutation)\n";
    assert_eq!(findings(&scan(flagged), "python:S6785").len(), 1);
    let clean = concat!(
        "schema = Schema(\n",
        "    query=Query,\n",
        "    extensions=[QueryDepthLimiter(max_depth=10)],\n",
        ")\n"
    );
    assert!(findings(&scan(clean), "python:S6785").is_empty());
    assert!(
        findings(
            &scan("class ColorSchema(Schema):\n    name = fields.Str()\n"),
            "python:S6785"
        )
        .is_empty()
    );
}

#[test]
fn s6245_requires_s3_server_side_encryption_configuration() {
    let flagged = "s3.create_bucket(Bucket=\"b\")\n";
    assert_eq!(findings(&scan(flagged), "python:S6245").len(), 1);
    assert!(findings(
            &scan("s3.create_bucket(Bucket=\"b\", ServerSideEncryptionConfiguration={\"Rules\": []})\n"),
            "python:S6245"
        )
        .is_empty());
}

#[test]
fn s6252_requires_s3_versioning_configuration() {
    let flagged = "s3.put_bucket_versioning(Bucket=\"b\")\n";
    assert_eq!(findings(&scan(flagged), "python:S6252").len(), 1);
    assert!(findings(
            &scan("s3.put_bucket_versioning(Bucket=\"b\", VersioningConfiguration={\"Status\": \"Enabled\"})\n"),
            "python:S6252"
        )
        .is_empty());
}

#[test]
fn s6265_flags_public_acl_and_all_users_grants() {
    let flagged = concat!(
        "s3.put_object_acl(Bucket=\"b\", Key=\"k\", ACL=\"public-read\")\n",
        "s3.put_bucket_acl(Bucket=\"b\", GrantFullControl='uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"')\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6265").len(), 2);
    assert!(
        findings(
            &scan("s3.put_object_acl(Bucket=\"b\", Key=\"k\", ACL=\"private\")\n"),
            "python:S6265"
        )
        .is_empty()
    );
}

#[test]
fn s6270_flags_wildcard_principal_policies() {
    let flagged = concat!(
        "policy = {\"Statement\": [{\"Effect\": \"Allow\", \"Principal\": \"*\",\n",
        "    \"Action\": \"s3:GetObject\"}]}\n",
        "policy2 = {\"Statement\": [{\"Effect\": \"Allow\", \"Principal\": {\"AWS\": \"*\"}}]}\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6270").len(), 2);
    assert!(findings(
            &scan("policy = {\"Statement\": [{\"Principal\": {\"AWS\": \"arn:aws:iam::123:root\"}}]}\n"),
            "python:S6270"
        )
        .is_empty());
}

#[test]
fn s6302_flags_wildcard_action_policies() {
    let flagged = concat!(
        "p1 = {\"Action\": \"*\"}\n",
        "p2 = {\"Action\": [\"s3:*\", \"ec2:RunInstances\"]}\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6302").len(), 1);
    assert!(
        findings(
            &scan("p3 = {\"Action\": [\"s3:GetObject\"]}\n"),
            "python:S6302"
        )
        .is_empty()
    );
}

#[test]
fn s6275_flags_unencrypted_ebs_volumes() {
    let flagged = concat!(
        "ec2.create_volume(Size=8, AvailabilityZone=\"us-east-1a\")\n",
        "ec2.create_volume(Size=8, Encrypted=False)\n",
        "ec2.run_instances(ImageId=\"ami\", BlockDeviceMappings=[{\"DeviceName\": \"/dev/sda\"}])\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6275").len(), 3);
    assert!(
        findings(
            &scan("ec2.create_volume(Size=8, AvailabilityZone=\"us-east-1a\", Encrypted=True)\n"),
            "python:S6275"
        )
        .is_empty()
    );
}

#[test]
fn s6281_requires_full_s3_public_access_block() {
    let flagged = concat!(
        "s3.put_public_access_block(\n",
        "    Bucket=\"b\",\n",
        "    PublicAccessBlockConfiguration={\"BlockPublicAcls\": True},\n",
        ")\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6281").len(), 1);
    let clean = concat!(
        "s3.put_public_access_block(\n",
        "    Bucket=\"b\",\n",
        "    PublicAccessBlockConfiguration={\n",
        "        \"BlockPublicAcls\": True, \"BlockPublicPolicy\": True,\n",
        "        \"IgnorePublicAcls\": True, \"RestrictPublicBuckets\": True,\n",
        "    },\n",
        ")\n"
    );
    assert!(findings(&scan(clean), "python:S6281").is_empty());
}

#[test]
fn s6304_flags_all_resources_policies() {
    let flagged = concat!(
        "p1 = {\"Effect\": \"Allow\", \"Resource\": \"*\"}\n",
        "p2 = {\"Effect\": \"Allow\", \"Resource\": [\"*\"]}\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6304").len(), 2);
    assert!(
        findings(
            &scan("p3 = {\"Effect\": \"Allow\", \"Resource\": \"arn:aws:s3:::bucket/*\"}\n"),
            "python:S6304"
        )
        .is_empty()
    );
}

#[test]
fn s6303_requires_rds_storage_encryption() {
    let flagged = concat!(
        "rds.create_db_instance(DBInstanceIdentifier=\"db\")\n",
        "rds.create_db_cluster(DBClusterIdentifier=\"c\", StorageEncrypted=False)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6303").len(), 2);
    assert!(
        findings(
            &scan("rds.create_db_instance(DBInstanceIdentifier=\"db\", StorageEncrypted=True)\n"),
            "python:S6303"
        )
        .is_empty()
    );
}

#[test]
fn s6308_requires_opensearch_encryption_options() {
    let flagged = concat!(
        "client.create_domain(DomainName=\"d\")\n",
        "es.create_elasticsearch_domain(DomainName=\"e\")\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6308").len(), 2);
    assert!(findings(
            &scan("client.create_domain(DomainName=\"d\", EncryptionAtRestOptions={\"Enabled\": True})\n"),
            "python:S6308"
        )
        .is_empty());
}

#[test]
fn s6317_flags_wildcard_scoped_actions() {
    let flagged = "p = {\"Action\": [\"s3:*\", \"ec2:DescribeInstances\"]}\n";
    assert_eq!(findings(&scan(flagged), "python:S6317").len(), 1);
    assert!(
        findings(
            &scan("p = {\"Action\": [\"s3:GetObject\", \"ec2:DescribeInstances\"]}\n"),
            "python:S6317"
        )
        .is_empty()
    );
}

#[test]
fn s6319_requires_sagemaker_volume_kms_key() {
    let flagged = "sm.create_notebook_instance(NotebookInstanceName=\"n\", RoleArn=\"r\")\n";
    assert_eq!(findings(&scan(flagged), "python:S6319").len(), 1);
    assert!(findings(
            &scan("sm.create_notebook_instance(NotebookInstanceName=\"n\", RoleArn=\"r\", VolumeKmsKeyId=\"k\")\n"),
            "python:S6319"
        )
        .is_empty());
}

#[test]
fn s6321_flags_admin_ports_open_to_world() {
    let flagged = concat!(
        "ec2.authorize_security_group_ingress(GroupId=\"g\", IpPermissions=[\n",
        "    {\"FromPort\": 22, \"ToPort\": 22, \"IpRanges\": [{\"CidrIp\": \"0.0.0.0/0\"}]},\n",
        "])\n",
        "ec2.authorize_security_group_ingress(GroupId=\"g\", IpPermissions=[\n",
        "    {\"FromPort\": 3389, \"ToPort\": 3389, \"IpRanges\": [{\"CidrIp\": \"0.0.0.0/0\"}]},\n",
        "])\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6321").len(), 2);
    let clean = concat!(
        "ec2.authorize_security_group_ingress(GroupId=\"g\", IpPermissions=[\n",
        "    {\"FromPort\": 443, \"ToPort\": 443, \"IpRanges\": [{\"CidrIp\": \"10.0.0.0/16\"}]},\n",
        "])\n"
    );
    assert!(findings(&scan(clean), "python:S6321").is_empty());
}

#[test]
fn s6327_requires_sns_kms_master_key() {
    assert_eq!(
        findings(&scan("sns.create_topic(Name=\"t\")\n"), "python:S6327").len(),
        1
    );
    assert!(
        findings(
            &scan("sns.create_topic(Name=\"t\", KmsMasterKeyId=\"key\")\n"),
            "python:S6327"
        )
        .is_empty()
    );
}

#[test]
fn s6329_flags_public_network_access_flags() {
    let flagged = concat!(
        "rds.create_db_instance(DBInstanceIdentifier=\"d\", PubliclyAccessible=True)\n",
        "ec2.modify_subnet_attribute(SubnetId=\"s\", MapPublicIpOnLaunch=True)\n",
        "ec2.run_instances(NetworkInterfaces=[{\"AssociatePublicIpAddress\": True}])\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6329").len(), 3);
    assert!(
        findings(
            &scan("rds.create_db_instance(DBInstanceIdentifier=\"d\", PubliclyAccessible=False)\n"),
            "python:S6329"
        )
        .is_empty()
    );
}

#[test]
fn s6330_requires_sqs_kms_master_queue_id() {
    assert_eq!(
        findings(&scan("sqs.create_queue(QueueName=\"q\")\n"), "python:S6330").len(),
        1
    );
    assert!(
        findings(
            &scan("sqs.create_queue(QueueName=\"q\", KmsMasterQueueId=\"key\")\n"),
            "python:S6330"
        )
        .is_empty()
    );
}

#[test]
fn s6332_requires_efs_encryption() {
    let flagged = concat!(
        "efs.create_file_system(CreationToken=\"t\")\n",
        "efs.create_file_system(CreationToken=\"t\", Encrypted=False)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6332").len(), 2);
    assert!(
        findings(
            &scan("efs.create_file_system(CreationToken=\"t\", Encrypted=True)\n"),
            "python:S6332"
        )
        .is_empty()
    );
}

#[test]
fn s6333_flags_api_gateway_open_authorization() {
    let flagged = "apigw.put_method(restApiId=\"a\", resourceId=\"r\", httpMethod=\"GET\", authorizationType=\"NONE\")\n";
    assert_eq!(findings(&scan(flagged), "python:S6333").len(), 1);
    assert!(findings(
            &scan("apigw.put_method(restApiId=\"a\", resourceId=\"r\", httpMethod=\"GET\", authorizationType=\"AWS_IAM\")\n"),
            "python:S6333"
        )
        .is_empty());
}

#[test]
fn s6463_flags_unrestricted_security_group_egress() {
    let flagged = concat!(
        "ec2.authorize_security_group_egress(GroupId=\"g\", IpPermissions=[\n",
        "    {\"IpProtocol\": \"-1\", \"IpRanges\": [{\"CidrIp\": \"0.0.0.0/0\"}]},\n",
        "])\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6463").len(), 1);
    let clean = concat!(
        "ec2.authorize_security_group_egress(GroupId=\"g\", IpPermissions=[\n",
        "    {\"IpProtocol\": \"tcp\", \"IpRanges\": [{\"CidrIp\": \"10.0.0.0/16\"}]},\n",
        "])\n"
    );
    assert!(findings(&scan(clean), "python:S6463").is_empty());
}

#[test]
fn s3752_flags_overbroad_http_routes() {
    let flagged = concat!(
        "@app.route(\"/x\", methods=[\"GET\", \"POST\", \"PUT\", \"DELETE\", \"PATCH\"])\n",
        "router.add_route(\"*\", \"/y\", handler)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S3752").len(), 2);
    let clean = concat!(
        "@app.route(\"/x\", methods=[\"GET\", \"POST\"])\n",
        "router.add_route(\"GET\", \"/y\", handler)\n"
    );
    assert!(findings(&scan(clean), "python:S3752").is_empty());
}

#[test]
fn s5795_flags_identity_comparisons_with_cached_types() {
    let flagged = "if x is 5:\n    pass\nif y is not \"v\":\n    pass\n";
    assert_eq!(findings(&scan(flagged), "python:S5795").len(), 2);
    let clean = "if z is None:\n    pass\nif a == 5:\n    pass\n";
    assert!(findings(&scan(clean), "python:S5795").is_empty());
}

#[test]
fn s3403_flags_identity_between_dissimilar_literals() {
    let flagged = "if 5 is \"a\":\n    pass\nif [1] is {\"k\": 1}:\n    pass\n";
    assert_eq!(findings(&scan(flagged), "python:S3403").len(), 2);
    let clean = "if b is None:\n    pass\n";
    assert!(findings(&scan(clean), "python:S3403").is_empty());
}

#[test]
fn s6663_flags_non_integer_sequence_indexes() {
    let flagged = "[1, 2][\"0\"]\n(1, 2)[0.5]\n\"abc\"[\"x\"]\n";
    assert_eq!(findings(&scan(flagged), "python:S6663").len(), 3);
    let clean = "{\"a\": 1}[\"a\"]\n[1, 2][0]\n";
    assert!(findings(&scan(clean), "python:S6663").is_empty());
}

#[test]
fn s5756_flags_calls_of_literals_and_non_callable_bindings() {
    let flagged = "5()\nx = 7\nx()\n";
    let messages = findings_of(flagged, "python:S5756");
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0], "This expression is not callable.");
    assert_eq!(messages[1], "'x' is not callable.");

    let clean = concat!(
        "\"abc\".upper()\n",
        "def handler():\n    pass\n",
        "handler()\n",
        "import os\n",
        "os.path.join('a', 'b')\n",
        "y = 1\n",
        "y = y + 1\n",
        "print(y)\n"
    );
    assert!(findings_of(clean, "python:S5756").is_empty());
}

#[test]
fn s2201_flags_discarded_results_of_pure_calls() {
    let flagged = concat!(
        "sorted(items)\n",
        "\"a,b\".split(\",\")\n",
        "\" x \".strip().upper()\n"
    );
    let messages = findings_of(flagged, "python:S2201");
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0], "The return value of 'sorted' is not used.");
    assert_eq!(messages[2], "The return value of 'upper' is not used.");

    let kept = concat!(
        "ordered = sorted(items)\n",
        "items.append(1)\n",
        "handler.write('x')\n"
    );
    assert!(findings_of(kept, "python:S2201").is_empty());
}

#[test]
fn s3699_flags_expression_uses_of_void_outputs() {
    let flagged = concat!(
        "def log_nothing():\n    print('x')\n",
        "total = log_nothing() + 1\n",
        "if log_nothing():\n    pass\n"
    );
    assert_eq!(findings_of(flagged, "python:S3699").len(), 2);

    let clean = concat!(
        "def log_nothing():\n    print('x')\n",
        "log_nothing()\n",
        "def get_value():\n    return 4\n",
        "kept = get_value() + 1\n",
        "@deco\n",
        "def wrapped():\n    pass\n"
    );
    assert!(findings_of(clean, "python:S3699").is_empty());
}

#[test]
fn s935_flags_bare_returns_under_concrete_hints() {
    let flagged = concat!(
        "def score() -> int:\n",
        "    if flag:\n",
        "        return\n",
        "    return 1\n"
    );
    assert_eq!(findings_of(flagged, "python:S935").len(), 1);

    let clean = concat!(
        "def maybe() -> Optional[int]:\n    return\n",
        "def either(flag: bool) -> int | str:\n    return\n",
        "def anything() -> object:\n    return\n",
        "def loose():\n    return\n",
        "def outer() -> int:\n",
        "    def inner():\n        return\n",
        "    inner()\n",
        "    return 2\n"
    );
    assert!(findings_of(clean, "python:S935").is_empty());
}

#[test]
fn s5890_flags_annotated_assignments_with_contradicting_literals() {
    let flagged = "count: int = \"many\"\nratio: float = [1]\nname: str = 5\n";
    assert_eq!(findings_of(flagged, "python:S5890").len(), 3);

    let clean = concat!(
        "count: int = 3\n",
        "flag: bool = True\n",
        "ratio: float = 1\n",
        "values: list[int] = []\n",
        "maybe: Optional[str] = None\n",
        "loose = \"anything\"\n"
    );
    assert!(findings_of(clean, "python:S5890").is_empty());
}

#[test]
fn s5886_flags_returns_contradicting_type_hints() {
    let flagged = concat!(
        "def count() -> int:\n",
        "    return \"many\"\n",
        "def label() -> str:\n",
        "    if flag:\n",
        "        return 4\n",
        "    return \"ok\"\n"
    );
    assert_eq!(findings_of(flagged, "python:S5886").len(), 2);

    let clean = concat!(
        "def ratio() -> float:\n    return 1\n",
        "def values() -> list[int]:\n    return []\n",
        "def maybe() -> Optional[int]:\n    return None\n",
        "def either(flag: bool) -> int | str:\n    return \"x\"\n"
    );
    assert!(findings_of(clean, "python:S5886").is_empty());
}

#[test]
fn s930_flags_argument_count_mismatches_against_local_defs() {
    let flagged = concat!(
        "def add(a, b):\n    return a + b\n",
        "add(1)\n",
        "add(1, 2, 3)\n",
        "def tagged(value, *, key):\n    return value\n",
        "tagged(1)\n"
    );
    assert_eq!(findings_of(flagged, "python:S930").len(), 3);

    let clean = concat!(
        "def add(a, b):\n    return a + b\n",
        "add(1, 2)\n",
        "add(b=2, a=1)\n",
        "def opt(first, second=2):\n    return first\n",
        "opt(1)\n",
        "def rest(*parts):\n    return parts\n",
        "rest()\n",
        "rest(1, 2)\n"
    );
    assert!(findings_of(clean, "python:S930").is_empty());
}

#[test]
fn s930_checks_methods_and_constructors_file_locally() {
    let flagged = concat!(
        "class Dog:\n",
        "    def __init__(self, name):\n        self.name = name\n",
        "    def speak(self, times):\n        return times\n",
        "Dog()\n",
        "d = Dog('rex')\n",
        "d.speak()\n"
    );
    assert_eq!(findings_of(flagged, "python:S930").len(), 2);

    let clean = concat!(
        "class Cat:\n",
        "    def purr(self, volume=1):\n        return volume\n",
        "c = Cat()\n",
        "c.purr()\n",
        "c.purr(3)\n"
    );
    assert!(findings_of(clean, "python:S930").is_empty());
}

#[test]
fn s5655_flags_arguments_contradicting_parameter_annotations() {
    let flagged = concat!(
        "def repeat(text: str, times: int) -> str:\n",
        "    return text * times\n",
        "repeat(5, 2)\n",
        "repeat(\"a\", times=\"b\")\n"
    );
    assert_eq!(findings_of(flagged, "python:S5655").len(), 2);

    let clean = concat!(
        "def repeat(text: str, times: int) -> str:\n    return text * times\n",
        "repeat(\"a\", 2)\n",
        "repeat(times=3, text=\"a\")\n",
        "def loose(value):\n    return value\n",
        "loose([1])\n"
    );
    assert!(findings_of(clean, "python:S5655").is_empty());
}

#[test]
fn s2876_flags_non_iterator_iter_returns() {
    let flagged_literal = concat!(
        "class Bag:\n",
        "    def __iter__(self):\n",
        "        return [1, 2]\n"
    );
    assert_eq!(findings_of(flagged_literal, "python:S2876").len(), 1);

    let flagged_call = concat!(
        "class Bag:\n",
        "    def __init__(self):\n        self.items = [1]\n",
        "    def __iter__(self):\n        return sorted(self.items)\n"
    );
    assert_eq!(findings_of(flagged_call, "python:S2876").len(), 1);

    let clean = concat!(
        "class Bag:\n",
        "    def __iter__(self):\n        return iter([1, 2])\n",
        "class Gen:\n",
        "    def __iter__(self):\n        yield 1\n",
        "class SelfIter:\n",
        "    def __iter__(self):\n        return self\n"
    );
    assert!(findings_of(clean, "python:S2876").is_empty());
}

#[test]
fn s2638_flags_overrides_that_change_contracts() {
    let flagged_rename = concat!(
        "class Animal:\n",
        "    def speak(self, word, times=1):\n        return word * times\n",
        "class Dog(Animal):\n",
        "    def speak(self, sound, times=1):\n        return sound * times\n"
    );
    assert_eq!(findings_of(flagged_rename, "python:S2638").len(), 1);

    let flagged_required = concat!(
        "class Loader:\n",
        "    def pull(self, path, *, strict=False):\n        return path\n",
        "class FastLoader(Loader):\n",
        "    def pull(self, path, *, strict):\n        return path\n"
    );
    assert_eq!(findings_of(flagged_required, "python:S2638").len(), 1);

    let clean = concat!(
        "class Animal:\n",
        "    def speak(self, word, times=1):\n        return word * times\n",
        "class Dog(Animal):\n",
        "    def speak(self, word, times=1):\n        return word * times\n",
        "class Cat(Animal):\n",
        "    def speak(self, word, times=1, tone=\"high\"):\n        return word * times\n"
    );
    assert!(findings_of(clean, "python:S2638").is_empty());
}

#[test]
fn s5713_flags_subclass_and_parent_sharing_an_except_clause() {
    let flagged_direct = concat!(
        "class AppError(Exception):\n    pass\n",
        "class NotFound(AppError):\n    pass\n",
        "try:\n    pass\nexcept (NotFound, AppError):\n    pass\n"
    );
    assert_eq!(findings_of(flagged_direct, "python:S5713").len(), 1);

    let flagged_transitive = concat!(
        "class Top(Exception):\n    pass\n",
        "class Middle(Top):\n    pass\n",
        "class Leaf(Middle):\n    pass\n",
        "try:\n    pass\nexcept (Leaf, Top):\n    pass\n"
    );
    assert_eq!(findings_of(flagged_transitive, "python:S5713").len(), 1);

    let clean = concat!(
        "class AppError(Exception):\n    pass\n",
        "class NotFound(AppError):\n    pass\n",
        "try:\n    pass\nexcept (NotFound, ValueError):\n    pass\n",
        "try:\n    pass\nexcept NotFound:\n    pass\n"
    );
    assert!(findings_of(clean, "python:S5713").is_empty());
}
#[test]
fn s100_and_s1542_partition_functions_by_class_nesting() {
    let report = analyze(
        PathBuf::from("test.py"),
        "class C:\n    def BadName(self):\n        pass\n",
        &AnalyzerOptions::default(),
    );
    let s100: Vec<_> = report
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:S100")
        .collect();
    assert_eq!(s100.len(), 1);
    assert_eq!(s100[0].range.start.line, 2);

    // A def nested inside a method is a nested function: python:S1542,
    // never python:S100. Compliant names stay silent.
    let nested = analyze(
        PathBuf::from("test.py"),
        "class C:\n    def ok(self):\n        def Inner():\n            pass\n",
        &AnalyzerOptions::default(),
    );
    let s1542: Vec<_> = nested
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:S1542")
        .collect();
    assert_eq!(s1542.len(), 1);
    assert_eq!(s1542[0].range.start.line, 3);
    assert!(
        nested
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S100")
    );
}

#[test]
fn s1542_flags_module_and_nested_functions_on_boundary_shapes() {
    let violating = analyze(
        PathBuf::from("test.py"),
        "def Outer():\n    pass\n\n\ndef _ok_name():\n    pass\n",
        &AnalyzerOptions::default(),
    );
    let s1542: Vec<_> = violating
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:S1542")
        .collect();
    assert_eq!(s1542.len(), 1);
    assert_eq!(s1542[0].range.start.line, 1);

    // Dunder-style names comply; digits and underscores follow the lead
    // character.
    let clean = analyze(
        PathBuf::from("test.py"),
        "def __enter__():\n    pass\n\n\ndef x_1():\n    pass\n",
        &AnalyzerOptions::default(),
    );
    assert!(
        clean
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S1542")
    );
}
#[test]
fn s101_flags_non_conforming_class_names_on_boundary_shapes() {
    // A trailing underscore breaks every branch of the pattern.
    assert_eq!(
        findings_of("class FooBar_:\n    pass\n", "python:S101").len(),
        1
    );
    // Mixed case after the optional lead underscore breaks both branches.
    assert_eq!(
        findings_of("class _fooBar:\n    pass\n", "python:S101").len(),
        1
    );
    // PascalCase, leading-underscore PascalCase and snake_case comply.
    assert!(findings_of(
            "class FooBar:\n    pass\n\n\nclass _Private:\n    pass\n\n\nclass snake_case:\n    pass\n",
            "python:S101"
        )
        .is_empty());
}
#[test]
fn s116_flags_class_fields_on_boundary_shapes() {
    // Upper-case constants violate the field pattern; multi-target
    // assignments report each offending name.
    assert_eq!(
        findings_of("class C:\n    Value = 1\n", "python:S116").len(),
        1
    );
    assert_eq!(
        findings_of("class C:\n    A = B = 1\n", "python:S116").len(),
        2
    );
    // No digit directly after the lead character.
    assert_eq!(
        findings_of("class C:\n    _1bad = 1\n", "python:S116").len(),
        1
    );
    // Lowercase, underscore-prefixed, dunder and digit-tailed names
    // comply.
    assert!(
        findings_of(
            "class C:\n    value = 1\n    _hidden = 2\n    __dunder__ = 3\n    x_1 = 4\n",
            "python:S116"
        )
        .is_empty()
    );
}
#[test]
fn s117_flags_non_conforming_parameters_and_locals_once() {
    assert_eq!(
        findings_of("def f(good, Bad):\n    pass\n", "python:S117").len(),
        1
    );
    // Star-args shapes count as parameters.
    assert_eq!(
        findings_of("def f(*Args, **Kw):\n    pass\n", "python:S117").len(),
        2
    );
    // Locals bind through assignment, for loops and except clauses.
    assert_eq!(
        findings_of("def f():\n    Bad = 1\n", "python:S117").len(),
        1
    );
    assert_eq!(
        findings_of(
            "def f():\n    for Item in []:\n        pass\n",
            "python:S117"
        )
        .len(),
        1
    );
    assert_eq!(
        findings_of(
            "def f():\n    try:\n        pass\n    except ValueError as Err:\n        pass\n",
            "python:S117"
        )
        .len(),
        1
    );
    // A rebound offending name is reported once per scope.
    assert_eq!(
        findings_of("def f():\n    Bad = 1\n    Bad = 2\n", "python:S117").len(),
        1
    );
    // Compliant snake_case names stay silent.
    assert!(
        findings_of(
            "def f(_ok, x_1=None, *a, **kw):\n    y_1 = _ok\n",
            "python:S117"
        )
        .is_empty()
    );
}
#[test]
fn s104_flags_files_exceeding_maximum_lines_of_code() {
    let options = AnalyzerOptions {
        maximum_lines_of_code: 3,
        ..AnalyzerOptions::default()
    };

    // Exactly at the limit: silent.
    let boundary = analyze(PathBuf::from("test.py"), "a = 1\nb = 2\nc = 3\n", &options);
    assert!(
        boundary
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S104")
    );

    // One code line over the limit: flagged once, anchored at line 1.
    let over = analyze(
        PathBuf::from("test.py"),
        "a = 1\nb = 2\nc = 3\n\n# comment only\nd = 4\n",
        &options,
    );
    let s104: Vec<_> = over
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:S104")
        .collect();
    assert_eq!(s104.len(), 1);
    assert_eq!(s104[0].range.start.line, 1);
}

#[test]
fn s107_flags_functions_exceeding_parameter_budget() {
    let options = AnalyzerOptions {
        maximum_function_parameters: 2,
        ..AnalyzerOptions::default()
    };

    // Exactly at the limit: silent.
    let boundary = analyze(
        PathBuf::from("test.py"),
        "def f(a, b):\n    pass\n",
        &options,
    );
    assert!(
        boundary
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S107")
    );

    // One parameter over: flagged on the function name.
    let over = analyze(
        PathBuf::from("test.py"),
        "def f(a, b, c):\n    pass\n",
        &options,
    );
    let s107: Vec<_> = over
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:S107")
        .collect();
    assert_eq!(s107.len(), 1);
    assert_eq!(s107[0].range.start.line, 1);

    // Star args and kwargs each count toward the budget.
    let starred = analyze(
        PathBuf::from("test.py"),
        "def f(a, b, *args, **kwargs):\n    pass\n",
        &options,
    );
    assert_eq!(
        starred
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "python:S107")
            .count(),
        1
    );

    // The catalog default budget keeps ordinary signatures silent.
    let defaults = analyze(
        PathBuf::from("test.py"),
        "def f(a, b, c):\n    pass\n",
        &AnalyzerOptions::default(),
    );
    assert!(
        defaults
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S107")
    );
}
#[test]
fn s1142_counts_only_the_functions_own_returns() {
    // Exactly three own returns stay silent at the catalog default.
    assert!(
        findings_of(
            "def f():\n    return 1\n    return 2\n    return 3\n",
            "python:S1142"
        )
        .is_empty()
    );
    // Four own returns exceed the budget.
    assert_eq!(
        findings_of(
            "def f():\n    return 1\n    return 2\n    return 3\n    return 4\n",
            "python:S1142"
        )
        .len(),
        1
    );
    // A nested definition owns its returns: the outer function stays
    // silent while the inner one is flagged on its own budget.
    let nested = analyze(
        PathBuf::from("test.py"),
        "def outer():\n    def inner():\n        return 1\n        return 2\n        return 3\n        return 4\n    return 0\n",
        &AnalyzerOptions::default(),
    );
    let s1142: Vec<_> = nested
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:S1142")
        .collect();
    assert_eq!(s1142.len(), 1);
    assert_eq!(s1142[0].range.start.line, 2);
}
#[test]
fn s138_flags_functions_exceeding_the_line_budget() {
    let options = AnalyzerOptions {
        maximum_function_length: 4,
        ..AnalyzerOptions::default()
    };

    // Exactly four lines of span: silent.
    let boundary = analyze(
        PathBuf::from("test.py"),
        "def f():\n    a = 1\n    b = 2\n    c = 3\n",
        &options,
    );
    assert!(
        boundary
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S138")
    );

    // Five lines of span: flagged once on the function name.
    let over = analyze(
        PathBuf::from("test.py"),
        "def f():\n    a = 1\n    b = 2\n    c = 3\n    d = 4\n",
        &options,
    );
    let s138: Vec<_> = over
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:S138")
        .collect();
    assert_eq!(s138.len(), 1);
    assert_eq!(s138[0].range.start.line, 1);

    // The catalog default budget keeps ordinary functions silent.
    let defaults = analyze(
        PathBuf::from("test.py"),
        "def f():\n    a = 1\n    b = 2\n    c = 3\n    d = 4\n",
        &AnalyzerOptions::default(),
    );
    assert!(
        defaults
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S138")
    );
}
#[test]
fn s134_flags_constructs_beyond_the_default_four_levels() {
    // Four nested levels stay silent at the catalog default.
    let boundary = analyze(
        PathBuf::from("test.py"),
        "for a in []:\n    for b in []:\n        while b:\n            if a:\n                pass\n",
        &AnalyzerOptions::default(),
    );
    assert!(
        boundary
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S134")
    );

    // A fifth level is flagged once, on its own construct.
    let over = analyze(
        PathBuf::from("test.py"),
        "for a in []:\n    for b in []:\n        while b:\n            if a:\n                if a:\n                    pass\n",
        &AnalyzerOptions::default(),
    );
    let s134: Vec<_> = over
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:S134")
        .collect();
    assert_eq!(s134.len(), 1);
    assert_eq!(s134[0].range.start.line, 5);
}

#[test]
fn s134_elif_chains_and_nested_units_do_not_inflate_depth() {
    // An elif chain shares its `if`'s single level.
    let chain = analyze(
        PathBuf::from("test.py"),
        "for a in []:\n    for b in []:\n        while b:\n            if a:\n                pass\n            elif a:\n                pass\n            elif a:\n                pass\n            else:\n                pass\n",
        &AnalyzerOptions::default(),
    );
    assert!(
        chain
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S134")
    );

    // Nested definitions are separate units and reset the counter.
    let units = analyze(
        PathBuf::from("test.py"),
        "def outer():\n    for a in []:\n        def inner():\n            for b in []:\n                pass\n",
        &AnalyzerOptions::default(),
    );
    assert!(
        units
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S134")
    );
}

#[test]
fn s1066_flags_sole_nested_if_without_clauses() {
    let flagged = scan("if a:\n    if b:\n        work()\n");
    assert_eq!(findings(&flagged, "python:S1066").len(), 1);
    // A chain of three mergeable levels flags both inner ifs.
    let chain = scan("if a:\n    if b:\n        if c:\n            work()\n");
    assert_eq!(findings(&chain, "python:S1066").len(), 2);
}

#[test]
fn s1066_spares_semantics_changing_shapes() {
    // Extra statements in the enclosing suite prevent the merge.
    assert!(
        findings(
            &scan("if a:\n    setup()\n    if b:\n        work()\n"),
            "python:S1066"
        )
        .is_empty()
    );
    for source in [
        "if a:\n    if b:\n        work()\n    else:\n        stop()\n",
        "if a:\n    work()\nelif a:\n    if b:\n        work()\n",
    ] {
        assert!(findings(&scan(source), "python:S1066").is_empty());
    }
}

#[test]
fn s108_flags_placeholder_only_non_function_suites() {
    let flagged = scan(concat!(
        "class C:\n",
        "    pass\n",
        "if a:\n",
        "    ...\n",
        "try:\n",
        "    pass\n",
        "except ValueError:\n",
        "    pass\n",
        "while b:\n",
        "    pass\n",
    ));
    // Class body, if body, try body, handler, and while body: five blocks.
    assert_eq!(findings(&flagged, "python:S108").len(), 5);
}

#[test]
fn s108_treats_docstrings_and_functions_as_content() {
    for clean in [
        "class C:\n    \"\"\"Documented.\"\"\"\n",
        "def f():\n    pass\n",
        "if a:\n    work()\nelse:\n    other()\n",
        "for x in xs:\n    step(x)\n",
    ] {
        assert!(findings(&scan(clean), "python:S108").is_empty());
    }
}

#[test]
fn s1110_flags_inner_paren_pairs_with_single_content() {
    let flagged = scan("print((\"Hello\" + name))\nvalue = ((a))\n");
    let found = findings(&flagged, "python:S1110");
    assert_eq!(found.len(), 2);
}

#[test]
fn s1110_spares_meaningful_and_empty_pairs() {
    for clean in [
        // Tuples change arity when the inner pair is removed.
        "pair = ((a, b))\nreturning = f((a, b))\n",
        // Empty pairs and string-only interiors are skipped.
        "unit = ()\nnested = (())\ntext = (\"s\")\n",
        // Call and grouping parentheses are load-bearing.
        "plain = (a)\ncalled = f(a)\nsub = table[(a)]\n",
    ] {
        assert!(findings(&scan(clean), "python:S1110").is_empty());
    }
}

#[test]
fn s1186_flags_placeholder_only_functions() {
    let flagged = scan(concat!(
        "def bare():\n",
        "    pass\n",
        "def stub():\n",
        "    ...\n",
        "class C:\n",
        "    def method(self):\n",
        "        pass\n",
    ));
    assert_eq!(findings(&flagged, "python:S1186").len(), 3);
}

#[test]
fn s1186_spares_documented_and_contractual_stubs() {
    for clean in [
        // A docstring already fills the function.
        "def documented():\n    \"\"\"Docs.\"\"\"\n",
        // Protocol-style abstract and overload stubs are empty by contract.
        "from abc import abstractmethod\nclass P:\n    @abstractmethod\n    def hook(self):\n        pass\n    @overload\n    def build(self):\n        ...\n",
        // Real bodies are not empty.
        "def real():\n    return 1\n",
    ] {
        assert!(findings(&scan(clean), "python:S1186").is_empty());
    }
}

#[test]
fn s1700_flags_members_named_like_their_class() {
    let flagged = scan(concat!(
        "class Sample:\n",
        "    def sample(self):\n",
        "        return 1\n",
        "    Sample = 3\n",
    ));
    assert_eq!(findings(&flagged, "python:S1700").len(), 2);
}

#[test]
fn s1700_spares_differing_or_foreign_names() {
    for clean in [
        // Different member names are fine.
        "class Sample:\n    def render(self):\n        return 1\n",
        // Only the immediate class scope counts; the outer class is untouched.
        "class Outer:\n    class Inner:\n        def outer(self):\n            return 1\n",
    ] {
        assert!(findings(&scan(clean), "python:S1700").is_empty());
    }
}

#[test]
fn s1722_flags_classes_without_bases() {
    assert_eq!(
        findings(&scan("class Bare:\n    pass\n"), "python:S1722").len(),
        1
    );
    assert_eq!(
        findings(&scan("class EmptyParens():\n    pass\n"), "python:S1722").len(),
        1
    );
}

#[test]
fn s1722_spares_explicit_inheritance() {
    for clean in [
        "class Object(object):\n    pass\n",
        "class Base(BaseError):\n    pass\n",
        "class Keyword(kw=object):\n    pass\n",
    ] {
        assert!(findings(&scan(clean), "python:S1722").is_empty());
    }
}

#[test]
fn s1720_flags_public_definitions_without_docstrings() {
    let flagged =
        scan("def bare():\n    return 1\nclass C:\n    def method(self):\n        return 2\n");
    assert_eq!(findings(&flagged, "python:S1720").len(), 2);
}

#[test]
fn s1720_spares_private_and_documented_functions() {
    for clean in [
        // Underscore-prefixed names are private; dunders are exempt too.
        "def _helper():\n    return 1\nclass C:\n    def __init__(self):\n        self.x = 1\n",
        // A docstring fills the contract.
        "def documented():\n    \"\"\"Docs.\"\"\"\n",
        "class C:\n    def method(self):\n        \"\"\"Docs.\"\"\"\n",
    ] {
        assert!(findings(&scan(clean), "python:S1720").is_empty());
    }
}

#[test]
fn s1845_flags_case_only_collisions_in_scope() {
    let module = scan("value = 1\nValue = 2\n");
    assert_eq!(findings(&module, "python:S1845").len(), 1);
    let class_scope = scan(concat!(
        "class C:\n",
        "    def render(self):\n",
        "        return 1\n",
        "    RENDER = 2\n",
    ));
    assert_eq!(findings(&class_scope, "python:S1845").len(), 1);
}
#[test]
fn s1845_spares_identical_names_and_separate_scopes() {
    for clean in [
        // Exact duplicates are redefinitions, not case collisions.
        "value = 1\nvalue = 2\n",
        // Members of separate class scopes never collide.
        "class A:\n    def go(self):\n        return 1\nclass B:\n    def go(self):\n        return 2\n",
        "def outer():\n    value = 1\nvalue = 2\n",
    ] {
        assert!(findings(&scan(clean), "python:S1845").is_empty());
    }
}

#[test]
fn s3776_scores_nesting_weighted_structures() {
    let source = concat!(
        "def f(a, b):\n",
        "    if a:\n",
        "        if b:\n",
        "            if a and b:\n",
        "                pass\n",
    );
    // cognitive = if(1) + nested if(2) + nested if(3) + boolop chain(1) = 7.
    for (threshold, expected) in [(6, 1), (7, 0)] {
        let options = AnalyzerOptions {
            maximum_cognitive_complexity: threshold,
            ..AnalyzerOptions::default()
        };
        let report = analyze(PathBuf::from("t.py"), source, &options);
        assert_eq!(findings(&report, "python:S3776").len(), expected);
    }
}

#[test]
fn s3776_threshold_is_configurable() {
    let options = AnalyzerOptions {
        maximum_cognitive_complexity: 1,
        ..AnalyzerOptions::default()
    };
    // Two sequential ifs score 2 cognitive points.
    let report = analyze(
        PathBuf::from("t.py"),
        "def f(a, b):\n    if a:\n        pass\n    if b:\n        pass\n",
        &options,
    );
    let found = findings(&report, "python:S3776");
    assert_eq!(found.len(), 1);
    assert_eq!(
        found[0].message,
        "Refactor this function to reduce its Cognitive Complexity from 2 to the 1 allowed."
    );
}

#[test]
fn function_complexity_flags_past_threshold_with_baseline() {
    // if(1) + elif(1) + for(1) + while(1) + boolop values-1(1) + baseline(1)
    // = 6, which exceeds the lowered threshold of 4.
    let source = concat!(
        "def f(a, b, c):\n",
        "    if a:\n",
        "        pass\n",
        "    elif b:\n",
        "        pass\n",
        "    else:\n",
        "        pass\n",
        "    for x in []:\n",
        "        while c or a:\n",
        "            pass\n",
    );
    let options = AnalyzerOptions {
        maximum_function_complexity: 4,
        ..AnalyzerOptions::default()
    };
    // if(1) + elif(1) + for(1) + while(1) + boolop values-1(1) + baseline(1) = 6
    let report = analyze(PathBuf::from("t.py"), source, &options);
    assert_eq!(findings(&report, "python:FunctionComplexity").len(), 1);
}

#[test]
fn file_complexity_sums_all_function_units() {
    let source = concat!(
        "def f():\n",
        "    if a:\n",
        "        pass\n",
        "\n",
        "def g():\n",
        "    if b:\n",
        "        pass\n",
    );
    // Each unit: baseline 1 + one if = 2; total 4 exceeds the lowered bar.
    let options = AnalyzerOptions {
        maximum_file_complexity: 3,
        ..AnalyzerOptions::default()
    };
    let report = analyze(PathBuf::from("t.py"), source, &options);
    assert_eq!(findings(&report, "python:FileComplexity").len(), 1);
    assert!(findings(&scan(source), "python:FileComplexity").is_empty());
}

#[test]
fn class_complexity_sums_direct_methods() {
    let source = concat!(
        "class C:\n",
        "    def m(self):\n",
        "        if a:\n",
        "            pass\n",
        "    def n(self):\n",
        "        try:\n",
        "            pass\n",
        "        except ValueError:\n",
        "            pass\n",
    );
    // Methods: (1 + 1) + (1 + 1 handler) = 4.
    let options = AnalyzerOptions {
        maximum_class_complexity: 3,
        ..AnalyzerOptions::default()
    };
    let report = analyze(PathBuf::from("t.py"), source, &options);
    assert_eq!(findings(&report, "python:ClassComplexity").len(), 1);
    assert!(findings(&scan(source), "python:ClassComplexity").is_empty());
}

#[test]
fn complexity_units_exclude_nested_definitions_and_count_match_cases() {
    let source = concat!(
        "def outer(v):\n",
        "    match v:\n",
        "        case 1:\n",
        "            pass\n",
        "        case _:\n",
        "            def inner(x):\n",
        "                if x:\n",
        "                    pass\n",
        "                return [y for y in v if y]\n",
    );
    // outer: match cases(2) + baseline(1) = 3; the comprehension filter
    // and the `if` belong to inner's own unit, which also scores 3.
    let options = AnalyzerOptions {
        maximum_function_complexity: 2,
        ..AnalyzerOptions::default()
    };
    let report = analyze(PathBuf::from("t.py"), source, &options);
    assert_eq!(findings(&report, "python:FunctionComplexity").len(), 2);
    assert!(findings(&scan(source), "python:FunctionComplexity").is_empty());
}

#[test]
fn s6799_flags_f_strings_nested_three_levels_deep() {
    let flagged = scan("deep = f\"{f\"{f\"{x}\"}\"}\"\n");
    assert_eq!(findings(&flagged, "python:S6799").len(), 1);
}

#[test]
fn s6799_spares_single_and_double_level_nesting() {
    for clean in [
        "flat = f\"value {x}\"\n",
        "once = f\"outer {f\"inner {x}\"} end\"\n",
        "plain = \"no interpolation at all\"\n",
    ] {
        assert!(findings(&scan(clean), "python:S6799").is_empty());
    }
}
