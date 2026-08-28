use std::path::PathBuf;

use super::{AnalyzerOptions, analyze};
use crate::test_support::{
    findings, findings_of, issue, pos, regex_finds, scan, scan_with_options,
};

#[test]
fn one_statement_per_line_flags_the_complete_statement_sequence() {
    let report = scan("a = 1\nb = 2\nc = 3; d = 4\n");
    assert_eq!(
        report.issues,
        vec![
            hoonarqube_ir::Issue::new(
                "python:S1720",
                "Add a docstring to this module.",
                hoonarqube_ir::Range::file_level(),
            ),
            issue(
                "python:S1481",
                "Remove the unused local variable \"a\".",
                (1, 0),
                (1, 1),
            ),
            issue(
                "python:S1481",
                "Remove the unused local variable \"b\".",
                (2, 0),
                (2, 1),
            ),
            issue(
                "python:S1481",
                "Remove the unused local variable \"c\".",
                (3, 0),
                (3, 1),
            ),
            issue(
                "python:OneStatementPerLine",
                "At most one statement is allowed per line, but 2 statements were found on this line.",
                (3, 0),
                (3, 12),
            ),
            issue(
                "python:S1481",
                "Remove the unused local variable \"d\".",
                (3, 7),
                (3, 8),
            ),
        ]
    );
}

#[test]
fn exec_and_print_calls_are_py3_calls_and_not_flagged() {
    // CE matches only py2 statement forms; under py3 parsing `exec(...)` and
    // `print(...)` are plain builtin calls and stay out of scope. Attribute
    // access is untouched either way.
    let source = "exec(\"x = 1\")\nprint(\"hi\")\nobj.exec(1)\nsys.print(2)\n";
    assert!(findings(&scan(source), "python:ExecStatementUsage").is_empty());
    assert!(findings(&scan(source), "python:PrintStatementUsage").is_empty());
}

#[test]
fn metrics_count_code_comment_and_blank_lines() {
    let report = scan("x = 1\n# only a comment\n\n");
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
    let report = scan("if x:\n  y = 1; z = 2\n");
    let split_issues: Vec<_> = report
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:OneStatementPerLine")
        .collect();
    assert_eq!(split_issues.len(), 1);
    assert_eq!(split_issues[0].range.start, pos(2, 2));
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
                hoonarqube_ir::Issue::new(
                    "python:S1720",
                    "Add a docstring to this module.",
                    hoonarqube_ir::Range::file_level(),
                ),
                issue(
                    "python:S1720",
                    "Add a docstring to this function.",
                    (3, 4),
                    (3, 9),
                ),
                issue(
                    "python:OneStatementPerLine",
                    "At most one statement is allowed per line, but 2 statements were found on this line.",
                    (6, 4),
                    (6, 16),
                ),
                issue(
                    "python:NoSonar",
                    "Is #NOSONAR used to exclude false-positive or to hide real quality flaw?",
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
    assert_eq!(found[0].range.start.line, 1);
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
fn s1192_flags_duplicated_literals_per_function_scope() {
    // CE counts occurrences within one function; three module-level copies stay silent.
    assert!(
        findings(
            &scan("a = \"dup\"\nb = \"dup\"\nc = \"dup\"\n"),
            "python:S1192"
        )
        .is_empty()
    );
    let flagged = scan("def run():\n    x = \"dup\" + \"dup\"\n    return \"dup\"\n\n\nrun()\n");
    assert_eq!(findings(&flagged, "python:S1192").len(), 2);
    // Occurrences in separate functions never accumulate across scopes.
    let split = scan("def a():\n    return \"dup\"\n\ndef b():\n    return \"dup\"\n");
    assert!(findings(&split, "python:S1192").is_empty());
}

#[test]
fn s1192_exclusion_regex_suppresses_matches() {
    let options = AnalyzerOptions {
        duplicate_literal_exclusion_regex: "dup".to_string(),
        ..AnalyzerOptions::default()
    };
    let report = scan_with_options(
        "def run():\n    x = \"dup\" + \"dup\"\n    return \"dup\"\n\n\nrun()\n",
        &options,
    );
    assert!(findings(&report, "python:S1192").is_empty());
}

#[test]
fn s1192_sees_duplicates_inside_pep695_type_aliases() {
    // PEP 695 alias values must reach the shared walk tables; identical alias
    // values duplicate exactly like assigned string literals (catalog S1192
    // threshold: 3 occurrences within one function scope).
    let flagged = scan(
        "def run():\n    type Bucket = Literal[\"dup\"]\n    type Mirror = Literal[\"dup\"]\n    type Trio = Literal[\"dup\"]\n\n\nrun()\n",
    );
    assert!(!findings(&flagged, "python:S1192").is_empty());
    let single = scan("type Bucket = Literal[\"dup\"]\n");
    assert!(findings(&single, "python:S1192").is_empty());
}

#[test]
fn s5828_flags_invalid_open_modes_only() {
    let flagged = scan("open(\"d\", \"q\")\nopen(\"d\", mode=\"rr\")\nopen(\"d\", \"rb\")\n");
    assert_eq!(findings(&flagged, "python:S5828").len(), 1);
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
fn s5717_flags_mutated_defaults() {
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
    assert_eq!(findings(&flagged, "python:S5717").len(), 1);
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
fn s5806_flags_function_local_builtin_shadowing_only() {
    let flagged =
        scan("def process(items):\n    len = len(items)\n    return len\n\n\nprocess([1])\n");
    assert_eq!(findings(&flagged, "python:S5806").len(), 1);
    // CE scopes the rule to function locals; module-level rebinding stays silent.
    assert!(findings(&scan("id = 42\n"), "python:S5806").is_empty());
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
fn s5953_accepts_match_capture_pattern_bindings() {
    let source = concat!(
        "def handle(cmd):\n",
        "    match cmd:\n",
        "        case \"go\", dist:\n",
        "            print(dist)\n",
    );
    assert!(findings(&scan(source), "python:S5953").is_empty());
    let undefined = concat!(
        "def handle(cmd):\n",
        "    match cmd:\n",
        "        case _:\n",
        "            print(never_defined)\n",
    );
    assert_eq!(findings(&scan(undefined), "python:S5953").len(), 1);
}

#[test]
fn s5953_accepts_later_comprehension_iterables_using_earlier_targets() {
    let source = "xs = [1, 2]\nys = [1, 2]\nresult = [x * y for x in xs for y in zip(x, ys)]\n";
    assert!(findings(&scan(source), "python:S5953").is_empty());
}

#[test]
fn s125_applies_catalog_exception_parameter_default() {
    let exempt = concat!(
        "# fmt: if x == 1: y = 2\n",
        "# py2: print undefined_thing\n",
        "# pylint: disable=all\n",
    );
    assert!(findings(&scan(exempt), "python:S125").is_empty());
    let flagged = "# value = compute(1)\n";
    assert_eq!(findings(&scan(flagged), "python:S125").len(), 1);
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
fn s2159_flags_only_self_comparisons() {
    let flagged = scan(
        "def decide(flag):\n    if flag == flag:\n        return 1\n    return 0\n\n\ndecide(True)\n",
    );
    assert_eq!(findings(&flagged, "python:S2159").len(), 1);
    // Constant-folding through known initializers exceeds the CE engine's scope.
    let known_initializer = scan(
        "def decide(flag):\n    expected = True\n    if expected == True:\n        return 1\n    return 0\n\n\ndecide(True)\n",
    );
    assert!(findings(&known_initializer, "python:S2159").is_empty());
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
    let custom_clean = scan_with_options(
        "def run():\n    scratch_pad = 1\n    leftover = 2\n    return leftover\n\n\nrun()\n",
        &options,
    );
    assert!(findings(&custom_clean, "python:S1481").is_empty());
    let custom_flagged =
        scan("def run():\n    scratch_pad = 1\n    leftover = 2\n    return leftover\n\n\nrun()\n");
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
    let enabled = scan_with_options(source, &options);
    assert_eq!(findings(&enabled, "python:S4487").len(), 1);
}
// -----------------------------------------------------------------------
// regex engine + Tier-B regex rules.
// -----------------------------------------------------------------------

use super::{RxUnit, decode_string_part};

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
    assert!(regex_finds(
        "import re\nre.compile(r'(?#oops')\n",
        "python:S5856"
    ));
    assert!(!regex_finds(
        "import re\nre.compile(r'(?#ok)a')\n",
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
fn s6281_requires_full_s3_public_access_block() {
    let flagged = concat!(
        "client = boto3.client(\"s3\")\n",
        "s3.put_public_access_block(\n",
        "    Bucket=\"b\",\n",
        "    PublicAccessBlockConfiguration={\"BlockPublicAcls\": True},\n",
        ")\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6281").len(), 0);
    // Stub-only files carry no resolvable boto3 client and stay silent (CE parity).
    let stub_only = "s3.put_public_access_block(\n    Bucket=\"b\",\n    PublicAccessBlockConfiguration={\"BlockPublicAcls\": True},\n)\n";
    assert!(findings(&scan(stub_only), "python:S6281").is_empty());
    let clean = concat!(
        "client = boto3.client(\"s3\")\n",
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
fn s6302_flags_wildcard_action_policies() {
    let flagged = concat!(
        "client = boto3.resource(\"iam\")\n",
        "p1 = {\"Action\": \"*\"}\n",
        "p2 = {\"Action\": [\"s3:*\", \"ec2:RunInstances\"]}\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6302").len(), 0);
    let stub_only = concat!(
        "p1 = {\"Action\": \"*\"}\n",
        "p2 = {\"Action\": [\"s3:*\", \"ec2:RunInstances\"]}\n"
    );
    assert!(findings(&scan(stub_only), "python:S6302").is_empty());
    assert!(
        findings(
            &scan(concat!(
                "client = boto3.resource(\"iam\")\n",
                "p3 = {\"Action\": [\"s3:GetObject\"]}\n"
            )),
            "python:S6302"
        )
        .is_empty()
    );
}

#[test]
fn s6304_flags_all_resources_policies() {
    let flagged = concat!(
        "client = boto3.client(\"s3\")\n",
        "p1 = {\"Effect\": \"Allow\", \"Resource\": \"*\"}\n",
        "p2 = {\"Effect\": \"Allow\", \"Resource\": [\"*\"]}\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6304").len(), 0);
    let stub_only = "p1 = {\"Effect\": \"Allow\", \"Resource\": \"*\"}\np2 = {\"Effect\": \"Allow\", \"Resource\": [\"*\"]}\n";
    assert!(findings(&scan(stub_only), "python:S6304").is_empty());
    assert!(
        findings(
            &scan(concat!(
                "client = boto3.client(\"s3\")\n",
                "p3 = {\"Effect\": \"Allow\", \"Resource\": \"arn:aws:s3:::bucket/*\"}\n"
            )),
            "python:S6304"
        )
        .is_empty()
    );
}

#[test]
fn s6303_requires_rds_storage_encryption() {
    let flagged = concat!(
        "rds = boto3.client(\"rds\")\n",
        "rds.create_db_instance(DBInstanceIdentifier=\"db\")\n",
        "rds.create_db_cluster(DBClusterIdentifier=\"c\", StorageEncrypted=False)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6303").len(), 0);
    let stub_only = concat!(
        "rds.create_db_instance(DBInstanceIdentifier=\"db\")\n",
        "rds.create_db_cluster(DBClusterIdentifier=\"c\", StorageEncrypted=False)\n"
    );
    assert!(findings(&scan(stub_only), "python:S6303").is_empty());
    assert!(
        findings(
            &scan(concat!(
                "rds = boto3.client(\"rds\")\n",
                "rds.create_db_instance(DBInstanceIdentifier=\"db\", StorageEncrypted=True)\n"
            )),
            "python:S6303"
        )
        .is_empty()
    );
}

#[test]
fn s6308_requires_opensearch_encryption_options() {
    let flagged = concat!(
        "es = boto3.client(\"es\")\n",
        "es.create_domain(DomainName=\"d\")\n",
        "es.create_elasticsearch_domain(DomainName=\"e\")\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6308").len(), 0);
    let stub_only = concat!(
        "client.create_domain(DomainName=\"d\")\n",
        "es.create_elasticsearch_domain(DomainName=\"e\")\n"
    );
    assert!(findings(&scan(stub_only), "python:S6308").is_empty());
    assert!(
        findings(
            &scan(concat!(
                "es = boto3.client(\"es\")\n",
                "es.create_domain(DomainName=\"d\", EncryptionAtRestOptions={\"Enabled\": True})\n"
            )),
            "python:S6308"
        )
        .is_empty()
    );
}

#[test]
fn s6317_flags_wildcard_scoped_actions() {
    let flagged = concat!(
        "client = boto3.client(\"s3\")\n",
        "p = {\"Action\": [\"s3:*\", \"ec2:DescribeInstances\"]}\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6317").len(), 0);
    let stub_only = "p = {\"Action\": [\"s3:*\", \"ec2:DescribeInstances\"]}\n";
    assert!(findings(&scan(stub_only), "python:S6317").is_empty());
    assert!(
        findings(
            &scan(concat!(
                "client = boto3.client(\"s3\")\n",
                "p = {\"Action\": [\"s3:GetObject\", \"ec2:DescribeInstances\"]}\n"
            )),
            "python:S6317"
        )
        .is_empty()
    );
}

#[test]
fn s6319_requires_sagemaker_volume_kms_key() {
    let flagged = concat!(
        "sm = boto3.client(\"sagemaker\")\n",
        "sm.create_notebook_instance(NotebookInstanceName=\"n\", RoleArn=\"r\")\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6319").len(), 0);
    let stub_only = "sm.create_notebook_instance(NotebookInstanceName=\"n\", RoleArn=\"r\")\n";
    assert!(findings(&scan(stub_only), "python:S6319").is_empty());
    assert!(findings(
            &scan(concat!(
                "sm = boto3.client(\"sagemaker\")\n",
                "sm.create_notebook_instance(NotebookInstanceName=\"n\", RoleArn=\"r\", VolumeKmsKeyId=\"k\")\n"
            )),
            "python:S6319"
        )
        .is_empty());
}

#[test]
fn s6321_flags_admin_ports_open_to_world() {
    let flagged = concat!(
        "ec2 = boto3.client(\"ec2\")\n",
        "ec2.authorize_security_group_ingress(GroupId=\"g\", IpPermissions=[\n",
        "    {\"FromPort\": 22, \"ToPort\": 22, \"IpRanges\": [{\"CidrIp\": \"0.0.0.0/0\"}]},\n",
        "])\n",
        "ec2.authorize_security_group_ingress(GroupId=\"g\", IpPermissions=[\n",
        "    {\"FromPort\": 3389, \"ToPort\": 3389, \"IpRanges\": [{\"CidrIp\": \"0.0.0.0/0\"}]},\n",
        "])\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6321").len(), 0);
    let stub_only = concat!(
        "ec2.authorize_security_group_ingress(GroupId=\"g\", IpPermissions=[\n",
        "    {\"FromPort\": 22, \"ToPort\": 22, \"IpRanges\": [{\"CidrIp\": \"0.0.0.0/0\"}]},\n",
        "])\n"
    );
    assert!(findings(&scan(stub_only), "python:S6321").is_empty());
    let clean = concat!(
        "ec2 = boto3.client(\"ec2\")\n",
        "ec2.authorize_security_group_ingress(GroupId=\"g\", IpPermissions=[\n",
        "    {\"FromPort\": 443, \"ToPort\": 443, \"IpRanges\": [{\"CidrIp\": \"10.0.0.0/16\"}]},\n",
        "])\n"
    );
    assert!(findings(&scan(clean), "python:S6321").is_empty());
}

#[test]
fn s6327_requires_sns_kms_master_key() {
    let flagged = "sns = boto3.client(\"sns\")\nsns.create_topic(Name=\"t\")\n";
    assert_eq!(findings(&scan(flagged), "python:S6327").len(), 0);
    assert!(findings(&scan("sns.create_topic(Name=\"t\")\n"), "python:S6327").is_empty());
    assert!(
        findings(
            &scan("sns = boto3.client(\"sns\")\nsns.create_topic(Name=\"t\", KmsMasterKeyId=\"key\")\n"),
            "python:S6327"
        )
        .is_empty()
    );
}

#[test]
fn s6329_flags_public_network_access_flags() {
    let flagged = concat!(
        "session_client = boto3.Session().client(\"ec2\")\n",
        "rds.create_db_instance(DBInstanceIdentifier=\"d\", PubliclyAccessible=True)\n",
        "ec2.modify_subnet_attribute(SubnetId=\"s\", MapPublicIpOnLaunch=True)\n",
        "ec2.run_instances(NetworkInterfaces=[{\"AssociatePublicIpAddress\": True}])\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6329").len(), 0);
    let stub_only = concat!(
        "rds.create_db_instance(DBInstanceIdentifier=\"d\", PubliclyAccessible=True)\n",
        "ec2.modify_subnet_attribute(SubnetId=\"s\", MapPublicIpOnLaunch=True)\n",
        "ec2.run_instances(NetworkInterfaces=[{\"AssociatePublicIpAddress\": True}])\n"
    );
    assert!(findings(&scan(stub_only), "python:S6329").is_empty());
    assert!(
        findings(
            &scan(concat!(
                "ec2 = boto3.client(\"ec2\")\n",
                "rds.create_db_instance(DBInstanceIdentifier=\"d\", PubliclyAccessible=False)\n"
            )),
            "python:S6329"
        )
        .is_empty()
    );
}

#[test]
fn s6330_requires_sqs_kms_master_queue_id() {
    let flagged = "sqs = boto3.client(\"sqs\")\nsqs.create_queue(QueueName=\"q\")\n";
    assert_eq!(findings(&scan(flagged), "python:S6330").len(), 0);
    assert!(findings(&scan("sqs.create_queue(QueueName=\"q\")\n"), "python:S6330").is_empty());
    assert!(
        findings(
            &scan("sqs = boto3.client(\"sqs\")\nsqs.create_queue(QueueName=\"q\", KmsMasterQueueId=\"key\")\n"),
            "python:S6330"
        )
        .is_empty()
    );
}

#[test]
fn s6332_requires_efs_encryption() {
    let flagged = concat!(
        "efs = boto3.client(\"efs\")\n",
        "efs.create_file_system(CreationToken=\"t\")\n",
        "efs.create_file_system(CreationToken=\"t\", Encrypted=False)\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6332").len(), 0);
    let stub_only = concat!(
        "efs.create_file_system(CreationToken=\"t\")\n",
        "efs.create_file_system(CreationToken=\"t\", Encrypted=False)\n"
    );
    assert!(findings(&scan(stub_only), "python:S6332").is_empty());
    assert!(
        findings(
            &scan(concat!(
                "efs = boto3.client(\"efs\")\n",
                "efs.create_file_system(CreationToken=\"t\", Encrypted=True)\n"
            )),
            "python:S6332"
        )
        .is_empty()
    );
}

#[test]
fn s6333_flags_api_gateway_open_authorization() {
    let flagged = concat!(
        "apigw = boto3.client(\"apigateway\")\n",
        "apigw.put_method(restApiId=\"a\", resourceId=\"r\", httpMethod=\"GET\", authorizationType=\"NONE\")\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6333").len(), 0);
    let stub_only = "apigw.put_method(restApiId=\"a\", resourceId=\"r\", httpMethod=\"GET\", authorizationType=\"NONE\")\n";
    assert!(findings(&scan(stub_only), "python:S6333").is_empty());
    assert!(findings(
            &scan(concat!(
                "apigw = boto3.client(\"apigateway\")\n",
                "apigw.put_method(restApiId=\"a\", resourceId=\"r\", httpMethod=\"GET\", authorizationType=\"AWS_IAM\")\n"
            )),
            "python:S6333"
        )
        .is_empty());
}

#[test]
fn s6463_flags_unrestricted_security_group_egress() {
    let flagged = concat!(
        "ec2 = boto3.client(\"ec2\")\n",
        "ec2.authorize_security_group_egress(GroupId=\"g\", IpPermissions=[\n",
        "    {\"IpProtocol\": \"-1\", \"IpRanges\": [{\"CidrIp\": \"0.0.0.0/0\"}]},\n",
        "])\n"
    );
    assert_eq!(findings(&scan(flagged), "python:S6463").len(), 0);
    let stub_only = concat!(
        "ec2.authorize_security_group_egress(GroupId=\"g\", IpPermissions=[\n",
        "    {\"IpProtocol\": \"-1\", \"IpRanges\": [{\"CidrIp\": \"0.0.0.0/0\"}]},\n",
        "])\n"
    );
    assert!(findings(&scan(stub_only), "python:S6463").is_empty());
    let clean = concat!(
        "ec2 = boto3.client(\"ec2\")\n",
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
    assert_eq!(
        messages[0],
        "Fix this call; this expression has type int and it is not callable."
    );
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
    assert_eq!(messages[0], "The return value of \"sorted\" must be used.");
    assert_eq!(
        messages[2],
        "The return value of \"str.upper\" must be used."
    );

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
fn s3699_ignores_nested_def_returns_when_classifying_void_functions() {
    // A nested inner def's `return`/`yield` must not classify the outer
    // function as non-void; consuming outer()'s output stays invalid.
    let nested_return = concat!(
        "def outer():\n",
        "    def inner():\n        return 1\n",
        "total = outer() + 1\n"
    );
    assert_eq!(findings_of(nested_return, "python:S3699").len(), 1);
    let nested_yield = concat!(
        "def outer():\n",
        "    def gen():\n        yield 1\n",
        "total = outer() + 1\n"
    );
    assert_eq!(findings_of(nested_yield, "python:S3699").len(), 1);
    let outer_returns = concat!(
        "def outer():\n",
        "    def inner():\n        return 1\n",
        "    return inner()\n",
        "total = outer() + 1\n"
    );
    assert!(findings_of(outer_returns, "python:S3699").is_empty());
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
    let report = scan("class C:\n    def BadName(self):\n        pass\n");
    let s100: Vec<_> = report
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:S100")
        .collect();
    assert_eq!(s100.len(), 1);
    assert_eq!(s100[0].range.start.line, 2);

    // A def nested inside a method is a nested function: python:S1542,
    // never python:S100. Compliant names stay silent.
    let nested = scan("class C:\n    def ok(self):\n        def Inner():\n            pass\n");
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
    let violating = scan("def Outer():\n    pass\n\n\ndef _ok_name():\n    pass\n");
    let s1542: Vec<_> = violating
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:S1542")
        .collect();
    assert_eq!(s1542.len(), 1);
    assert_eq!(s1542[0].range.start.line, 1);

    // Dunder-style names comply; digits and underscores follow the lead
    // character.
    let clean = scan("def __enter__():\n    pass\n\n\ndef x_1():\n    pass\n");
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
    let boundary = scan_with_options("a = 1\nb = 2\nc = 3\n", &options);
    assert!(
        boundary
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S104")
    );

    // One code line over the limit: flagged once, anchored at line 1.
    let over = scan_with_options("a = 1\nb = 2\nc = 3\n\n# comment only\nd = 4\n", &options);
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
    let boundary = scan_with_options("def f(a, b):\n    pass\n", &options);
    assert!(
        boundary
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S107")
    );

    // One parameter over: flagged on the function name.
    let over = scan_with_options("def f(a, b, c):\n    pass\n", &options);
    let s107: Vec<_> = over
        .issues
        .iter()
        .filter(|issue| issue.rule_key == "python:S107")
        .collect();
    assert_eq!(s107.len(), 1);
    assert_eq!(s107[0].range.start.line, 1);

    // Star args and kwargs each count toward the budget.
    let starred = scan_with_options("def f(a, b, *args, **kwargs):\n    pass\n", &options);
    assert_eq!(
        starred
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "python:S107")
            .count(),
        1
    );

    // The catalog default budget keeps ordinary signatures silent.
    let defaults = scan("def f(a, b, c):\n    pass\n");
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
    let nested = scan(
        "def outer():\n    def inner():\n        return 1\n        return 2\n        return 3\n        return 4\n    return 0\n",
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

    // Three body lines of code: silent.
    let boundary = scan_with_options("def f():\n    a = 1\n    b = 2\n    c = 3\n", &options);
    assert!(
        boundary
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S138")
    );

    // Five body lines of code: flagged once on the function name. Sonar does
    // not include the `def` line in this metric.
    let over = scan_with_options(
        "def f():\n    a = 1\n    b = 2\n    c = 3\n    d = 4\n    e = 5\n",
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
    let defaults = scan("def f():\n    a = 1\n    b = 2\n    c = 3\n    d = 4\n");
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
    let boundary = scan(
        "for a in []:\n    for b in []:\n        while b:\n            if a:\n                pass\n",
    );
    assert!(
        boundary
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S134")
    );

    // A fifth level is flagged once, on its own construct.
    let over = scan(
        "for a in []:\n    for b in []:\n        while b:\n            if a:\n                if a:\n                    pass\n",
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
    let chain = scan(
        "for a in []:\n    for b in []:\n        while b:\n            if a:\n                pass\n            elif a:\n                pass\n            elif a:\n                pass\n            else:\n                pass\n",
    );
    assert!(
        chain
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S134")
    );

    // Nested definitions are separate units and reset the counter.
    let units = scan(
        "def outer():\n    for a in []:\n        def inner():\n            for b in []:\n                pass\n",
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
    assert_eq!(findings(&flagged, "python:S1700").len(), 1);
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
fn tracked_python_oracle_gap_pairs_trigger_only_the_bad_control() {
    const CASES: &[(&str, &str, &str, usize)] = &[
        ("python:S4784", "s4784_bad.py", "s4784_good.py", 1),
        ("python:S5247", "s5247_bad.py", "s5247_good.py", 1),
        ("python:S5300", "s5300_bad.py", "s5300_good.py", 1),
        ("python:S5344", "s5344_bad.py", "s5344_good.py", 1),
        ("python:S5439", "s5439_bad.py", "s5439_good.py", 1),
        ("python:S5443", "s5443_bad.py", "s5443_good.py", 1),
        ("python:S5527", "s5527_bad.py", "s5527_good.py", 1),
        ("python:S5542", "s5542_bad.py", "s5542_good.py", 1),
        ("python:S5547", "s5547_bad.py", "s5547_good.py", 1),
        ("python:S5607", "s5607_bad.py", "s5607_good.py", 1),
        ("python:S5632", "s5632_bad.py", "s5632_good.py", 1),
        ("python:S5642", "s5642_bad.py", "s5642_good.py", 1),
        ("python:S5644", "s5644_bad.py", "s5644_good.py", 1),
        ("python:S5655", "s5655_bad.py", "s5655_good.py", 1),
        ("python:S5659", "s5659_bad.py", "s5659_good.py", 1),
        ("python:S5707", "s5707_bad.py", "s5707_good.py", 1),
        ("python:S5708", "s5708_bad.py", "s5708_good.py", 1),
        ("python:S5713", "s5713_bad.py", "s5713_good.py", 1),
        ("python:S5756", "s5756_bad.py", "s5756_good.py", 1),
        ("python:S5795", "s5795_bad.py", "s5795_good.py", 1),
        ("python:S5856", "s5856_bad.py", "s5856_good.py", 1),
        ("python:S5886", "s5886_bad.py", "s5886_good.py", 1),
        ("python:S5890", "s5890_bad.py", "s5890_good.py", 1),
        ("python:S6245", "s6245_bad.py", "s6245_good.py", 1),
        ("python:S6252", "s6252_bad.py", "s6252_good.py", 1),
        ("python:S6265", "s6265_bad.py", "s6265_good.py", 1),
        ("python:S6270", "s6270_bad.py", "s6270_good.py", 1),
        ("python:S6275", "s6275_bad.py", "s6275_good.py", 1),
        ("python:S6281", "s6281_bad.py", "s6281_good.py", 1),
        ("python:S6302", "s6302_bad.py", "s6302_good.py", 1),
        ("python:S6303", "s6303_bad.py", "s6303_good.py", 1),
        ("python:S6304", "s6304_bad.py", "s6304_good.py", 1),
        ("python:S6308", "s6308_bad.py", "s6308_good.py", 1),
        ("python:S6317", "s6317_bad.py", "s6317_good.py", 1),
        ("python:S6319", "s6319_bad.py", "s6319_good.py", 1),
        ("python:S6321", "s6321_bad.py", "s6321_good.py", 1),
        ("python:S6327", "s6327_bad.py", "s6327_good.py", 1),
        ("python:S6329", "s6329_bad.py", "s6329_good.py", 1),
        ("python:S6330", "s6330_bad.py", "s6330_good.py", 1),
        ("python:S6332", "s6332_bad.py", "s6332_good.py", 1),
        ("python:S6333", "s6333_bad.py", "s6333_good.py", 1),
        ("python:S6463", "s6463_bad.py", "s6463_good.py", 1),
    ];
    let project = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.oracle/sonar/projects/oracle-py/src");
    for &(key, bad_name, good_name, expected_bad_count) in CASES {
        let bad_path = project.join(bad_name);
        let bad_source = std::fs::read_to_string(&bad_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", bad_path.display()));
        assert_eq!(
            findings(&scan(&bad_source), key).len(),
            expected_bad_count,
            "bad oracle control for {key}",
        );

        let good_path = project.join(good_name);
        let good_source = std::fs::read_to_string(&good_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", good_path.display()));
        assert_eq!(
            findings(&scan(&good_source), key).len(),
            0,
            "good oracle control for {key}",
        );
    }
}
