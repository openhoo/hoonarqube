//! Regression suite for the dapper parity package (#341, #342, #350): the
//! S2479 verbatim line-break exemption, the S4581 bare-default target
//! resolution, and the frozen catalog's MAIN rule scope enforced centrally on
//! the Sonar surface.

use super::{AnalyzerOptions, CsLanguage, PathBuf, analyze, analyze_default, with_key};

fn analyze_at(path: &str, source: &str) -> hoonarqube_ir::FileReport {
    analyze(
        PathBuf::from(path),
        source,
        CsLanguage::CSharp,
        &AnalyzerOptions::default(),
    )
}

// --- csharpsquid:S2479 — inescapable literals and the reference table ------

/// dapper tests/Dapper.Tests/DataReaderTests.cs:180 and
/// benchmarks/Dapper.Tests.Performance/LegacyTests.cs:262: multi-line
/// verbatim strings produced 77 `csharpsquid:S2479` findings against the
/// `SonarQube` 26.8 oracle's zero. Verbatim and raw strings are inescapable
/// by design: their physical line breaks are the literal's spelling, not
/// hidden control characters.
#[test]
fn s2479_spares_physical_line_breaks_inside_verbatim_strings() {
    let report = analyze_default(
        "class C\n{\n    string Sql => @\"select Id\nfrom Posts\nwhere Id = @id\";\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S2479").is_empty());
}

/// Raw strings (C# 11) are inescapable for the same reason.
#[test]
fn s2479_spares_physical_line_breaks_inside_raw_strings() {
    let report = analyze_default(
        "class C\n{\n    string Sql => \"\"\"\nselect Id\nfrom Posts\n\"\"\";\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S2479").is_empty());
}

/// dapper benchmarks/Dapper.Tests.Performance/Program.cs:58: the oracle
/// keeps a raw tab inside a verbatim SQL string unreported — the whole
/// inescapable literal is exempt, not only its line breaks.
#[test]
fn s2479_spares_raw_tab_inside_verbatim_strings() {
    let report =
        analyze_default("class C\n{\n    string Sql => @\"Begin\n\tCreate Table Posts\";\n}\n");
    assert!(with_key(&report, "csharpsquid:S2479").is_empty());
}

/// Clean control: a raw tab in a plain (escapable) string stays reported
/// with the reference's short escape spelling.
#[test]
fn s2479_still_flags_real_control_characters() {
    let plain_tab = analyze_default("class C\n{\n    string text = \"a\tb\";\n}\n");
    let flagged = with_key(&plain_tab, "csharpsquid:S2479");
    assert_eq!(flagged.len(), 1);
    assert!(
        flagged[0].message.contains("'\\t'"),
        "tab should use the reference's short escape: {}",
        flagged[0].message
    );
}

// --- csharpsquid:S4581 — bare default resolved through Guid targets ---------

/// dapper Dapper.ProviderTools/DbConnectionExtensions.cs:19 and :49: the
/// `SonarQube` 26.8 oracle reports `clientConnectionId = default;` twice where
/// hq 0.8.2 reported nothing. A bare `default` must resolve its target type
/// through the in-file assignment flow, exactly like `default(Guid)`.
#[test]
fn s4581_flags_bare_default_assigned_to_guid_targets() {
    // The exact dapper shape: assignment to an `out Guid` parameter.
    let out_param = analyze_default(
        "class C\n{\n    bool TryGet(out Guid clientConnectionId)\n    {\n        clientConnectionId = default;\n        return false;\n    }\n}\n",
    );
    assert_eq!(with_key(&out_param, "csharpsquid:S4581").len(), 1);

    // Declarator initializers and the explicit `default(Guid)` spelling.
    let initializers = analyze_default(
        "class C\n{\n    Guid g = default;\n    Guid Other() { Guid h = default(Guid); return h; }\n}\n",
    );
    assert_eq!(with_key(&initializers, "csharpsquid:S4581").len(), 2);

    // Field and property targets of a plain assignment.
    let members = analyze_default(
        "class C\n{\n    private Guid field;\n    Guid Property { get; set; }\n    void M() { field = default; Property = default; }\n}\n",
    );
    assert_eq!(with_key(&members, "csharpsquid:S4581").len(), 2);
}

/// Clean controls: the reference exempts parameter defaults (`Guid.Empty`
/// is not a compile-time constant) and every target whose converted type is
/// not exactly `Guid` — nullable and non-Guid declarations stay clean.
#[test]
fn s4581_spares_non_guid_defaults_and_parameter_defaults() {
    let report = analyze_default(
        "class C\n{\n    void WithDefault(Guid g = default, Guid h = default(Guid)) { }\n    int Count()\n    {\n        int i = default;\n        Guid? maybe = default;\n        string text = default;\n        return i;\n    }\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S4581").is_empty());
}

// --- #350 — catalog MAIN rule scope on the Sonar surface --------------------

/// Issue #350: MAIN-scope rules must not report on test-scoped sources. The
/// `SonarQube` 26.8 oracle emits only TEST-scope findings on dapper's tests/
/// (S2699, S3415), so every catalog-MAIN emission there was a false positive.
/// Scope-ALL rules keep firing on tests.
#[test]
fn main_scope_rules_stay_silent_on_test_scope_sources() {
    let source = "class C\n{\n    int Add(int value)\n    {\n        System.Console.WriteLine(\"run\");\n        if (value > 100) { return value; }\n        return value;\n    }\n}\n";
    let main = analyze_at("src/Service.cs", source);
    assert_eq!(with_key(&main, "csharpsquid:S106").len(), 1);
    assert_eq!(with_key(&main, "csharpsquid:S109").len(), 1);
    let tests = analyze_at("tests/Dapper.Tests/ServiceTests.cs", source);
    assert!(with_key(&tests, "csharpsquid:S106").is_empty());
    assert!(with_key(&tests, "csharpsquid:S109").is_empty());

    // S4581 declares scope ALL in the frozen catalog: still reported.
    let all_scope = analyze_at(
        "tests/Dapper.Tests/GuidTests.cs",
        "class C\n{\n    Guid g = new Guid();\n}\n",
    );
    assert_eq!(with_key(&all_scope, "csharpsquid:S4581").len(), 1);
}

/// Benchmark classification follows the oracle's observed treatment: the
/// reference scanner classifies the benchmark project as a non-test project
/// (`IsTestProject=false`) and keeps reporting MAIN rules under
/// `benchmarks/` (dapper oracle: S109 78, S2221 1), so only conventional
/// test directories are test-scoped.
#[test]
fn benchmark_sources_stay_in_the_main_scope() {
    let source = "class C\n{\n    int Add(int value)\n    {\n        System.Console.WriteLine(\"run\");\n        if (value > 100) { return value; }\n        return value;\n    }\n}\n";
    let report = analyze_at("benchmarks/Dapper.Tests.Performance/Legacy.cs", source);
    assert_eq!(with_key(&report, "csharpsquid:S106").len(), 1);
    assert_eq!(with_key(&report, "csharpsquid:S109").len(), 1);
}
