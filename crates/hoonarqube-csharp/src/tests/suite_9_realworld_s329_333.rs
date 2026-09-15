//! Regression suite for the dapper false-positive package (#329-#333): S3973,
//! S109, S3059, S2333, and S2094 must mirror the reference platform's
//! documented semantics instead of over-reporting.

use super::{CsLanguage, PathBuf, analyze, analyze_default, analyze_options, with_key};
use crate::semantic::SourceSnapshot;
use crate::{AnalyzerOptions, ProjectTypeIndex};
use std::sync::Arc;

fn options_with_index(sources: &[(&str, &str)]) -> AnalyzerOptions {
    let snapshots: Vec<SourceSnapshot> = sources
        .iter()
        .map(|(path, source)| SourceSnapshot::new(PathBuf::from(path), *source))
        .collect();
    AnalyzerOptions {
        project_type_index: Some(Arc::new(ProjectTypeIndex::build(&snapshots))),
        ..AnalyzerOptions::default()
    }
}

fn analyze_at(path: &str, source: &str) -> hoonarqube_ir::FileReport {
    analyze(
        PathBuf::from(path),
        source,
        CsLanguage::CSharp,
        &AnalyzerOptions::default(),
    )
}

// --- csharpsquid:S3973 — braced bodies are always denoted by braces --------

#[test]
fn s3973_never_flags_braced_conditionally_executed_bodies() {
    let sources = [
        "class A\n{\n    int M(bool x)\n    {\n        if (x)\n        {\n            return 1;\n        }\n        return 2;\n    }\n}\n",
        "class A\n{\n    void M(bool x)\n    {\n        if (x)\n        {\n            Work();\n        }\n        else\n        {\n            Other();\n        }\n    }\n}\n",
        "class A\n{\n    void M(int n)\n    {\n        while (n > 0)\n        {\n            Step();\n        }\n        for (int i = 0; i < n; i++)\n        {\n            Step();\n        }\n        foreach (var item in new int[0])\n        {\n            Step();\n        }\n    }\n}\n",
        "class A\n{\n    void M(bool x)\n    {\n        if (x)\n        {\n        }\n        else if (!x)\n        {\n        }\n    }\n}\n",
    ];
    for source in sources {
        let report = analyze_default(source);
        assert!(
            with_key(&report, "csharpsquid:S3973").is_empty(),
            "braced bodies must never be flagged: {source}"
        );
    }
}

#[test]
fn s3973_still_flags_brace_less_bodies_at_or_before_the_header_column() {
    let report = analyze_default(
        "class A\n{\n    void M(bool x, int n)\n    {\n        if (x)\n        Apply();\n        while (n > 0)\n        Drain();\n        do\n        Retry();\n        while (n > 0);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3973");
    assert_eq!(flagged.len(), 3);
}

#[test]
fn s3973_keeps_indented_brace_less_bodies_clean() {
    let report = analyze_default(
        "class A\n{\n    void M(bool x)\n    {\n        if (x)\n            Apply();\n        while (x)\n            Drain();\n    }\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S3973").is_empty());
}

// --- csharpsquid:S109 — reference magic-number exceptions ------------------

#[test]
fn s109_spares_preprocessor_pragma_numbers() {
    let report = analyze_default(
        "class C\n{\n#pragma warning disable 0618\n    void M() { }\n#pragma warning restore 0618\n}\n",
    );
    assert!(
        with_key(&report, "csharpsquid:S109").is_empty(),
        "pragma warning numbers are directive text, not magic numbers"
    );
}

#[test]
fn s109_spares_test_scope_files_for_the_main_scoped_rule() {
    let report = analyze_at(
        "tests/Dapper.Tests/AsyncTests.cs",
        "class AsyncTests\n{\n    void Check()\n    {\n        Assert.Equal(42, Value());\n    }\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S109").is_empty());

    // Benchmark suites stay in the main scope (`IsTestProject=false` in the
    // reference project), so their unexplained numbers are still reported.
    let benchmark = analyze_at(
        "benchmarks/Dapper.Tests.Performance/PetaPoco.cs",
        "class PetaPoco\n{\n    int Iterations() => 5000;\n}\n",
    );
    assert_eq!(with_key(&benchmark, "csharpsquid:S109").len(), 1);
}

#[test]
fn s109_spares_variable_declarations_parameter_defaults_and_enum_members() {
    let report = analyze_default(
        "class C\n{\n    int field = 800;\n    const int Cap = 400;\n    void M(int retries = 7)\n    {\n        int plain = 11;\n        for (int i = 0; i < retries; i++)\n            Step(i);\n    }\n    enum E\n    {\n        Max = 600,\n    }\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S109").is_empty());
}

#[test]
fn s109_spares_get_hash_code_bodies_property_returns_and_initializers() {
    let report = analyze_default(
        "class C\n{\n    public override int GetHashCode()\n    {\n        return 31 * seed;\n    }\n\n    int Limited { get; set; } = 250;\n\n    string Label\n    {\n        get { return 3; }\n    }\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S109").is_empty());
}

#[test]
fn s109_spares_single_digit_collection_size_comparisons() {
    let report = analyze_default(
        "class C\n{\n    bool Split(string name)\n    {\n        var parts = Parts(name);\n        return parts.Length == 2 && parts.Count() > 1 && parts.Size != 3;\n    }\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S109").is_empty());
}

#[test]
fn s109_spares_constructor_named_and_time_style_arguments() {
    let report = analyze_default(
        "class C\n{\n    void M()\n    {\n        var map = new Dictionary<int, int>(41);\n        Step(amount: 42);\n        var wait = TimeSpan.FromMinutes(5);\n    }\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S109").is_empty());
}

#[test]
fn s109_keeps_flagging_non_declaration_contexts() {
    let report = analyze_default(
        "class C\n{\n    int total;\n    int Sum()\n    {\n        total = 42;\n        return 41 + total;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S109");
    assert_eq!(flagged.len(), 2);
}

// --- csharpsquid:S3059 — reference visibility semantics ---------------------

#[test]
fn s3059_reports_only_explicit_internal_top_level_types() {
    let report = analyze_default(
        "internal class Vault\n{\n    public int Count;\n\n    public void Render() { }\n}\n\nclass ImplicitInternal\n{\n    public int Count;\n}\n\npublic class Public\n{\n    public int Count;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3059");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);
}

#[test]
fn s3059_spares_nested_types_and_their_members() {
    let report = analyze_default(
        "public class Registry\n{\n    internal class Cache\n    {\n        public void Reset() { }\n    }\n\n    private sealed class Store\n    {\n        public int Total;\n    }\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S3059").is_empty());
}

#[test]
fn s3059_spares_overrides_operators_and_local_interface_implementations() {
    let report = analyze_default(
        "interface IThing\n{\n    object Parse(Type destination, object value);\n}\n\ninternal sealed class Impl : IThing\n{\n    public object Parse(Type destination, object value) => value;\n\n    public override string ToString() => \"Impl\";\n\n    public static Impl operator +(Impl left, Impl right) => left;\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S3059").is_empty());
}

#[test]
fn s3059_resolves_cross_file_interfaces_through_the_project_index() {
    let interface = "namespace Dapper\n{\n    public interface ITypeHandler\n    {\n        object Parse(Type destinationType, object value);\n\n        void SetValue(IDbDataParameter parameter, object value);\n    }\n}\n";
    let handler = "namespace Dapper\n{\n    internal sealed class DataTableHandler : ITypeHandler\n    {\n        public object Parse(Type destinationType, object value) => value;\n\n        public void SetValue(IDbDataParameter parameter, object value) { }\n    }\n}\n";
    let options = options_with_index(&[
        ("ITypeHandler.cs", interface),
        ("DataTableHandler.cs", handler),
    ]);
    let report = analyze_options(handler, &options);
    assert!(with_key(&report, "csharpsquid:S3059").is_empty());
}

#[test]
fn s3059_spares_test_scope_files_for_the_main_scoped_rule() {
    let report = analyze_at(
        "tests/Dapper.Tests/DataReaderTests.cs",
        "internal sealed class TestReader : DbDataReader\n{\n    public int Total;\n\n    public void Render() { }\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S3059").is_empty());
}

#[test]
fn s3059_keeps_flagging_public_plain_members_of_internal_types() {
    let report = analyze_default(
        "internal sealed class SimpleMemberMap\n{\n    public SimpleMemberMap(string name) { }\n\n    public string Name { get; }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3059");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);
}

// --- csharpsquid:S2333 — project-wide partial declarations ------------------

#[test]
fn s2333_counts_partial_declarations_across_the_project_index() {
    let mapper = "namespace Dapper\n{\n    public static partial class SqlMapper\n    {\n        public static int Foo() => 1;\n    }\n}\n";
    let extensions = "namespace Dapper\n{\n    public static partial class SqlMapper\n    {\n        public static int Bar() => 2;\n    }\n}\n";
    let options = options_with_index(&[
        ("SqlMapper.cs", mapper),
        ("SqlMapper.Extensions.cs", extensions),
    ]);
    let report = analyze_options(mapper, &options);
    assert!(
        with_key(&report, "csharpsquid:S2333").is_empty(),
        "a partial type declared in several files needs its modifier"
    );
}

#[test]
fn s2333_still_flags_single_declaration_partials() {
    let source = "namespace Dapper\n{\n    public static partial class CompiledRegex\n    {\n        public static int Foo() => 1;\n    }\n}\n";
    let options = options_with_index(&[("CompiledRegex.cs", source)]);
    let report = analyze_options(source, &options);
    let flagged = with_key(&report, "csharpsquid:S2333");
    assert_eq!(flagged.len(), 1);
}

#[test]
fn s2333_without_index_keeps_the_file_local_contract() {
    let single = analyze_default("public partial class Alone\n{\n}\n");
    assert_eq!(with_key(&single, "csharpsquid:S2333").len(), 1);

    let pair =
        analyze_default("public partial class Pair\n{\n}\n\npublic partial class Pair\n{\n}\n");
    assert!(with_key(&pair, "csharpsquid:S2333").is_empty());
}

// --- csharpsquid:S2094 — reference empty-type exemptions --------------------

#[test]
fn s2094_spares_attributed_types_and_known_marker_base_classes() {
    let report = analyze_default(
        "[AttributeUsage(AttributeTargets.Method)]\npublic sealed class MyMarkerAttribute : Attribute\n{\n}\n\ninternal sealed class PlainError : Exception\n{\n}\n\npublic sealed class UnattributedMarker : Attribute\n{\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S2094").is_empty());
}

#[test]
fn s2094_spares_types_with_attributes_generic_bases_and_primary_constructors() {
    let report = analyze_default(
        "class Holder\n{\n    [Collection(\"Misc\")]\n    public sealed class MiscTests : BaseTests<SqlProvider>\n    {\n    }\n\n    public sealed class PlainGenericBase : BaseTests<SqlProvider>\n    {\n    }\n\n    public class MultiBase : Base, System.IDisposable\n    {\n    }\n\n    public class PrimaryCtor(string message)\n    {\n    }\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S2094").is_empty());
}

#[test]
fn s2094_spares_conditionally_compiled_and_documented_names() {
    let report = analyze_default(
        "#if !NET5_0_OR_GREATER\ninternal static class IsExternalInit\n{\n}\n#endif\n\npublic class IgnoreCommand\n{\n}\n\npublic class AssemblyDoc\n{\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S2094").is_empty());
}

#[test]
fn s2094_still_flags_plain_empty_types_including_comment_only_bodies() {
    let report = analyze_default(
        "namespace Dapper\n{\n    public static partial class SqlMapper\n    {\n        private sealed class DontMap { /* hiding constructor */ }\n    }\n}\n\nclass Bare\n{\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2094");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 9);
}
