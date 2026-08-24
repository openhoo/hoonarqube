//! Test suite part; the full suite spans `tests/*.rs`.

use super::*;

#[test]
fn extensions_map_to_csharp() {
    assert_eq!(language_for_extension("cs"), Some(CsLanguage::CSharp));
    assert_eq!(language_for_extension("py"), None);
}

#[test]
fn clean_csharp_parses_with_metrics() {
    let report = analyze(
        PathBuf::from("test.cs"),
        "int total = 1;\ntotal = total + total;\n",
        CsLanguage::CSharp,
        &AnalyzerOptions::default(),
    );
    assert_eq!(report.language, "csharpsquid");
    assert!(report.issues.is_empty());
    assert_eq!(report.metrics.lines, 2);
    assert!(report.metrics.code_lines > 0);
    assert_eq!(report.metrics.comment_lines, 0);
}

#[test]
fn comment_lines_are_counted_separately() {
    let report = analyze(
        PathBuf::from("test.cs"),
        "// leading note\nclass A { }\n/* block\ncomment */\n",
        CsLanguage::CSharp,
        &AnalyzerOptions::default(),
    );
    assert_eq!(report.metrics.comment_lines, 3);
    assert_eq!(report.metrics.code_lines, 1);
}

#[test]
fn line_length_honors_option_with_exact_boundary_clean() {
    let options = AnalyzerOptions {
        maximum_line_length: 13,
        ..Default::default()
    };
    let at_limit = analyze(
        PathBuf::from("t.cs"),
        "const int ab;\n",
        CsLanguage::CSharp,
        &options,
    );
    assert!(at_limit.issues.is_empty());

    let over_limit = analyze(
        PathBuf::from("t.cs"),
        "const int abc;\n",
        CsLanguage::CSharp,
        &options,
    );
    assert_eq!(over_limit.issues.len(), 1);
    assert_eq!(over_limit.issues[0].rule_key, "csharpsquid:S103");
    assert_eq!(over_limit.issues[0].range.start.line, 1);
    assert_eq!(
        over_limit.issues[0].message,
        "This line exceeds the maximum allowed length of 13 characters."
    );
}

#[test]
fn broken_source_neither_panics_nor_emits_issues() {
    let report = analyze(
        PathBuf::from("t.cs"),
        "class {{{ ;;; ???\n",
        CsLanguage::CSharp,
        &AnalyzerOptions::default(),
    );
    assert!(report.issues.is_empty());
}

#[test]
fn s104_flags_files_over_the_loc_threshold() {
    let options = AnalyzerOptions {
        maximum_file_loc_threshold: 3,
        ..Default::default()
    };
    let over = analyze_options("class A\n{\n}\nint b;\n", &options);
    let flagged = with_key(&over, "csharpsquid:S104");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);

    let at_limit = analyze_options("class A\n{\n}\nint b;\n", &AnalyzerOptions::default());
    assert!(with_key(&at_limit, "csharpsquid:S104").is_empty());
}

#[test]
fn s105_reports_leading_tab_characters() {
    let report = analyze_default("\tint x;\nclass A\n{\n}\n");
    let flagged = with_key(&report, "csharpsquid:S105");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);
    assert_eq!(flagged[0].range.start.column, 0);
    assert_eq!(
        flagged[0].message,
        "Replace all tab characters in this file by spaces."
    );

    let clean = analyze_default("    int x;\nclass A\n{\n}\n");
    assert!(with_key(&clean, "csharpsquid:S105").is_empty());
}

#[test]
fn s113_requires_trailing_newline() {
    let report = analyze_default("class A {}");
    let flagged = with_key(&report, "csharpsquid:S113");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);
    assert_eq!(flagged[0].range.start.column, 10);
    assert_eq!(
        flagged[0].message,
        "Add a new line at the end of this file."
    );

    assert!(with_key(&analyze_default(""), "csharpsquid:S113").is_empty());
    assert!(with_key(&analyze_default("class A {}\n"), "csharpsquid:S113").is_empty());
}

#[test]
fn s1109_flags_indented_closing_braces() {
    let report = analyze_default("class A\n{\n    }\n");
    let flagged = with_key(&report, "csharpsquid:S1109");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[0].range.start.column, 4);

    let clean = analyze_default("class A\n{\n}\n");
    assert!(with_key(&clean, "csharpsquid:S1109").is_empty());
}

#[test]
fn s122_flags_second_statement_on_a_line() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        int a = 1; int b = 2;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S122");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[0].range.start.column, 19);

    let clean = analyze_default(
        "class A\n{\n    void M()\n    {\n        int a = 1;\n        int b = 2;\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S122").is_empty());
}

#[test]
fn s3972_flags_inline_else_catch_and_finally() {
    let report = analyze_default(
        "class A\n{\n    void M(int x)\n    {\n        if (x > 0) { } else { }\n        try { } catch (System.Exception) { } finally { }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3972");
    assert_eq!(flagged.len(), 3);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 6);
    assert_eq!(flagged[2].range.start.line, 6);

    let clean = analyze_default(
        "class A\n{\n    void M(int x)\n    {\n        if (x > 0)\n        {\n        }\n        else\n        {\n        }\n        try\n        {\n        }\n        catch (System.Exception)\n        {\n        }\n        finally\n        {\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3972").is_empty());
}

#[test]
fn s3973_flags_unindented_conditional_bodies() {
    let report = analyze_default(
        "class A\n{\n    void M(int x)\n    {\n        if (x > 0)\n        x++;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3973");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 6);
    assert_eq!(
        flagged[0].message,
        "Indent this statement to make its scope obvious."
    );

    let indented = analyze_default(
        "class A\n{\n    void M(int x)\n    {\n        if (x > 0)\n            x++;\n    }\n}\n",
    );
    assert!(with_key(&indented, "csharpsquid:S3973").is_empty());

    let same_line = analyze_default(
        "class A\n{\n    void M(int x)\n    {\n        if (x > 0) x++;\n    }\n}\n",
    );
    assert!(with_key(&same_line, "csharpsquid:S3973").is_empty());
}

#[test]
fn s1659_flags_multiple_declarators_on_one_line() {
    let report = analyze_default("class A\n{\n    int a = 1, b = 2;\n}\n");
    let flagged = with_key(&report, "csharpsquid:S1659");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[0].range.start.column, 15);

    let split_lines = analyze_default("class A\n{\n    int a = 1,\n        b = 2;\n}\n");
    assert!(with_key(&split_lines, "csharpsquid:S1659").is_empty());
}

#[test]
fn s4663_flags_only_empty_comments() {
    let report = analyze_default("//\nclass A {}\n/* */\n");
    let flagged = with_key(&report, "csharpsquid:S4663");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 1);
    assert_eq!(flagged[1].range.start.line, 3);

    let clean = analyze_default("///\n// note\nclass A {}\n/* filled */\n");
    assert!(with_key(&clean, "csharpsquid:S4663").is_empty());
}

#[test]
fn s125_flags_commented_out_code_runs() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        // if (ready)\n        // {\n        //     Launch();\n        // }\n        int x = 1;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S125");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let prose = analyze_default(
        "class A\n{\n    // This method computes the total.\n    // See the design notes.\n    void M() { }\n}\n",
    );
    assert!(with_key(&prose, "csharpsquid:S125").is_empty());
}

#[test]
fn s2148_boundary_separators_and_radixes() {
    let report = analyze_default(
        "class A\n{\n    int[] sizes = { 9999, 10000, 10_000, 0xABCD, 123456789012 };\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2148");
    assert_eq!(flagged.len(), 2);

    let reals = analyze_default(
        "class A\n{\n    double a = 10000.5;\n    double b = 9999.5;\n    var c = 2e5;\n    var d = 2e3;\n}\n",
    );
    let flagged_reals = with_key(&reals, "csharpsquid:S2148");
    assert_eq!(flagged_reals.len(), 2);
    assert_eq!(flagged_reals[0].range.start.line, 3);
    assert_eq!(flagged_reals[1].range.start.line, 5);
}

#[test]
fn s1451_header_modes() {
    let options = AnalyzerOptions {
        header_format: "/// MIT Licensed".to_string(),
        ..Default::default()
    };
    let compliant = analyze_options("/// MIT Licensed\nclass A {}\n", &options);
    assert!(with_key(&compliant, "csharpsquid:S1451").is_empty());

    let missing = analyze_options("class A {}\n", &options);
    let flagged = with_key(&missing, "csharpsquid:S1451");
    assert_eq!(flagged.len(), 1);
    assert_eq!(
        flagged[0].range.start,
        hoonarqube_ir::Pos { line: 1, column: 0 }
    );

    let regex_mode = AnalyzerOptions {
        header_format: "/// MIT Licensed".to_string(),
        header_is_regular_expression: true,
        ..Default::default()
    };
    let skipped = analyze_options("class A {}\n", &regex_mode);
    assert!(with_key(&skipped, "csharpsquid:S1451").is_empty());

    let disabled = analyze_options("class A {}\n", &AnalyzerOptions::default());
    assert!(with_key(&disabled, "csharpsquid:S1451").is_empty());
}

#[test]
fn s100_method_and_property_names() {
    let report = analyze_default(
        "class A\n{\n    void bad_name() { }\n    void GoodName() { }\n    int bad_prop { get; set; }\n    int GoodProp { get; set; }\n    void IFoo.lower_case() { }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S100");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 5);
    assert!(flagged[0].message.contains("this method"));
    assert!(flagged[1].message.contains("this property"));
}

#[test]
fn s101_type_names_by_kind() {
    let report = analyze_default(
        "class lower_class { }\ninterface iface { }\nstruct point { }\nenum kind { A }\nrecord Point(int X, int Y);\n",
    );
    let flagged = with_key(&report, "csharpsquid:S101");
    assert_eq!(flagged.len(), 4);
    assert!(flagged[0].message.contains("this class"));
    assert!(flagged[1].message.contains("this interface"));
    assert!(flagged[2].message.contains("this struct"));
    assert!(flagged[3].message.contains("this enum"));
}

#[test]
fn s2342_enum_formats_split_on_flags_attribute() {
    let report = analyze_default(
        "[Flags]\nenum HttpMethod { A }\nenum httpCode { A }\n[Flags]\nenum HttpMethods { A }\nenum HttpCodes { A }\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2342");
    assert_eq!(flagged.len(), 2);
    assert!(
        flagged[0]
            .message
            .contains("^([A-Z]{1,3}[a-z0-9]+)*([A-Z]{2})?s$")
    );
    assert!(
        flagged[1]
            .message
            .contains("^([A-Z]{1,3}[a-z0-9]+)*([A-Z]{2})?$")
    );
}

#[test]
fn s2344_enum_suffixes() {
    let report =
        analyze_default("enum ColorsEnum { A }\nenum AccessFlags { A }\nenum Colors { A }\n");
    let flagged = with_key(&report, "csharpsquid:S2344");
    assert_eq!(flagged.len(), 2);
    assert!(flagged[0].message.contains("Enum"));
    assert!(flagged[1].message.contains("Flags"));
}

#[test]
fn s3376_extended_type_suffixes_required() {
    let report = analyze_default(
        "class Foo : Exception { }\nclass BarException : Exception { }\nclass Args : EventArgs { }\nclass PayloadArgs : EventArgs { }\nclass Plain { }\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3376");
    assert_eq!(flagged.len(), 3);
    assert!(flagged[0].message.contains("Exception"));
    assert!(flagged[1].message.contains("EventArgs"));
    assert!(flagged[2].message.contains("EventArgs"));
}

#[test]
fn s3872_parameter_duplicating_method_name() {
    let report = analyze_default("class A\n{\n    void M(int m, int other) { }\n}\n");
    let flagged = with_key(&report, "csharpsquid:S3872");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[0].range.start.column, 15);
}

#[test]
fn s4041_type_names_matching_namespaces() {
    let report = analyze_default("namespace Data\n{\n    class Loader { }\n}\nclass data { }\n");
    let flagged = with_key(&report, "csharpsquid:S4041");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
    assert!(flagged[0].message.contains("Data"));
}

#[test]
fn s4059_getter_methods_duplicating_properties() {
    let report = analyze_default(
        "class A\n{\n    int Foo => 1;\n    int GetFoo() => 2;\n    int GetBar() => 3;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4059");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 4);
    assert!(flagged[0].message.contains("\"Foo\""));
}

#[test]
fn s4136_overloads_must_be_grouped() {
    let separated = analyze_default(
        "class A\n{\n    void Alpha() { }\n    void Beta() { }\n    void Alpha(int a) { }\n}\n",
    );
    let flagged = with_key(&separated, "csharpsquid:S4136");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let grouped = analyze_default(
        "class A\n{\n    void Alpha() { }\n    void Alpha(int a) { }\n    void Beta() { }\n    void Beta(int b) { }\n}\n",
    );
    assert!(with_key(&grouped, "csharpsquid:S4136").is_empty());
}

#[test]
fn s4261_async_suffix_directions_and_skips() {
    let report = analyze_default(
        "class A\n{\n    async Task Go() { await Task.Yield(); }\n    Task DoneAsync() => Task.CompletedTask;\n    async Task RunAsync() { await Task.Yield(); }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4261");
    assert_eq!(flagged.len(), 2);
    assert!(flagged[0].message.starts_with("Add the \"Async\" suffix"));
    assert!(
        flagged[1]
            .message
            .starts_with("Remove the \"Async\" suffix")
    );

    let overrides = analyze_default(
        "class Base { public virtual async Task XAsync() => Task.CompletedTask; }\nclass Derived : Base\n{\n    public override Task XAsync() => Task.CompletedTask;\n}\n",
    );
    assert!(with_key(&overrides, "csharpsquid:S4261").is_empty());

    let interfaces = analyze_default("interface I\n{\n    Task DoAsync();\n}\n");
    assert!(with_key(&interfaces, "csharpsquid:S4261").is_empty());
}

#[test]
fn s6669_logger_member_names() {
    let report = analyze_default(
        "class A\n{\n    ILogger log;\n    ILogger _logger;\n    ILogger Logger;\n    ILogger factory;\n    IFormatter bogus;\n}\nclass B\n{\n    ILogger Log { get; } = null!;\n    ILogger writer { get; } = null!;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S6669");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 6);
    assert_eq!(flagged[1].range.start.line, 12);
    assert!(flagged[0].message.contains("^_?[Ll]og(ger)?$"));
}

#[test]
fn issues_are_sorted_by_position() {
    let report = analyze_default("\tint x;\nclass A {}\n");
    let positions: Vec<(u32, u32)> = report
        .issues
        .iter()
        .map(|issue| (issue.range.start.line, issue.range.start.column))
        .collect();
    let mut sorted = positions.clone();
    sorted.sort_unstable();
    assert_eq!(positions, sorted);
}

#[test]
fn s1104_flags_public_instance_fields_only() {
    let report = analyze_default(
        "class Widget\n{\n    public int Count;\n}\nclass Hidden\n{\n    private int count;\n}\nclass Shared\n{\n    public static int total;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1104");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let clean = analyze_default("class Widget\n{\n    private int count;\n}\n");
    assert!(with_key(&clean, "csharpsquid:S1104").is_empty());
}

#[test]
fn s2357_flags_non_private_fields_but_not_constants() {
    let report = analyze_default(
        "class Widget\n{\n    internal int cached;\n}\nclass Quiet\n{\n    private int cached;\n}\nclass Limits\n{\n    public const int Max = 3;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2357");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s2223_flags_visible_static_fields_even_readonly() {
    let report = analyze_default(
        "class Cache\n{\n    internal static int counter;\n}\nclass Scale\n{\n    public static readonly int Factor = 1;\n}\nclass Locked\n{\n    private const int Cap = 9;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2223");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 7);
}

#[test]
fn s2339_flags_public_constants_only() {
    let report = analyze_default(
        "class Limits\n{\n    public const int Max = 3;\n}\nclass PrivateLimits\n{\n    private const int Cap = 2;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2339");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s2386_flags_mutable_public_static_fields() {
    let report = analyze_default(
        "class Counter\n{\n    public static int hits;\n}\nclass Frozen\n{\n    public static readonly int start = 1;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2386");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s2156_flags_protected_members_in_sealed_types() {
    let report = analyze_default(
        "sealed class Fixed\n{\n    public void Grow()\n    {\n    }\n\n    protected void Shrink()\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2156");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);
}

#[test]
fn s2290_flags_virtual_field_like_events() {
    let report = analyze_default(
        "class Broadcaster\n{\n    public virtual event System.EventHandler Changed;\n\n    public event System.EventHandler Stopped;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2290");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s3442_flags_public_constructors_in_abstract_classes() {
    let report = analyze_default(
        "abstract class Plant\n{\n    public Plant()\n    {\n    }\n}\nabstract class Seed\n{\n    protected Seed()\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3442");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s3453_flags_uninstantiable_private_constructor_classes() {
    let source = "class Secret\n{\n    private Secret()\n    {\n    }\n}\nclass Gateway\n{\n    private Gateway()\n    {\n    }\n\n    public static Gateway Create()\n    {\n        return new Gateway();\n    }\n}\npartial class Split\n{\n    private Split()\n    {\n    }\n}\n";
    let report = analyze_default(source);
    let flagged = with_key(&report, "csharpsquid:S3453");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);
}

#[test]
fn s3871_flags_non_public_exception_types() {
    let report = analyze_default(
        "class FaultError : Exception\n{\n}\npublic class AppFailure : Exception\n{\n}\nclass Container\n{\n    private class InnerError : Exception\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3871");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 1);
    assert_eq!(flagged[1].range.start.line, 9);
}

#[test]
fn s4060_flags_unsealed_attribute_classes() {
    let report = analyze_default(
        "class HintAttribute : Attribute\n{\n}\nsealed class TagAttribute : Attribute\n{\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4060");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);
}

#[test]
fn s4035_flags_unsealed_iequatable_implementations() {
    let report = analyze_default(
        "class Amount : IEquatable<Amount>\n{\n    public bool Equals(Amount other)\n    {\n        return true;\n    }\n}\nsealed class Ratio : IEquatable<Ratio>\n{\n    public bool Equals(Ratio other)\n    {\n        return true;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4035");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);
}

#[test]
fn s3260_flags_undecided_private_types() {
    let report = analyze_default(
        "class Outer\n{\n    class Inner\n    {\n    }\n}\nclass Zoo\n{\n    class Beast\n    {\n    }\n\n    sealed class Tamed : Beast\n    {\n    }\n\n    record Token(int id);\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3260");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 17);
}

#[test]
fn s3059_flags_members_more_visible_than_their_container() {
    let report = analyze_default(
        "public class Registry\n{\n    internal class Cache\n    {\n        public void Reset()\n        {\n        }\n\n        private void Prime()\n        {\n        }\n    }\n}\ninternal class Vault\n{\n    public class Door\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3059");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 16);
}

#[test]
fn s2360_flags_optional_parameters_except_overrides() {
    let report = analyze_default(
        "class Base\n{\n    public virtual void Configure(int retries = 3)\n    {\n    }\n}\nclass Child : Base\n{\n    public override void Configure(int retries = 3)\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2360");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s3874_flags_out_and_ref_parameters_except_overrides() {
    let report = analyze_default(
        "class Parser\n{\n    public bool TryRead(out int value)\n    {\n        value = 0;\n        return true;\n    }\n\n    public void Swap(ref int left)\n    {\n    }\n\n    public void Plain(int value)\n    {\n    }\n}\nclass DerivedParser : Parser\n{\n    public override bool TryRead(out int value)\n    {\n        value = 1;\n        return true;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3874");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 9);
}

#[test]
fn s3447_flags_optional_attribute_on_ref_parameters() {
    let report = analyze_default(
        "class Binder\n{\n    public void Store([Optional] ref int target)\n    {\n    }\n\n    public void Keep(ref int target)\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3447");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s3450_requires_optional_next_to_default_parameter_value() {
    let report = analyze_default(
        "class Loader\n{\n    public void Load([DefaultParameterValue(5)] int count)\n    {\n    }\n\n    public void Ready([DefaultParameterValue(5)] [Optional] int count)\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3450");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s3451_flags_default_value_on_parameters() {
    let report = analyze_default(
        "class Saver\n{\n    public void Save([DefaultValue(3)] int retries)\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3451");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s3343_requires_caller_information_parameters_last() {
    let bad = analyze_default(
        "class Tracer\n{\n    public void Track([CallerMemberName] string member = \"\", int depth = 0)\n    {\n    }\n}\n",
    );
    let flagged = with_key(&bad, "csharpsquid:S3343");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let last = analyze_default(
        "class Tracer\n{\n    public void Track(int depth, [CallerMemberName] string member = \"\")\n    {\n    }\n}\n",
    );
    assert!(with_key(&last, "csharpsquid:S3343").is_empty());

    let before_params = analyze_default(
        "class Tracer\n{\n    public void Track(int depth, [CallerMemberName] string member = \"\", params object[] rest)\n    {\n    }\n}\n",
    );
    assert!(with_key(&before_params, "csharpsquid:S3343").is_empty());
}

#[test]
fn s4214_and_s4200_flag_pinvoke_declarations_by_visibility() {
    let report = analyze_default(
        "class Audio\n{\n    [DllImport(\"user32.dll\")]\n    public static extern bool Beep(uint frequency, uint duration);\n\n    [DllImport(\"user32.dll\")]\n    internal static extern bool Chime(uint frequency);\n}\n",
    );
    let visible = with_key(&report, "csharpsquid:S4214");
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].range.start.line, 4);
    let wrapped = with_key(&report, "csharpsquid:S4200");
    assert_eq!(wrapped.len(), 2);
}

#[test]
fn s4000_flags_pointer_types_in_public_signatures() {
    let report = analyze_default(
        "class Memory\n{\n    public void Copy(int* source, int count)\n    {\n    }\n\n    internal int* Head()\n    {\n        return null;\n    }\n\n    public int* Tail()\n    {\n        return null;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4000");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 12);
}

#[test]
fn s3967_flags_multidimensional_arrays_not_jagged() {
    let report = analyze_default(
        "class Board\n{\n    private int[,] grid;\n\n    private int[][] rows;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3967");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s2368_flags_public_methods_with_multidimensional_array_parameters() {
    let report = analyze_default(
        "class Painter\n{\n    public void Draw(int[,] pixels)\n    {\n    }\n\n    internal void Blend(int[,] pixels)\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2368");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s4022_flags_non_int_enum_storage() {
    let report = analyze_default(
        "enum Tiny : byte\n{\n    One\n}\nenum Plain\n{\n    Two\n}\nenum Wide : int\n{\n    Three\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4022");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);
}

#[test]
fn s4017_flags_nested_generics_in_signatures() {
    let report = analyze_default(
        "class Graph\n{\n    public void Load(List<Dictionary<string, int>> data)\n    {\n    }\n\n    public List<List<int>> Build()\n    {\n        return new List<List<int>>();\n    }\n\n    public void Save(Dictionary<string, int> data)\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4017");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 7);
}

#[test]
fn s2436_caps_generic_arities_with_boundaries_clean() {
    let report = analyze_default(
        "class Pairing<A, B>\n{\n}\nclass Tripling<A, B, C>\n{\n}\nclass Handler\n{\n    public void Trio<TOne, TTwo, TThree>(TOne first, TTwo second, TThree third)\n    {\n    }\n\n    public void Quad<TOne, TTwo, TThree, TFour>(TOne first, TTwo second, TThree third, TFour fourth)\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2436");
    assert_eq!(flagged.len(), 2);
    assert_eq!(
        flagged[0].message,
        "Reduce the number of type parameters (3 > 2)."
    );
    assert_eq!(
        flagged[1].message,
        "Reduce the number of type parameters (4 > 3)."
    );

    let options = AnalyzerOptions {
        maximum_generic_parameters_for_methods: 1,
        ..Default::default()
    };
    let tightened = analyze_options(
        "class Solo\n{\n    public void Duo<TOne, TTwo>(TOne first, TTwo second)\n    {\n    }\n}\n",
        &options,
    );
    let capped = with_key(&tightened, "csharpsquid:S2436");
    assert_eq!(capped.len(), 1);
    assert_eq!(
        capped[0].message,
        "Reduce the number of type parameters (2 > 1)."
    );
    assert!(with_key(&analyze_default("class Solo\n{\n    public void Duo<TOne, TTwo>(TOne first, TTwo second)\n    {\n    }\n}\n"), "csharpsquid:S2436").is_empty());
}

#[test]
fn s4018_flags_method_type_parameters_missing_from_parameter_list() {
    let report = analyze_default(
        "class Sender\n{\n    public void Send<TMessage>(TMessage message)\n    {\n    }\n\n    public void Lose<TLost>()\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4018");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);
}

#[test]
fn s2326_flags_unused_type_parameters_constraints_count_as_usage() {
    let report = analyze_default(
        "class Box<TContent>\n{\n    private int size;\n}\nclass Crate<TItem>\n{\n    private TItem item;\n\n    public bool Matches<TOther>(TOther candidate)\n        where TOther : TItem\n    {\n        return false;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2326");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);
}

#[test]
fn s3168_flags_async_void_methods() {
    let report = analyze_default(
        "class Worker\n{\n    public async void FireAsync()\n    {\n    }\n\n    public async System.Threading.Tasks.Task RunAsync()\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3168");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s2306_flags_async_await_identifiers_but_not_keywords() {
    let report = analyze_default(
        "int async = 1;\nint await = 2;\n\nclass Sleeper\n{\n    public async void NapAsync()\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2306");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 1);
    assert_eq!(flagged[1].range.start.line, 2);
}

#[test]
fn s907_flags_goto_statements() {
    let report = analyze_default(
        "class Jumper\n{\n    public void Jump()\n    {\n        goto Done;\nDone:\n        return;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S907");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s1227_flags_break_outside_loops_and_switches() {
    let report = analyze_default(
        "class Runner\n{\n    public void Run(bool again)\n    {\n        if (again)\n        {\n            break;\n        }\n    }\n\n    public void Walk()\n    {\n        while (true)\n        {\n            break;\n        }\n    }\n\n    public int Pick(int number)\n    {\n        switch (number)\n        {\n            case 1:\n                break;\n        }\n        return number;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1227");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);
}

#[test]
fn s6640_flags_unsafe_blocks_and_declarations() {
    let report = analyze_default(
        "class Raw\n{\n    public void Touch()\n    {\n        unsafe\n        {\n            int value = 1;\n        }\n    }\n\n    public unsafe void Direct()\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S6640");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 11);
    assert_eq!(flagged[0].message, "Remove this unsafe block.");
    assert_eq!(
        flagged[1].message,
        "Remove the 'unsafe' modifier from this declaration."
    );
}

#[test]
fn s4061_flags_arglist_usage() {
    let report = analyze_default(
        "class Varargs\n{\n    public void Call()\n    {\n        Native(1, __arglist);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4061");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s121_requires_curly_braces_on_embedded_statements() {
    let report = analyze_default(
        "class A\n{\n    void M(bool x)\n    {\n        if (x)\n        {\n            DoIt();\n        }\n        while (x)\n            DoIt();\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S121");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 10);

    let clean = analyze_default(
        "class A\n{\n    void M(bool x)\n    {\n        while (x)\n        {\n            DoIt();\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S121").is_empty());
}

#[test]
fn s108_flags_empty_blocks_but_not_commented_ones() {
    let report = analyze_default(
        "class A\n{\n    void M(bool x)\n    {\n        if (x)\n        {\n        }\n        if (x)\n        {\n            /* note */\n        }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S108");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 6);
}

#[test]
fn s1116_flags_empty_statements() {
    let report =
        analyze_default("class A\n{\n    void M()\n    {\n        ;\n        DoIt();\n    }\n}\n");
    let flagged = with_key(&report, "csharpsquid:S1116");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s1110_flags_redundant_parenthesis_pairs() {
    let report = analyze_default(
        "class A\n{\n    int Twice(int x)\n    {\n        return ((x)) + (x);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1110");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s3235_flags_return_and_argument_parentheses() {
    let report = analyze_default(
        "class A\n{\n    int Get(int x)\n    {\n        return (x);\n    }\n    void Use(int y)\n    {\n        Consume((y));\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3235");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 9);

    let clean =
        analyze_default("class A\n{\n    int Get(int x)\n    {\n        return x;\n    }\n}\n");
    assert!(with_key(&clean, "csharpsquid:S3235").is_empty());
}

#[test]
fn s1066_merges_else_less_ifs_holding_one_nested_if() {
    let report = analyze_default(
        "class A\n{\n    void M(bool a, bool b)\n    {\n        if (a)\n        {\n            if (b)\n            {\n                DoIt();\n            }\n        }\n        if (a)\n        {\n            if (b)\n            {\n                DoIt();\n            }\n            else\n            {\n                Stop();\n            }\n        }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1066");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s126_demands_a_terminal_else_on_chains() {
    let open_chain = analyze_default(
        "class A\n{\n    void M(int n)\n    {\n        if (n == 1)\n        {\n            Stop();\n        }\n        else if (n == 2)\n        {\n            Stop();\n        }\n    }\n}\n",
    );
    let flagged = with_key(&open_chain, "csharpsquid:S126");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 9);

    let closed_chain = analyze_default(
        "class A\n{\n    void M(int n)\n    {\n        if (n == 1)\n        {\n            Stop();\n        }\n        else\n        {\n            Stop();\n        }\n    }\n}\n",
    );
    assert!(with_key(&closed_chain, "csharpsquid:S126").is_empty());
}

#[test]
fn s131_requires_a_default_clause() {
    let missing = analyze_default(
        "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                break;\n        }\n    }\n}\n",
    );
    assert_eq!(with_key(&missing, "csharpsquid:S131").len(), 1);

    let present = analyze_default(
        "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                break;\n            default:\n                break;\n        }\n    }\n}\n",
    );
    assert!(with_key(&present, "csharpsquid:S131").is_empty());
}

#[test]
fn s1301_rejects_switches_with_fewer_than_three_cases() {
    let small = analyze_default(
        "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                break;\n            case 2:\n                break;\n            default:\n                break;\n        }\n    }\n}\n",
    );
    assert_eq!(with_key(&small, "csharpsquid:S1301").len(), 1);

    let boundary = analyze_default(
        "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                break;\n            case 2:\n                break;\n            case 3:\n                break;\n            default:\n                break;\n        }\n    }\n}\n",
    );
    assert!(with_key(&boundary, "csharpsquid:S1301").is_empty());
}

#[test]
fn s1479_limits_switch_section_statement_counts() {
    let options = AnalyzerOptions {
        maximum_switch_section_statements: 2,
        ..Default::default()
    };
    let over = analyze_options(
        "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                DoIt();\n                DoIt();\n                DoIt();\n                break;\n        }\n    }\n}\n",
        &options,
    );
    assert_eq!(with_key(&over, "csharpsquid:S1479").len(), 1);

    let at_limit = analyze_options(
        "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                DoIt();\n                break;\n        }\n    }\n}\n",
        &options,
    );
    assert!(with_key(&at_limit, "csharpsquid:S1479").is_empty());
}

#[test]
fn s1151_limits_switch_section_line_spans() {
    let options = AnalyzerOptions {
        maximum_switch_section_lines: 4,
        ..Default::default()
    };
    let over = analyze_options(
        "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                DoIt();\n                DoIt();\n                DoIt();\n                break;\n        }\n    }\n}\n",
        &options,
    );
    assert_eq!(with_key(&over, "csharpsquid:S1151").len(), 1);

    let at_limit = analyze_options(
        "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                DoIt();\n                DoIt();\n                break;\n        }\n    }\n}\n",
        &options,
    );
    assert!(with_key(&at_limit, "csharpsquid:S1151").is_empty());
}

#[test]
fn s134_enforces_the_configured_nesting_depth() {
    let nested = "class A\n{\n    void M(bool go, bool ok)\n    {\n        foreach (var item in Items)\n        {\n            while (go)\n            {\n                if (ok)\n                {\n                    DoIt();\n                }\n            }\n        }\n    }\n}\n";
    let options = AnalyzerOptions {
        maximum_nesting_level: 0,
        ..Default::default()
    };
    let report = analyze_options(nested, &options);
    let flagged = with_key(&report, "csharpsquid:S134");
    assert_eq!(flagged[0].range.start.line, 7);
    assert_eq!(flagged[1].range.start.line, 9);

    let relaxed = AnalyzerOptions {
        maximum_nesting_level: 2,

        ..Default::default()
    };
    assert!(with_key(&analyze_options(nested, &relaxed), "csharpsquid:S134").is_empty());
}

#[test]
fn s1199_flags_plain_nested_code_blocks() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        {\n            DoIt();\n        }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1199");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s2681_encloses_multiline_embedded_bodies_in_braces() {
    let report = analyze_default(
        "class A\n{\n    void M(int x)\n    {\n        if (x > 0)\n            DoIt(\n                x);\n        if (x > 0)\n        {\n            DoIt(x);\n        }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2681");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 6);

    let braced = analyze_default(
        "class A\n{\n    void M(int x)\n    {\n        if (x > 0)\n        {\n            DoIt(\n                x);\n        }\n    }\n}\n",
    );
    assert!(with_key(&braced, "csharpsquid:S2681").is_empty());
}

#[test]
fn s1821_flags_switches_nested_in_switches() {
    let report = analyze_default(
        "class A\n{\n    void M(int a, int b)\n    {\n        switch (a)\n        {\n            case 1:\n                switch (b)\n                {\n                    case 2:\n                        break;\n                }\n                break;\n        }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1821");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 8);

    let flat = analyze_default(
        "class A\n{\n    void M(int a)\n    {\n        switch (a)\n        {\n            case 1:\n                break;\n        }\n    }\n}\n",
    );
    assert!(with_key(&flat, "csharpsquid:S1821").is_empty());
}

#[test]
fn s4524_keeps_default_first_or_last() {
    let middle = analyze_default(
        "class A\n{\n    void M(int a)\n    {\n        switch (a)\n        {\n            case 1:\n                break;\n            default:\n                break;\n            case 2:\n                break;\n        }\n    }\n}\n",
    );
    let flagged = with_key(&middle, "csharpsquid:S4524");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 9);

    let trailing = analyze_default(
        "class A\n{\n    void M(int a)\n    {\n        switch (a)\n        {\n            case 1:\n                break;\n            case 2:\n                break;\n            default:\n                break;\n        }\n    }\n}\n",
    );
    assert!(with_key(&trailing, "csharpsquid:S4524").is_empty());
}

#[test]
fn s3458_drops_empty_cases_falling_into_default() {
    let report = analyze_default(
        "class A\n{\n    void M(int a)\n    {\n        switch (a)\n        {\n            case 1:\n            default:\n                break;\n            case 2:\n                break;\n        }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3458");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);

    let stacked = analyze_default(
        "class A\n{\n    void M(int a)\n    {\n        switch (a)\n        {\n            case 1:\n            case 2:\n                break;\n            default:\n                break;\n        }\n    }\n}\n",
    );
    assert!(with_key(&stacked, "csharpsquid:S3458").is_empty());
}

#[test]
fn s3532_removes_empty_default_clauses() {
    let report = analyze_default(
        "class A\n{\n    void M(int a)\n    {\n        switch (a)\n        {\n            case 1:\n                break;\n            default:\n        }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3532");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 9);

    let populated = analyze_default(
        "class A\n{\n    void M(int a)\n    {\n        switch (a)\n        {\n            default:\n                break;\n        }\n    }\n}\n",
    );
    assert!(with_key(&populated, "csharpsquid:S3532").is_empty());
}

#[test]
fn s1264_converts_condition_only_for_loops_to_while() {
    let report = analyze_default(
        "class A\n{\n    void M(bool go)\n    {\n        for (;;)\n        {\n            if (!go)\n            {\n                break;\n            }\n        }\n        for (; go; )\n        {\n            DoIt();\n        }\n        for (var i = 0; i < 3; i++)\n        {\n            DoIt();\n        }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1264");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 12);

    let complete = analyze_default(
        "class A\n{\n    void M()\n    {\n        for (var i = 0; i < 3; i++)\n        {\n            DoIt();\n        }\n    }\n}\n",
    );
    assert!(with_key(&complete, "csharpsquid:S1264").is_empty());
}

#[test]
fn s1994_requires_the_increment_to_drive_the_counter() {
    let detached = analyze_default(
        "class A\n{\n    void M()\n    {\n        for (var i = 0; i < 3; )\n        {\n            i = 1;\n        }\n    }\n}\n",
    );
    let flagged = with_key(&detached, "csharpsquid:S1994");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let driven = analyze_default(
        "class A\n{\n    void M()\n    {\n        for (var i = 0; i < 3; i++)\n        {\n            DoIt();\n        }\n    }\n}\n",
    );
    assert!(with_key(&driven, "csharpsquid:S1994").is_empty());
}

#[test]
fn s138_limits_function_body_spans() {
    let options = AnalyzerOptions {
        maximum_function_lines: 2,
        ..Default::default()
    };
    let over = analyze_options(
        "class A\n{\n    void M()\n    {\n        DoIt();\n        DoIt();\n        DoIt();\n    }\n}\n",
        &options,
    );
    let flagged = with_key(&over, "csharpsquid:S138");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let at_limit = AnalyzerOptions {
        maximum_function_lines: 5,
        ..Default::default()
    };
    assert!(
            with_key(&analyze_options(
                "class A\n{\n    void M()\n    {\n        DoIt();\n        DoIt();\n        DoIt();\n    }\n}\n",
                &at_limit
            ), "csharpsquid:S138")
                .is_empty()
        );
}

#[test]
fn s107_limits_method_parameter_counts() {
    let eight = analyze_default(
        "class A\n{\n    void M(int a, int b, int c, int d, int e, int f, int g, int h)\n    {\n        DoIt();\n    }\n}\n",
    );
    let flagged = with_key(&eight, "csharpsquid:S107");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let seven = analyze_default(
        "class A\n{\n    void M(int a, int b, int c, int d, int e, int f, int g)\n    {\n        DoIt();\n    }\n}\n",
    );
    assert!(with_key(&seven, "csharpsquid:S107").is_empty());
}

#[test]
fn s1541_limits_cyclomatic_complexity() {
    let branching = "class A\n{\n    int Score(bool a, bool b, bool c)\n    {\n        if (a && b)\n        {\n            return 1;\n        }\n        return c ? 2 : 3;\n    }\n}\n";
    let strict = AnalyzerOptions {
        maximum_function_complexity_threshold: 3,
        ..Default::default()
    };
    let report = analyze_options(branching, &strict);
    let flagged = with_key(&report, "csharpsquid:S1541");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let tolerant = AnalyzerOptions {
        maximum_function_complexity_threshold: 4,
        ..Default::default()
    };
    assert!(with_key(&analyze_options(branching, &tolerant), "csharpsquid:S1541").is_empty());
}

#[test]
fn s3776_limits_cognitive_complexity_with_nesting_weights() {
    let nested = "class A\n{\n    void M(bool a, bool b)\n    {\n        if (a)\n        {\n            if (b)\n            {\n                DoIt();\n            }\n        }\n    }\n}\n";
    let strict = AnalyzerOptions {
        maximum_cognitive_complexity_threshold: 2,
        ..Default::default()
    };
    let report = analyze_options(nested, &strict);
    let flagged = with_key(&report, "csharpsquid:S3776");
    assert_eq!(flagged[0].range.start.line, 3);

    let tolerant = AnalyzerOptions {
        maximum_cognitive_complexity_threshold: 3,
        ..Default::default()
    };
    assert!(with_key(&analyze_options(nested, &tolerant), "csharpsquid:S3776").is_empty());
}

#[test]
fn s1067_limits_logical_operators_per_expression() {
    let four = analyze_default(
        "class A\n{\n    bool Check(bool a, bool b, bool c, bool d, bool e)\n    {\n        return a && b && c && d && e;\n    }\n}\n",
    );
    let flagged = with_key(&four, "csharpsquid:S1067");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let three = analyze_default(
        "class A\n{\n    bool Check(bool a, bool b, bool c)\n    {\n        return a && b && c;\n    }\n}\n",
    );
    assert!(with_key(&three, "csharpsquid:S1067").is_empty());
}

#[test]
fn s1186_flags_empty_methods_except_attributed_ones() {
    let report = analyze_default(
        "class A\n{\n    void Empty()\n    {\n    }\n\n    [System.Obsolete]\n    void Hook()\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1186");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s1048_forbids_throwing_finalizers() {
    let report = analyze_default(
        "class A\n{\n    ~A()\n    {\n        throw new System.Exception();\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1048");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let quiet = analyze_default("class A\n{\n    ~A()\n    {\n        Release();\n    }\n}\n");
    assert!(with_key(&quiet, "csharpsquid:S1048").is_empty());
}

#[test]
fn s3880_flags_empty_finalizers() {
    let report = analyze_default("class A\n{\n    ~A()\n    {\n    }\n}\n");
    let flagged = with_key(&report, "csharpsquid:S3880");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s2372_forbids_throwing_property_getters() {
    let report = analyze_default(
        "class A\n{\n    string Name\n    {\n        get\n        {\n            throw new System.Exception();\n        }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2372");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let calm = analyze_default("class A\n{\n    string Name => \"value\";\n}\n");
    assert!(with_key(&calm, "csharpsquid:S2372").is_empty());
}

#[test]
fn s2376_flags_write_only_properties() {
    let report = analyze_default(
        "class A\n{\n    string Name\n    {\n        set\n        {\n            stored = value;\n        }\n    }\n\n    string Both\n    {\n        get\n        {\n            return stored;\n        }\n        set\n        {\n            stored = value;\n        }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2376");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s2292_replaces_trivial_accessor_pairs_with_auto_properties() {
    let report = analyze_default(
        "class A\n{\n    int Value\n    {\n        get { return number; }\n        set { number = value; }\n    }\n\n    int Auto { get; set; }\n\n    int Computed\n    {\n        get { return number + 1; }\n        set { number = value; }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2292");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s1694_demands_abstract_and_concrete_members_on_abstract_classes() {
    let report = analyze_default(
        "abstract class OnlyAbstract\n{\n    public abstract void Go();\n}\n\nabstract class OnlyConcrete\n{\n    public void Walk()\n    {\n        DoIt();\n    }\n}\n\nabstract class Mixed\n{\n    public abstract void Run();\n\n    public void Walk()\n    {\n        DoIt();\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1694");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 1);
    assert_eq!(flagged[1].range.start.line, 6);
}

#[test]
fn s2094_flags_empty_classes_and_records() {
    let report = analyze_default(
        "class Bare\n{\n}\n\nrecord BareRecord;\n\npartial class Split\n{\n}\n\nrecord Positioned(int Id);\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2094");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 1);
    assert_eq!(flagged[1].range.start.line, 5);
}

#[test]
fn s4023_flags_empty_interfaces() {
    let report =
        analyze_default("interface IBare\n{\n}\n\ninterface IFull\n{\n    void Go();\n}\n");
    let flagged = with_key(&report, "csharpsquid:S4023");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);
}

#[test]
fn s3261_flags_empty_namespaces() {
    let report = analyze_default(
        "namespace Empty\n{\n}\n\nnamespace Full\n{\n    class Inside\n    {\n        int member;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3261");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);
}

#[test]
fn s3903_moves_file_scope_types_into_namespaces() {
    let report =
        analyze_default("class One\n{\n    int member;\n}\n\nclass Two\n{\n    int member;\n}\n");
    let flagged = with_key(&report, "csharpsquid:S3903");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 1);
    assert_eq!(flagged[1].range.start.line, 6);

    let lone = analyze_default("class Solo\n{\n    int member;\n}\n");
    assert!(with_key(&lone, "csharpsquid:S3903").is_empty());
}

#[test]
fn s1764_flags_identical_operands() {
    let report =
        analyze_default("class A\n{\n    void M(int x)\n    {\n        var d = x - x;\n    }\n}\n");
    let flagged = with_key(&report, "csharpsquid:S1764");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let clean =
        analyze_default("class A\n{\n    void M(int x)\n    {\n        var m = x * x;\n    }\n}\n");
    assert!(with_key(&clean, "csharpsquid:S1764").is_empty());
}

#[test]
fn s1862_flags_repeated_else_if_conditions() {
    let report = analyze_default(
        "class A\n{\n    void M(int x)\n    {\n        if (x > 0) { Work(); }\n        else if (x > 0) { More(); }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1862");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 6);

    let clean = analyze_default(
        "class A\n{\n    void M(int x)\n    {\n        if (x > 0) { Work(); }\n        else if (x < 0) { More(); }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S1862").is_empty());
}

#[test]
fn s3923_flags_fully_identical_branches() {
    let report = analyze_default(
        "class A\n{\n    void M(bool flag)\n    {\n        if (flag) { Run(); }\n        else { Run(); }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3923");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let clean = analyze_default(
        "class A\n{\n    void M(bool flag)\n    {\n        if (flag) { Run(); }\n        else { Stop(); }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3923").is_empty());
}

#[test]
fn s1871_flags_duplicate_switch_sections() {
    let report = analyze_default(
        "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                Work();\n                break;\n            case 2:\n                Work();\n                break;\n        }\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S1871").len(), 1);
    assert!(with_key(&report, "csharpsquid:S3626").is_empty());

    let clean = analyze_default(
        "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                Work();\n                break;\n            case 2:\n                Rest();\n                break;\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S1871").is_empty());
}

#[test]
fn s4144_flags_identical_sibling_method_bodies() {
    let report = analyze_default(
        "class A\n{\n    int First()\n    {\n        return Compute(1);\n    }\n\n    int Second()\n    {\n        return Compute(1);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4144");
    assert_eq!(flagged.len(), 1);

    let clean = analyze_default(
        "class A\n{\n    int First()\n    {\n        return Compute(1);\n    }\n\n    int Second()\n    {\n        return Compute(2);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4144").is_empty());
}

#[test]
fn s2760_flags_adjacent_repeated_conditions() {
    let report = analyze_default(
        "class A\n{\n    void M(int x)\n    {\n        if (x > 0) { Work(); }\n        if (x > 0) { More(); }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2760");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 6);

    let clean = analyze_default(
        "class A\n{\n    void M(int x)\n    {\n        if (x > 0) { Work(); }\n        if (x < 9) { More(); }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2760").is_empty());
}

#[test]
fn s3441_flags_redundant_anonymous_property_names() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        var o = new { Name = Name };\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3441");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let clean = analyze_default(
        "class A\n{\n    void M(string other)\n    {\n        var o = new { Name = other };\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3441").is_empty());
}

#[test]
fn s3604_flags_self_referential_member_initializers() {
    let report = analyze_default(
        "class A\n{\n    void M(int x)\n    {\n        var p = new Point { X = x, Y = Y };\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3604");
    assert_eq!(flagged.len(), 1);

    let clean = analyze_default(
        "class A\n{\n    void M(int x)\n    {\n        var p = new Point { X = x };\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3604").is_empty());
}

#[test]
fn s3400_flags_constant_returning_methods() {
    let report =
        analyze_default("class A\n{\n    int Answer()\n    {\n        return 42;\n    }\n}\n");
    let flagged = with_key(&report, "csharpsquid:S3400");
    assert_eq!(flagged.len(), 1);

    let computed =
        analyze_default("class A\n{\n    int Sum()\n    {\n        return 40 + 2;\n    }\n}\n");
    assert!(with_key(&computed, "csharpsquid:S3400").is_empty());

    let entry_point = analyze_options(
        "class A\n{\n    static void Main()\n    {\n        return;\n    }\n}\n",
        &AnalyzerOptions::default(),
    );
    assert!(with_key(&entry_point, "csharpsquid:S3400").is_empty());
}

#[test]
fn s3626_flags_trailing_loop_jumps_only() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        while (KeepGoing())\n        {\n            Step();\n            break;\n        }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3626");
    assert_eq!(flagged[0].range.start.line, 8);

    let falling_through = analyze_default(
        "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                Step();\n                break;\n        }\n    }\n}\n",
    );
    assert!(with_key(&falling_through, "csharpsquid:S3626").is_empty());
}

#[test]
fn s1848_and_s3984_split_dropped_creations_by_type() {
    let plain =
        analyze_default("class A\n{\n    void M()\n    {\n        new Widget();\n    }\n}\n");
    assert_eq!(with_key(&plain, "csharpsquid:S1848").len(), 1);
    assert!(with_key(&plain, "csharpsquid:S3984").is_empty());

    let exception = analyze_default(
        "class A\n{\n    void M()\n    {\n        new BoomException(\"why\");\n    }\n}\n",
    );
    assert_eq!(with_key(&exception, "csharpsquid:S3984").len(), 1);
    assert!(with_key(&exception, "csharpsquid:S1848").is_empty());

    let used = analyze_default(
        "class A\n{\n    void M()\n    {\n        var w = new Widget();\n    }\n}\n",
    );
    assert!(with_key(&used, "csharpsquid:S1848").is_empty());
}

#[test]
fn s3717_tracks_not_implemented_throws() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        throw new NotImplementedException(\"later\");\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3717");
    assert_eq!(flagged.len(), 1);

    let done = analyze_default(
        "class A\n{\n    void M()\n    {\n        throw new System.Exception(\"boom\");\n    }\n}\n",
    );
    assert!(with_key(&done, "csharpsquid:S3717").is_empty());
}

#[test]
fn s1133_and_s1123_distinguish_annotated_obsoletes() {
    let bare = analyze_default("[Obsolete]\nclass Old\n{\n}\n");
    assert_eq!(with_key(&bare, "csharpsquid:S1133").len(), 1);
    assert_eq!(with_key(&bare, "csharpsquid:S1123").len(), 1);

    let explained = analyze_default("[Obsolete(\"use New\")]\nclass Old\n{\n}\n");
    assert_eq!(with_key(&explained, "csharpsquid:S1133").len(), 1);
    assert!(with_key(&explained, "csharpsquid:S1123").is_empty());

    let fresh = analyze_default("class Current\n{\n}\n");
    assert!(with_key(&fresh, "csharpsquid:S1133").is_empty());
}

#[test]
fn s1309_tracks_suppressions_and_pragmas() {
    let attribute =
        analyze_default("[SuppressMessage(\"Category\", \"CheckId\")]\nclass A\n{\n}\n");
    assert_eq!(with_key(&attribute, "csharpsquid:S1309").len(), 1);

    let pragma =
        analyze_default("class A\n{\n#pragma warning disable CS1234\n    void M() { }\n}\n");
    assert_eq!(with_key(&pragma, "csharpsquid:S1309").len(), 1);

    let quiet = analyze_default("class A\n{\n    void M() { }\n}\n");
    assert!(with_key(&quiet, "csharpsquid:S1309").is_empty());
}

#[test]
fn s1607_flags_ignored_tests() {
    let ignored = analyze_default(
        "[Fact(Ignore = \"broken\")]\nvoid T() { }\n"
            .replace("[Fact(Ignore = \"broken\")]", "[Ignore]")
            .as_str(),
    );
    assert_eq!(with_key(&ignored, "csharpsquid:S1607").len(), 1);

    let active = analyze_default("class Tests\n{\n    [Fact]\n    void T() { }\n}\n");
    assert!(with_key(&active, "csharpsquid:S1607").is_empty());
}

#[test]
fn s3431_flags_expected_exception_attribute() {
    let report = analyze_default("[ExpectedException(typeof(System.Exception))]\nvoid T() { }\n");
    assert_eq!(with_key(&report, "csharpsquid:S3431").len(), 1);

    let clean = analyze_default("class Tests\n{\n    [Fact]\n    void T() { }\n}\n");
    assert!(with_key(&clean, "csharpsquid:S3431").is_empty());
}

#[test]
fn s6513_requires_coverage_exclusion_reasons() {
    let bare = analyze_default("[ExcludeFromCodeCoverage]\nclass Generated\n{\n}\n");
    assert_eq!(with_key(&bare, "csharpsquid:S6513").len(), 1);

    let justified =
        analyze_default("[ExcludeFromCodeCoverage(\"generated code\")]\nclass Generated\n{\n}\n");
    assert!(with_key(&justified, "csharpsquid:S6513").is_empty());
}

#[test]
fn s1210_requires_comparable_contracts() {
    let incomplete = analyze_default(
        "class Temp : IComparable<Temp>\n{\n    public int CompareTo(Temp other) => 0;\n}\n",
    );
    assert_eq!(with_key(&incomplete, "csharpsquid:S1210").len(), 1);

    let complete = analyze_default(
        "class Temp : IComparable<Temp>\n{\n    public int value;\n\n    public int CompareTo(Temp other) => value.CompareTo(other.value);\n\n    public override bool Equals(object obj) => obj is Temp other && value == other.value;\n\n    public static bool operator <(Temp a, Temp b) => a.value < b.value;\n\n    public static bool operator >(Temp a, Temp b) => a.value > b.value;\n}\n",
    );
    assert!(with_key(&complete, "csharpsquid:S1210").is_empty());
}

#[test]
fn s1206_flags_lone_equals_or_gethashcode_overrides() {
    let lone_equals =
        analyze_default("class C\n{\n    public override bool Equals(object obj) => true;\n}\n");
    assert_eq!(with_key(&lone_equals, "csharpsquid:S1206").len(), 1);

    let paired = analyze_default(
        "class C\n{\n    public override bool Equals(object obj) => true;\n\n    public override int GetHashCode() => 7;\n}\n",
    );
    assert!(with_key(&paired, "csharpsquid:S1206").is_empty());
}

#[test]
fn s2166_flags_exception_names_without_exception_bases() {
    let misnamed = analyze_default("class BoomException\n{\n}\n");
    assert_eq!(with_key(&misnamed, "csharpsquid:S2166").len(), 1);

    let proper = analyze_default("class BoomException : System.Exception\n{\n}\n");
    assert!(with_key(&proper, "csharpsquid:S2166").is_empty());
}

#[test]
fn s4027_requires_standard_constructors() {
    let thin =
        analyze_default("class BoomError : System.Exception\n{\n    public BoomError() { }\n}\n");
    assert_eq!(with_key(&thin, "csharpsquid:S4027").len(), 1);

    let full = analyze_default(
        "class BoomError : System.Exception\n{\n    public BoomError() { }\n\n    public BoomError(string message) { }\n\n    public BoomError(string message, System.Exception inner) { }\n}\n",
    );
    assert!(with_key(&full, "csharpsquid:S4027").is_empty());
}

#[test]
fn s3875_flags_operator_equals_on_classes_but_not_structs() {
    let class_form = analyze_default(
        "class Ref\n{\n    public static bool operator ==(Ref a, Ref b) => true;\n\n    public static bool operator !=(Ref a, Ref b) => false;\n}\n",
    );
    assert_eq!(with_key(&class_form, "csharpsquid:S3875").len(), 1);

    let struct_form = analyze_default(
        "struct Value\n{\n    public static bool operator ==(Value a, Value b) => true;\n\n    public static bool operator !=(Value a, Value b) => false;\n}\n",
    );
    assert!(with_key(&struct_form, "csharpsquid:S3875").is_empty());
}

#[test]
fn s4050_requires_equality_operator_pairing() {
    let unpaired = analyze_default(
        "struct Value\n{\n    public static bool operator ==(Value a, Value b) => true;\n}\n",
    );
    assert_eq!(with_key(&unpaired, "csharpsquid:S4050").len(), 1);

    let paired = analyze_default(
        "struct Value\n{\n    public static bool operator ==(Value a, Value b) => true;\n\n    public static bool operator !=(Value a, Value b) => false;\n\n    public override bool Equals(object obj) => true;\n}\n",
    );
    assert!(with_key(&paired, "csharpsquid:S4050").is_empty());
}

#[test]
fn s4069_requires_named_operator_alternatives() {
    let anonymous = analyze_default(
        "struct Money\n{\n    public static Money operator +(Money a, Money b) => a;\n}\n",
    );
    assert_eq!(with_key(&anonymous, "csharpsquid:S4069").len(), 1);

    let named = analyze_default(
        "struct Money\n{\n    public static Money operator +(Money a, Money b) => a;\n\n    public static Money Add(Money a, Money b) => a;\n}\n",
    );
    assert!(with_key(&named, "csharpsquid:S4069").is_empty());
}

#[test]
fn s3877_flags_throws_from_special_methods() {
    let throwing = analyze_default(
        "class C\n{\n    public override string ToString()\n    {\n        throw new System.Exception();\n    }\n}\n",
    );
    assert_eq!(with_key(&throwing, "csharpsquid:S3877").len(), 1);

    let calm = analyze_default(
        "class C\n{\n    public override string ToString()\n    {\n        return nameof(C);\n    }\n}\n",
    );
    assert!(with_key(&calm, "csharpsquid:S3877").is_empty());
}

#[test]
fn s2225_flags_null_returning_to_string() {
    let null_return = analyze_default(
        "class C\n{\n    public override string ToString()\n    {\n        return null;\n    }\n}\n",
    );
    assert_eq!(with_key(&null_return, "csharpsquid:S2225").len(), 1);

    let real_value = analyze_default(
        "class C\n{\n    public override string ToString()\n    {\n        return \"C\";\n    }\n}\n",
    );
    assert!(with_key(&real_value, "csharpsquid:S2225").is_empty());
}

#[test]
fn s2328_flags_mutable_fields_in_gethashcode() {
    let poisoned = analyze_default(
        "class C\n{\n    private int moving;\n\n    private readonly int frozen;\n\n    public override int GetHashCode() => frozen + moving;\n}\n",
    );
    assert_eq!(with_key(&poisoned, "csharpsquid:S2328").len(), 1);

    let stable = analyze_default(
        "class C\n{\n    private readonly int frozen;\n\n    public override int GetHashCode() => frozen;\n}\n",
    );
    assert!(with_key(&stable, "csharpsquid:S2328").is_empty());
}

#[test]
fn s3397_flags_base_equals_inside_equals_override() {
    let misuse = analyze_default(
        "class C\n{\n    public override bool Equals(object obj) => base.Equals(obj);\n}\n",
    );
    assert_eq!(with_key(&misuse, "csharpsquid:S3397").len(), 1);

    let proper = analyze_default(
        "class C\n{\n    public override bool Equals(object obj) => obj is C other && other.id == id;\n\n    private int id;\n}\n",
    );
    assert!(with_key(&proper, "csharpsquid:S3397").is_empty());
}

#[test]
fn s3249_flags_base_calls_on_object_derived_types() {
    let direct = analyze_default(
        "class C\n{\n    public override int GetHashCode() => base.GetHashCode();\n}\n",
    );
    assert_eq!(with_key(&direct, "csharpsquid:S3249").len(), 1);

    let derived = analyze_default(
        "class D : IEquatable<D>\n{\n    public bool Equals(D other) => true;\n\n    public override int GetHashCode() => base.GetHashCode();\n}\n",
    );
    assert!(with_key(&derived, "csharpsquid:S3249").is_empty());
}

#[test]
fn s3897_flags_typed_equals_without_iequatable() {
    let undeclared = analyze_default("class C\n{\n    public bool Equals(C other) => true;\n}\n");
    assert_eq!(with_key(&undeclared, "csharpsquid:S3897").len(), 1);

    let declared = analyze_default(
        "class C : IEquatable<C>\n{\n    public bool Equals(C other) => true;\n}\n",
    );
    assert!(with_key(&declared, "csharpsquid:S3897").is_empty());
}

#[test]
fn s3898_flags_structs_without_iequatable() {
    let boxed = analyze_default("struct Plain\n{\n    public int Value;\n}\n");
    assert_eq!(with_key(&boxed, "csharpsquid:S3898").len(), 1);

    let equatable = analyze_default(
        "struct Plain : IEquatable<Plain>\n{\n    public int Value;\n\n    public bool Equals(Plain other) => Value == other.Value;\n}\n",
    );
    assert!(with_key(&equatable, "csharpsquid:S3898").is_empty());
}

#[test]
fn s3971_and_s3234_track_suppress_finalize_calls() {
    let finalizerless = analyze_default(
        "class C\n{\n    void Close()\n    {\n        System.GC.SuppressFinalize(this);\n    }\n}\n",
    );
    assert_eq!(with_key(&finalizerless, "csharpsquid:S3971").len(), 1);
    assert_eq!(with_key(&finalizerless, "csharpsquid:S3234").len(), 1);

    let with_finalizer = analyze_default(
        "class C\n{\n    ~C() { }\n\n    void Close()\n    {\n        System.GC.SuppressFinalize(this);\n    }\n}\n",
    );
    assert_eq!(with_key(&with_finalizer, "csharpsquid:S3971").len(), 1);
    assert!(with_key(&with_finalizer, "csharpsquid:S3234").is_empty());
}

#[test]
fn s1215_flags_gc_collect_calls() {
    let report = analyze_default(
        "class C\n{\n    void Clean()\n    {\n        System.GC.Collect();\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S1215").len(), 1);

    let clean = analyze_default(
        "class C\n{\n    void Clean()\n    {\n        System.GC.KeepAlive(this);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S1215").is_empty());
}

#[test]
fn s1147_flags_exit_calls() {
    let report = analyze_default(
        "class C\n{\n    void Bail()\n    {\n        Environment.Exit(1);\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S1147").len(), 1);

    let clean =
        analyze_default("class C\n{\n    void Bail()\n    {\n        Shutdown.Now();\n    }\n}\n");
    assert!(with_key(&clean, "csharpsquid:S1147").is_empty());
}

#[test]
fn s106_flags_console_writes() {
    let report = analyze_default(
        "class C\n{\n    void Talk()\n    {\n        Console.WriteLine(\"hi\");\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S106").len(), 1);

    let clean = analyze_default(
        "class C\n{\n    void Talk()\n    {\n        Log.WriteLine(\"hi\");\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S106").is_empty());
}

#[test]
fn s2925_flags_thread_sleep_only_in_tests() {
    let test = analyze_default(
        "class Checks\n{\n    [Fact]\n    void Waits()\n    {\n        Thread.Sleep(10);\n    }\n}\n",
    );
    assert_eq!(with_key(&test, "csharpsquid:S2925").len(), 1);

    let production = analyze_default(
        "class Service\n{\n    void Waits()\n    {\n        Thread.Sleep(10);\n    }\n}\n",
    );
    assert!(with_key(&production, "csharpsquid:S2925").is_empty());
}

#[test]
fn s3889_flags_thread_suspend_resume() {
    let report = analyze_default(
        "class C\n{\n    void Pause(Thread workerThread)\n    {\n        workerThread.Suspend();\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S3889").len(), 1);

    let clean = analyze_default(
        "class C\n{\n    void Pause(Thread worker)\n    {\n        worker.Join();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3889").is_empty());
}
