//! Test suite part; the full suite spans `tests/*.rs`.

use super::*;

#[test]
fn s4143_flags_double_element_writes() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        data[0] = 1;\n        data[0] = 2;\n        data[1] = 3;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4143");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
    assert!(flagged[0].message.contains("overwritten"));
}

#[test]
fn s3994_and_s3995_prefer_uri_overloads() {
    let report = analyze_default(
        "class C\n{\n    public string Load(string path) { return path; }\n    public string Load(Uri path) { return \"\"; }\n    public Uri Find(int id) { return null!; }\n    public string Find(string path) { return \"\"; }\n}\n",
    );
    let parameters = with_key(&report, "csharpsquid:S3994");
    assert_eq!(parameters.len(), 1);
    assert_eq!(parameters[0].range.start.line, 3);
    let returns = with_key(&report, "csharpsquid:S3995");
    assert_eq!(returns.len(), 1);
    assert_eq!(returns[0].range.start.line, 6);
}

#[test]
fn s3996_flags_uri_named_string_properties() {
    let report = analyze_default(
        "class C\n{\n    public string HomeUri { get; set; }\n    public string Name { get; set; }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3996");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s4005_passes_uris_to_overloads() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        body = client.DownloadString(\"http://example.com\");\n        body = client.DownloadString(address);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4005");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s3257_suggests_var_for_repeated_types() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        List<int> xs = new List<int>();\n        int age = 5;\n        var zs = new List<int>();\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3257");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s3244_rejects_anonymous_unsubscriptions() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        handler -= () => { };\n        handler -= stored;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3244");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s3247_flags_duplicate_casts() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        var a = (Customer)item;\n        var b = (Customer)item;\n        var c = (Order)item;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3247");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 6);
}

#[test]
fn s1185_rejects_trivial_base_forwarding_overrides() {
    let report = analyze_default(
        "class D : B\n{\n    public override string Name() { return base.Name(); }\n    public override int Size() { var x = base.Size(); return x; }\n    public override void Run() { base.Run(); }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1185");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 5);
}

#[test]
fn s3237_requires_value_in_setters() {
    let report = analyze_default(
        "class E\n{\n    int cached;\n    int Cached\n    {\n        set { cached = value; }\n    }\n    int Other\n    {\n        set { cached = backup; }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3237");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 10);
}

#[test]
fn s4049_converts_accessor_shaped_methods() {
    let report = analyze_default(
        "class F\n{\n    public string GetName() { return name; }\n    public void SetName(string newValue) { this.name = newValue; }\n    public void Reset() { }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4049");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 4);
}

#[test]
fn s4040_flags_lowercase_normalization() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        key = name.ToLower();\n        other = name.ToLowerInvariant();\n        upper = name.ToUpper();\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4040");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 6);
}

#[test]
fn s4056_flags_culture_less_conversions() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        text = value.ToString();\n        number = int.Parse(raw);\n        number = double.Parse(raw, culture);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4056");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 6);
}

#[test]
fn s4058_requires_comparison_mode() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        same = string.Compare(first, second) == 0;\n        equal = first.Equals(second);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4058");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s1449_requires_culture_for_searches() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        at = text.IndexOf(\"needle\");\n        last = text.LastIndexOf(mark);\n        ordered = text.CompareTo(other);\n        found = text.IndexOf(\"needle\", StringComparison.Ordinal);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1449");
    assert_eq!(flagged.len(), 3);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[2].range.start.line, 7);
}

#[test]
fn s2115_flags_embedded_connection_passwords() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        var leaky = \"Server=s;Database=d;User=u;Password=secret;\";\n        var safe = \"Server=s;Database=d;Integrated Security=true;\";\n        var unset = \"Server=s;Password=;\";\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2115");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s3998_rejects_weak_identity_locks() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        lock (this) { }\n        lock (typeof(A)) { }\n        lock (\"key\") { }\n        lock (gate) { }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3998");
    assert_eq!(flagged.len(), 3);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[2].range.start.line, 7);
}

#[test]
fn s6507_and_s2445_check_lock_guards() {
    let report = analyze_default(
        "class A\n{\n    object gate;\n    readonly object frozen = new object();\n    void M()\n    {\n        lock (gate) { }\n        lock (frozen) { }\n        var local = new object();\n        lock (local) { }\n    }\n}\n",
    );
    let locals = with_key(&report, "csharpsquid:S6507");
    assert_eq!(locals.len(), 1);
    assert_eq!(locals[0].range.start.line, 10);
    let mutable_fields = with_key(&report, "csharpsquid:S2445");
    assert_eq!(mutable_fields.len(), 1);
    assert_eq!(mutable_fields[0].range.start.line, 7);
}

#[test]
fn s3363_flags_datetime_key_members() {
    let report = analyze_default(
        "class R\n{\n    public DateTime CreatedOn { get; set; }\n    public DateTime OrderKey { get; set; }\n    public DateTimeOffset Id { get; set; }\n    private DateTime stamp;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3363");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 4);
    assert_eq!(flagged[1].range.start.line, 5);
}

#[test]
fn s4052_rejects_outdated_base_types() {
    let report = analyze_default(
        "class Bag : ArrayList { }\nclass Map : DictionaryBase { }\nclass Modern : List<int> { }\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4052");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 1);
    assert_eq!(flagged[1].range.start.line, 2);
}

#[test]
fn s2699_requires_test_assertions() {
    let report = analyze_default(
        "class T\n{\n    [Test]\n    public void Verifies() { Assert.That(value, Is.EqualTo(1)); }\n    [Test]\n    public void Sleeps() { Thread.Sleep(10); }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2699");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s2701_flags_literal_assertions() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        Assert.IsTrue(true);\n        widget.IsFalse(false);\n        Assert.IsTrue(ready);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2701");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 6);
}

#[test]
fn s2970_completes_assert_that() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        Assert.That(actual);\n        Assert.That(actual, Is.EqualTo(1));\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2970");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s3415_puts_expected_first() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        Assert.AreEqual(result, 5);\n        Assert.AreEqual(5, result);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3415");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s2187_requires_tests_in_classes() {
    let report = analyze_default(
        "[TestClass]\nclass Empty\n{\n    public void Helper() { }\n}\n\n[TestClass]\nclass Real\n{\n    [TestMethod]\n    public void Works() { Assert.IsTrue(true); }\n}\n\nclass Plain { }\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2187");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);
}

#[test]
fn s4586_task_methods_do_not_return_null() {
    let report = analyze_default(
        "class A\n{\n    Task Work()\n    {\n        if (ready) { return null; }\n        return Task.CompletedTask;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4586");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let async_safe = analyze_default("class A\n{\n    async Task Go() { return null; }\n}\n");
    assert!(with_key(&async_safe, "csharpsquid:S4586").is_empty());
}

#[test]
fn s3881_and_s2953_check_dispose_contracts() {
    let complete = analyze_default(
        "class Good : IDisposable\n{\n    public void Dispose() { Dispose(true); }\n    protected virtual void Dispose(bool disposing) { }\n    ~Good() { Dispose(false); }\n}\n",
    );
    assert!(with_key(&complete, "csharpsquid:S3881").is_empty());
    assert!(with_key(&complete, "csharpsquid:S2953").is_empty());

    let minimal = analyze_default(
        "class Bad : IDisposable\n{\n    public void Dispose() { done = true; }\n}\n",
    );
    assert_eq!(with_key(&minimal, "csharpsquid:S3881").len(), 2);

    let unattributed = analyze_default("class Sloppy\n{\n    public void Dispose() { }\n}\n");
    let missing = with_key(&unattributed, "csharpsquid:S2953");
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].range.start.line, 1);
}

#[test]
fn s1118_hides_utility_constructors() {
    let report = analyze_default(
        "class Util\n{\n    public static void Run() { }\n    public Util() { }\n}\n\nclass Mixed\n{\n    public void Run() { }\n}\n\nclass Open\n{\n    public static void Run() { }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1118");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 4);
}

#[test]
fn s112_flags_reserved_exception_throws() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        throw new Exception(\"boom\");\n        throw new ApplicationException(\"x\");\n        throw new InvalidOperationException(\"specific\");\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S112");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 6);
}

#[test]
fn s1134_and_s1135_track_work_tags() {
    let report = analyze_default(
        "// FIXME: rewrite this loop\nclass A\n{\n    void M()\n    {\n        // TODO: extract helper\n        DoIt(); // TODO inline\n    }\n}\n",
    );
    let fixmes = with_key(&report, "csharpsquid:S1134");
    assert_eq!(fixmes.len(), 1);
    assert_eq!(fixmes[0].range.start.line, 1);
    let todos = with_key(&report, "csharpsquid:S1135");
    assert_eq!(todos.len(), 2);
    assert_eq!(todos[0].range.start.line, 6);
}

#[test]
fn s1163_bans_throws_in_finally() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        try { Work(); } finally { throw new IOException(\"late\"); }\n        throw new IOException(\"early\");\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1163");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s1696_and_s2221_require_specific_catches() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        try { } catch (NullReferenceException broken) { Recover(); }\n        try { } catch (System.Exception general) { Recover(); }\n        try { } catch (IOException io) { Recover(); }\n    }\n}\n",
    );
    let null_catches = with_key(&report, "csharpsquid:S1696");
    assert_eq!(null_catches.len(), 1);
    assert_eq!(null_catches[0].range.start.line, 5);
    let general_catches = with_key(&report, "csharpsquid:S2221");
    assert_eq!(general_catches.len(), 1);
    assert_eq!(general_catches[0].range.start.line, 6);
}

#[test]
fn s2139_single_reports_failures() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        try { Run(); } catch (System.Exception ex) { logger.LogError(\"Boom {Code}\", ex); throw; }\n        try { Run(); } catch (System.Exception ex) { logger.LogError(\"Logged {Code}\", ex); }\n        try { Run(); } catch (System.Exception ex) { throw; }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2139");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s2291_keeps_overflow_checks_on_sum() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        unchecked { total = values.Sum(); }\n        checked { total = values.Sum(); }\n        unchecked { total = values.Count; }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2291");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s2302_prefers_nameof_for_parameter_strings() {
    let report = analyze_default(
        "class A\n{\n    void Save(string userName)\n    {\n        audit = \"userName\";\n        audit = \"user\";\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2302");
    assert_eq!(flagged.len(), 1);
    assert_eq!(
        flagged[0].message,
        "Replace this string with 'nameof(userName)'."
    );
}

#[test]
fn s2327_merges_identical_try_handlers() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        try { One(); } catch (IOException e) { Heal(); } finally { Clean(); }\n        try { Two(); } catch (IOException e) { Heal(); } finally { Clean(); }\n        try { Three(); } catch (ArgumentException e) { Heal(); }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2327");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 6);
}

#[test]
fn s2333_removes_redundant_modifiers() {
    let report = analyze_default(
        "class Holder\n{\n    public string Name { public get; set; }\n}\n\npartial class Solo { }\npartial class Duo { }\npartial class Duo { }\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2333");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 6);
}

#[test]
fn s3433_checks_test_method_shapes() {
    let report = analyze_default(
        "class T\n{\n    [Fact]\n    public void Works() { Assert.True(ok); }\n    [Fact]\n    internal void Hidden() { }\n    [Theory]\n    public int Returns() => 1;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3433");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 7);
}

#[test]
fn s2486_and_s2737_require_catch_work() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        try { } catch (System.Exception) { Recover(); }\n        try { } catch (System.Exception) { }\n        try { } catch (System.Exception ex) { throw; }\n        try { } catch (IOException io) { }\n    }\n}\n",
    );
    let ignored = with_key(&report, "csharpsquid:S2486");
    assert_eq!(ignored.len(), 1);
    assert_eq!(ignored[0].range.start.line, 6);
    let rethrow_only = with_key(&report, "csharpsquid:S2737");
    assert_eq!(rethrow_only.len(), 1);
    assert_eq!(rethrow_only[0].range.start.line, 7);
}

#[test]
fn s2757_flags_transposed_operators() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        total =+ amount;\n        sum = a + b;\n        // note: x =+ y in prose\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2757");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s3217_typed_iteration_instead_of_casts() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        foreach (string raw in values)\n            Log(((string)raw).Length);\n        foreach (var other in items)\n            Log(other);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3217");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 6);
}

#[test]
fn s3346_keeps_debug_assert_pure() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        Debug.Assert(Fetch() == 2);\n        Debug.Assert(count == 2);\n        Debug.Assert(total == running++);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3346");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 7);
}

#[test]
fn s3427_disambiguates_optional_overloads() {
    let report = analyze_default(
        "class A\n{\n    public void Fill(int a, int b = 2) { }\n    public void Fill(int a) { }\n    public void Load(int a) { }\n    public void Load(int a, int b, int c = 3) { }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3427");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 4);
}

#[test]
fn s3445_uses_bare_rethrow() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        try { Run(); } catch (IOException ex) { throw ex; }\n        try { Run(); } catch (IOException ex) { throw; }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3445");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s3876_indexes_by_string_or_integer() {
    let report = analyze_default(
        "class Grid\n{\n    public string this[int x, int y] => \"\";\n    public int this[string key] => 0;\n    public double this[double ratio] => 1.0;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3876");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s3878_passes_elements_to_params_calls() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        Use(new[] { 1, 2 });\n        Use(existing);\n        Use(new int[] { 3 });\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3878");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 7);
}

#[test]
fn s3887_consts_readonly_primitive_fields() {
    let report = analyze_default(
        "class A\n{\n    public readonly int limit = 10;\n    private readonly int hidden = 1;\n    public readonly string label = \"x\";\n    public static readonly int cached = 2;\n    public readonly Builder built = new Builder();\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3887");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s3904_requires_assembly_version() {
    let unversioned = analyze_default("[assembly: System.CLSCompliant(false)]\nclass A { }\n");
    let flagged = with_key(&unversioned, "csharpsquid:S3904");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);

    let versioned = analyze_default("[assembly: AssemblyVersion(\"1.0.0.0\")]\nclass A { }\n");
    assert!(with_key(&versioned, "csharpsquid:S3904").is_empty());

    let plain = analyze_default("class A { }\n");
    assert!(with_key(&plain, "csharpsquid:S3904").is_empty());
}

#[test]
fn s3956_hides_list_in_public_signatures() {
    let report = analyze_default(
        "class A\n{\n    public List<int> Get() => xs;\n    public void Add(List<int> xs) { }\n    private List<int> secret;\n    public List<int> exposed;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3956");
    assert_eq!(flagged.len(), 3);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 4);
    assert_eq!(flagged[2].range.start.line, 6);
}

#[test]
fn s4004_makes_collection_properties_readonly() {
    let report = analyze_default(
        "class A\n{\n    public List<int> Items { get; set; }\n    public List<int> Rows { get; }\n    public Dictionary<string, int> Map { get; set; }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4004");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 5);
}

#[test]
fn s4545_references_existing_members_in_debugger_display() {
    let report = analyze_default(
        "[DebuggerDisplay(\"{Name}: {Missing}\")]\nclass Card\n{\n    public string Name { get; set; }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4545");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("'Missing'"));

    let known = analyze_default(
        "[DebuggerDisplay(\"{Name}\")]\nclass Card\n{\n    public string Name { get; set; }\n}\n",
    );
    assert!(with_key(&known, "csharpsquid:S4545").is_empty());
}

#[test]
fn s4487_flags_unreferenced_private_members() {
    let report = analyze_default(
        "class A\n{\n    private int Stale;\n    private void Dead() { }\n    public int Live;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4487");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 4);

    let clean = analyze_default(
        "class B\n{\n    private int used;\n    public int Read() { return used; }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4487").is_empty());
}

#[test]
fn s4487_skips_attributed_and_partial_members() {
    let attributed =
        analyze_default("class D\n{\n    [System.Obsolete]\n    private void Legacy() { }\n}\n");
    assert!(with_key(&attributed, "csharpsquid:S4487").is_empty());

    let partial = analyze_default("partial class E\n{\n    private int Maybe;\n}\n");
    assert!(with_key(&partial, "csharpsquid:S4487").is_empty());
}

#[test]
fn s1450_flags_fields_used_by_a_single_method() {
    let report = analyze_default(
        "class A\n{\n    private int counter;\n    public void Bump()\n    {\n        counter = counter + 1;\n        counter++;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1450");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let clean = analyze_default(
        "class B\n{\n    private int value;\n    public void Set(int v) { value = v; }\n    public int Get() { return value; }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S1450").is_empty());
}

#[test]
fn s3459_flags_read_but_never_assigned_fields() {
    let report = analyze_default(
        "class A\n{\n    private int orphan;\n    public int Peek() { return orphan; }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3459");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let clean = analyze_default(
        "class B\n{\n    private int seeded;\n    public B() { seeded = 1; }\n    public void Reset() { seeded = 0; }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3459").is_empty());
}

#[test]
fn s2933_flags_constructor_only_field_writes() {
    let report = analyze_default(
        "class A\n{\n    private int fixedValue;\n    private int inline = 7;\n    public A() { fixedValue = 42; }\n    public int Total() { return fixedValue + inline; }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2933");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 4);

    let rewritten = analyze_default(
        "class B\n{\n    private int mutableField;\n    public B() { mutableField = 1; }\n    public void Bump() { mutableField++; }\n}\n",
    );
    assert!(with_key(&rewritten, "csharpsquid:S2933").is_empty());

    let mismatched = analyze_default(
        "class C\n{\n    private static int shared;\n    public C() { shared = 1; }\n}\n",
    );
    assert!(with_key(&mismatched, "csharpsquid:S2933").is_empty());
}

#[test]
fn s2325_flags_instance_independent_private_members() {
    let report = analyze_default(
        "class A\n{\n    private int Double(int input) { return input * 2; }\n    public int Call() { return Double(21); }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2325");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let property_report = analyze_default(
        "class C\n{\n    private string Greeting => \"hi\";\n    public string Say() { return Greeting; }\n}\n",
    );
    let properties = with_key(&property_report, "csharpsquid:S2325");
    assert_eq!(properties.len(), 1);
    assert_eq!(properties[0].range.start.line, 3);

    let clean = analyze_default(
        "class B\n{\n    private int state;\n    private int Step() { return state + 1; }\n    public int Run() { state = 1; return Step(); }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2325").is_empty());
}

#[test]
fn s2696_flags_instance_writes_to_static_fields() {
    let report = analyze_default(
        "class A\n{\n    private static int hits;\n    public void Record() { hits = hits + 1; }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2696");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 4);

    let clean = analyze_default(
        "class B\n{\n    private static int total;\n    public static void Add(int amount) { total += amount; }\n    public static int Current() => total;\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2696").is_empty());
}

#[test]
fn s3218_flags_inner_statics_shadowing_outer() {
    let report = analyze_default(
        "class Outer\n{\n    private const string Tag = \"o\";\n    class Inner\n    {\n        private const string Tag = \"i\";\n        public string Get() { return Tag; }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3218");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 6);

    let clean = analyze_default(
        "class Outer\n{\n    private const string Tag = \"o\";\n    class Inner\n    {\n        private const string Mark = \"i\";\n        public string Get() { return Mark; }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3218").is_empty());
}

#[test]
fn s3398_flags_private_methods_called_only_from_nested_types() {
    let report = analyze_default(
        "class A\n{\n    private int Secret() { return 1; }\n    class Nested\n    {\n        public int Use(A owner) { return owner.Secret(); }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3398");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let clean = analyze_default(
        "class B\n{\n    private int Local() { return 2; }\n    public int Call() { return Local(); }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3398").is_empty());

    let sibling = analyze_default(
        "class C\n{\n    private int Hidden() { return 3; }\n}\nclass D\n{\n    public int Tap(C c) { return c.Hidden(); }\n}\n",
    );
    assert!(with_key(&sibling, "csharpsquid:S3398").is_empty());
}

#[test]
fn s1168_flags_null_returns_from_collections() {
    let report = analyze_default(
        "class A\n{\n    public List<int> Load()\n    {\n        return null;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1168");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let arrow_report = analyze_default("class C\n{\n    public int[] Make() => null;\n}\n");
    let arrows = with_key(&arrow_report, "csharpsquid:S1168");
    assert_eq!(arrows.len(), 1);
    assert_eq!(arrows[0].range.start.line, 3);

    let clean = analyze_default(
        "class B\n{\n    public List<int> Load()\n    {\n        return new List<int>();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S1168").is_empty());
}

#[test]
fn s1226_flags_values_overwritten_before_reading() {
    let report = analyze_default(
        "class A\n{\n    public void Run(int start)\n    {\n        start = 0;\n        System.Console.WriteLine(start);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1226");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let catch_report = analyze_default(
        "class C\n{\n    public void Try()\n    {\n        try\n        {\n            Probe();\n        }\n        catch (System.Exception error)\n        {\n            error = null;\n        }\n    }\n}\n",
    );
    let caught = with_key(&catch_report, "csharpsquid:S1226");
    assert_eq!(caught.len(), 1);
    assert_eq!(caught[0].range.start.line, 11);

    let clean = analyze_default(
        "class B\n{\n    public void Run(int start)\n    {\n        if (start > 0)\n        {\n            start = 0;\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S1226").is_empty());
}

#[test]
fn s1699_flags_constructors_calling_overridable_members() {
    let report = analyze_default(
        "class A\n{\n    public A()\n    {\n        Initialize();\n    }\n\n    protected virtual void Initialize() { }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1699");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let clean = analyze_default(
        "class B\n{\n    public B()\n    {\n        Setup();\n    }\n\n    private void Setup() { }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S1699").is_empty());
}

#[test]
fn s2955_flags_unconstrained_generic_null_comparisons() {
    let report = analyze_default(
        "class A\n{\n    public T Pick<T>(T candidate)\n    {\n        if (candidate == null)\n        {\n            return candidate;\n        }\n        return candidate;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2955");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let clean = analyze_default(
        "class B\n{\n    public T Pick<T>(T candidate) where T : class\n    {\n        if (candidate != null)\n        {\n            return candidate;\n        }\n        return null;\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2955").is_empty());
}

#[test]
fn s2997_flags_returning_disposable_from_using() {
    let report = analyze_default(
        "class A\n{\n    public System.IO.Stream Open()\n    {\n        using (var stream = new System.IO.MemoryStream())\n        {\n            return stream;\n        }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2997");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);

    let clean = analyze_default(
        "class B\n{\n    public System.IO.Stream Open()\n    {\n        System.IO.Stream kept;\n        using (var stream = new System.IO.MemoryStream())\n        {\n            kept = stream;\n        }\n        return kept;\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2997").is_empty());
}

#[test]
fn s3063_flags_unconsumed_string_builders() {
    let report = analyze_default(
        "class A\n{\n    public void Build()\n    {\n        var text = new System.Text.StringBuilder();\n        text.Append(\"a\");\n        text.AppendLine(\"b\");\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3063");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let clean = analyze_default(
        "class B\n{\n    public string Build()\n    {\n        var text = new System.Text.StringBuilder();\n        text.Append(\"a\");\n        return text.ToString();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3063").is_empty());
}

#[test]
fn s3172_flags_delegate_subtraction() {
    let report = analyze_default(
        "delegate int Compute(int value);\nclass A\n{\n    private Compute first;\n    private Compute second;\n\n    public int Evaluate(int input)\n    {\n        var combined = first - second;\n        return combined(input);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3172");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 9);

    let clean = analyze_default(
        "delegate int Compute(int value);\nclass A\n{\n    private Compute first;\n    private Compute second;\n\n    public int Evaluate(int input)\n    {\n        var combined = first + second;\n        return combined(input);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3172").is_empty());
}

#[test]
fn s3241_flags_fully_discarded_private_results() {
    let report = analyze_default(
        "class A\n{\n    private int Compute() => 42;\n    public void Run()\n    {\n        Compute();\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3241");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let clean = analyze_default(
        "class B\n{\n    private int Compute() => 42;\n    public int Run() => Compute();\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3241").is_empty());
}

#[test]
fn s3236_flags_explicit_caller_information_arguments() {
    let report = analyze_default(
        "class A\n{\n    private void Trace(string message, [System.Runtime.CompilerServices.CallerMemberName] string member = \"\")\n    {\n        Record(member);\n    }\n\n    private void Record(string member) { }\n}\n\nclass B\n{\n    void Go()\n    {\n        Trace(\"hi\", \"Go\");\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3236");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 15);

    let clean = analyze_default(
        "class A\n{\n    private void Trace(string message, [System.Runtime.CompilerServices.CallerMemberName] string member = \"\")\n    {\n        Record(member);\n    }\n\n    private void Record(string member) { }\n}\n\nclass B\n{\n    void Go()\n    {\n        Trace(\"hi\");\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3236").is_empty());
}

#[test]
fn s3366_flags_this_escaping_constructors() {
    let report = analyze_default(
        "class A\n{\n    public A()\n    {\n        System.Console.WriteLine(this);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3366");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let clean = analyze_default(
        "class B\n{\n    private int state;\n    public B()\n    {\n        state = this.state;\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3366").is_empty());
}

#[test]
fn s3263_flags_static_initialization_order_dependencies() {
    let report = analyze_default(
        "class A\n{\n    private static int first = second + 1;\n    private static int second = 5;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3263");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let clean = analyze_default(
        "class B\n{\n    private static int second = 5;\n    private static int first = second + 1;\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3263").is_empty());
}

#[test]
fn s3265_flags_bitwise_operations_on_non_flags_enums() {
    let report = analyze_default(
        "enum Color\n{\n    Red,\n    Green\n}\nclass A\n{\n    public int Combine(Color left, Color right)\n    {\n        return left | right;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3265");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 10);

    let clean = analyze_default(
        "[Flags]\nenum Mode\n{\n    Read,\n    Write\n}\nclass B\n{\n    public int Combine(Mode left, Mode right)\n    {\n        return left | right;\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3265").is_empty());
}

#[test]
fn s3443_flags_gettype_on_type_instances() {
    let report = analyze_default(
        "class A\n{\n    public void Inspect(object value)\n    {\n        var kind = value.GetType().GetType();\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3443");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let clean = analyze_default(
        "class B\n{\n    public void Inspect(object value)\n    {\n        var kind = value.GetType();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3443").is_empty());
}

#[test]
fn s3900_flags_unvalidated_nullable_public_parameters() {
    let report = analyze_default(
        "class A\n{\n    public int Measure(string? input)\n    {\n        return input.Length;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3900");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let clean = analyze_default(
        "class B\n{\n    public int Measure(string? input)\n    {\n        if (input == null)\n        {\n            return 0;\n        }\n        return input.Length;\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3900").is_empty());
}

#[test]
fn s3997_flags_string_overloads_not_delegating_to_uri() {
    let report = analyze_default(
        "class A\n{\n    public System.Uri Parse(System.Uri value)\n    {\n        return value;\n    }\n\n    public System.Uri Parse(string text)\n    {\n        return System.Text.RegularExpressions.Regex.Unescape(text);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3997");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 8);

    let clean = analyze_default(
        "class A\n{\n    public System.Uri Parse(System.Uri value)\n    {\n        return value;\n    }\n\n    public System.Uri Parse(string text)\n    {\n        return new System.Uri(text);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3997").is_empty());
}

#[test]
fn s4002_flags_finalizers_on_disposable_types() {
    let report = analyze_default(
        "class A : System.IDisposable\n{\n    public void Dispose() { }\n\n    ~A()\n    {\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4002");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let clean =
        analyze_default("class B : System.IDisposable\n{\n    public void Dispose() { }\n}\n");
    assert!(with_key(&clean, "csharpsquid:S4002").is_empty());
}

#[test]
fn s4275_flags_accessors_touching_different_fields() {
    let report = analyze_default(
        "class A\n{\n    private string first;\n    private string second;\n\n    public string Value\n    {\n        get { return first; }\n        set { second = value; }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S4275");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 6);

    let clean = analyze_default(
        "class B\n{\n    private string first;\n\n    public string Value\n    {\n        get { return first; }\n        set { first = value; }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4275").is_empty());
}

#[test]
fn s127_flags_for_bodies_writing_condition_names() {
    let violating = analyze_default(
        "class C {\n    void M(int size) {\n        int sum = 0;\n        for (int i = 0; i < size; i++) {\n            sum += i;\n            size = 3;\n        }\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S127");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 4);

    let clean = analyze_default(
        "class C {\n    void M(int size) {\n        int sum = 0;\n        for (int i = 0; i < size; i++) {\n            sum += i;\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S127").is_empty());
}

#[test]
fn s1751_flags_loops_ending_in_an_unconditional_exit() {
    let violating = analyze_default(
        "class C {\n    void M(bool ready) {\n        while (ready) {\n            Pump();\n            break;\n        }\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S1751").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M(bool ready) {\n        while (ready) {\n            Pump();\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S1751").is_empty());
}

#[test]
fn s1854_flags_stores_masked_before_any_read() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        int total = 1;\n        total = 2;\n        Log(total);\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S1854");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let clean = analyze_default(
        "class C {\n    void M() {\n        int total = Compute();\n        Log(total);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S1854").is_empty());
}

#[test]
fn s2123_flags_increments_overwritten_before_any_read() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        int count = 1;\n        count++;\n        count = 5;\n        Use(count);\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S2123");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 4);

    let clean = analyze_default(
        "class C {\n    void M() {\n        int count = 1;\n        count++;\n        Use(count);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2123").is_empty());
}

#[test]
fn s2077_flags_dynamically_composed_sql_text() {
    let violating = analyze_default(
        "class C {\n    void M(string name) {\n        var query = \"SELECT * FROM U WHERE N = '\" + name + \"'\";\n        var command = new SqlCommand(query, connection);\n        command.ExecuteReader();\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S2077");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 4);

    let clean = analyze_default(
        "class C {\n    void M() {\n        var query = \"SELECT 1\";\n        var command = new SqlCommand(query, connection);\n        command.ExecuteReader();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2077").is_empty());
}

#[test]
fn s2190_flags_escape_free_true_loops_and_bare_tail_recursion() {
    let violating = analyze_default(
        "class C {\n    void Spin() {\n        while (true) {\n            Turn();\n        }\n    }\n    void Fall() {\n        Fall();\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S2190").len(), 2);

    let clean = analyze_default(
        "class C {\n    void Spin(bool done) {\n        while (true) {\n            if (done) {\n                break;\n            }\n            Turn();\n        }\n    }\n    int Fact(int n) {\n        if (n <= 1) {\n            return 1;\n        }\n        return Fact(n - 1);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2190").is_empty());
}

#[test]
fn s2222_flags_monitor_exits_outside_finally_blocks() {
    let violating = analyze_default(
        "class C {\n    void M(object gate) {\n        Monitor.Enter(gate);\n        try {\n            Work();\n            Monitor.Exit(gate);\n        } catch (System.IO.IOException) {\n        }\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S2222");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let clean = analyze_default(
        "class C {\n    void M(object gate) {\n        Monitor.Enter(gate);\n        try {\n            Work();\n        } finally {\n            Monitor.Exit(gate);\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2222").is_empty());
}

#[test]
fn s2251_flags_counters_moving_against_their_bound() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        for (int i = 10; i > 0; i++) {\n            Tick();\n        }\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S2251").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M() {\n        for (int i = 0; i < 10; i++) {\n            Tick();\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2251").is_empty());
}

#[test]
fn s2252_flags_conditions_false_at_entry() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        for (int i = 10; i < 5; i++) {\n            Tick();\n        }\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S2252").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M() {\n        for (int i = 0; i < 5; i++) {\n            Tick();\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2252").is_empty());
}

#[test]
fn s2259_flags_dereferences_of_known_null_locals() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        string s = null;\n        Log(s.Length);\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S2259");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 4);

    let guarded = analyze_default(
        "class C {\n    void M() {\n        string t = null;\n        if (t != null) {\n            Log(t.Length);\n        }\n    }\n}\n",
    );
    assert!(with_key(&guarded, "csharpsquid:S2259").is_empty());
}

#[test]
fn s2583_flags_literal_false_conditions() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        if (false) {\n            Dead();\n        }\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S2583").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M(bool ready) {\n        if (ready) {\n            Run();\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2583").is_empty());
}

#[test]
fn s2589_flags_boolean_literals_next_to_short_circuit_operators() {
    let violating = analyze_default(
        "class C {\n    void M(bool ready) {\n        if (ready && true) {\n            Go();\n        }\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S2589").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M(bool ready, bool set) {\n        if (ready && set) {\n            Go();\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2589").is_empty());
}

#[test]
fn s2674_flags_discarded_stream_read_results() {
    let violating = analyze_default(
        "class C {\n    void M(System.IO.Stream stream) {\n        var buffer = new byte[16];\n        stream.Read(buffer, 0, 16);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S2674").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M(System.IO.Stream stream) {\n        var buffer = new byte[16];\n        var count = stream.Read(buffer, 0, 16);\n        Log(count);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2674").is_empty());
}

#[test]
fn s3353_flags_literal_locals_that_never_change() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        int retries = 3;\n        Attempt(retries);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S3353").len(), 1);

    let rewritten = analyze_default(
        "class C {\n    void M(int next) {\n        int retries = 3;\n        retries = next;\n        Attempt(retries);\n    }\n}\n",
    );
    assert!(with_key(&rewritten, "csharpsquid:S3353").is_empty());
}

#[test]
fn s3440_flags_comparisons_with_the_value_just_assigned() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        int limit = Read();\n        limit = 10;\n        if (limit == 10) {\n            Mark();\n        }\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S3440").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M() {\n        int limit = 10;\n        if (limit == 9) {\n            Mark();\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3440").is_empty());
}

#[test]
fn s3655_flags_value_access_without_hasvalue_guards() {
    let violating = analyze_default(
        "class C {\n    void M(int? maybe) {\n        var width = maybe.Value;\n        Draw(width);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S3655").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M(int? maybe) {\n        if (maybe.HasValue) {\n            var width = maybe.Value;\n            Draw(width);\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3655").is_empty());
}

#[test]
fn s3949_flags_constant_arithmetic_wrapping_int() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        var overflow = int.MaxValue + 1;\n        Log(overflow);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S3949").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M() {\n        var nearTop = int.MaxValue - 1;\n        Log(nearTop);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3949").is_empty());
}

#[test]
fn s3966_flags_objects_disposed_twice() {
    let violating = analyze_default(
        "class C {\n    void M(System.IO.Stream stream) {\n        stream.Dispose();\n        stream.Dispose();\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S3966");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 4);

    let clean = analyze_default(
        "class C {\n    void M(System.IO.Stream stream) {\n        stream.Dispose();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3966").is_empty());
}

#[test]
fn s4158_flags_access_into_provably_empty_creations() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        var first = new int[0][0];\n        Log(first);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S4158").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M() {\n        var empty = new int[0];\n        Log(empty.Length);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4158").is_empty());
}

#[test]
fn s2092_and_s3330_flag_cookies_missing_security_flags() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        var cookie = new HttpCookie(\"session\");\n        Response.Cookies.Add(cookie);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S2092").len(), 1);
    assert_eq!(with_key(&violating, "csharpsquid:S3330").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M() {\n        var cookie = new HttpCookie(\"session\");\n        cookie.Secure = true;\n        cookie.HttpOnly = true;\n        Response.Cookies.Add(cookie);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2092").is_empty());
    assert!(with_key(&clean, "csharpsquid:S3330").is_empty());
}

#[test]
fn s2178_flags_bitwise_combinations_of_boolean_operands() {
    let violating = analyze_default(
        "class C {\n    void M(bool IsReady, bool HasData) {\n        if (IsReady & HasData) {\n            Run();\n        }\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S2178").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M(int count, bool isReady) {\n        if (count > 0 && isReady) {\n            Run();\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2178").is_empty());
}

#[test]
fn s2612_flags_world_writable_unix_file_modes() {
    let violating = analyze_default(
        "class C {\n    void M(string path) {\n        File.SetUnixFileMode(path, UnixFileMode.OthersWrite);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S2612").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M(string path) {\n        File.SetUnixFileMode(path, UnixFileMode.UserRead);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2612").is_empty());
}

#[test]
fn s2755_flags_dtd_enabled_xml_parsers() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        var settings = new XmlReaderSettings();\n        settings.DtdProcessing = DtdProcessing.Parse;\n        settings.ProhibitDtd = false;\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S2755").len(), 2);

    let clean = analyze_default(
        "class C {\n    void M() {\n        var settings = new XmlReaderSettings();\n        settings.DtdProcessing = DtdProcessing.Ignore;\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2755").is_empty());
}

#[test]
fn s3011_flags_nonpublic_reflection_lookups() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        var field = typeof(A).GetField(\"secret\", BindingFlags.NonPublic | BindingFlags.Instance);\n        Log(field);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S3011").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M() {\n        var field = typeof(A).GetField(\"shown\", BindingFlags.Public | BindingFlags.Instance);\n        Log(field);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3011").is_empty());
}

#[test]
fn s3925_flags_incomplete_iserializable_implementations() {
    let violating = analyze_default("class Bad : ISerializable {\n}\n");
    assert_eq!(with_key(&violating, "csharpsquid:S3925").len(), 1);

    let clean = analyze_default(
        "class Good : ISerializable {\n    protected Good(SerializationInfo info, StreamingContext context) {\n    }\n    public void GetObjectData(SerializationInfo info, StreamingContext context) {\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3925").is_empty());
}

#[test]
fn s4036_flags_path_resolved_process_starts() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        Process.Start(\"notepad\");\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S4036").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M() {\n        Process.Start(\"C:\\\\tools\\\\notepad.exe\");\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4036").is_empty());
}

#[test]
fn s4159_flags_exported_contracts_without_implementation() {
    let violating = analyze_default("[Export(typeof(IRepo))]\nclass Bad {\n}\n");
    assert_eq!(with_key(&violating, "csharpsquid:S4159").len(), 1);

    let clean = analyze_default("[Export(typeof(IRepo))]\nclass Good : IRepo {\n}\n");
    assert!(with_key(&clean, "csharpsquid:S4159").is_empty());
}

#[test]
fn s4277_flags_shared_mef_parts_created_with_new() {
    let violating = analyze_default(
        "[Shared]\nclass Part {\n}\nclass User {\n    void M() {\n        var p = new Part();\n        Use(p);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S4277").len(), 1);

    let clean = analyze_default(
        "class Plain {\n}\nclass User {\n    void M() {\n        var p = new Plain();\n        Use(p);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4277").is_empty());
}

#[test]
fn s4433_flags_anonymous_ldap_binds() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        var entry = new DirectoryEntry(\"LDAP://srv\");\n        Use(entry);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S4433").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M() {\n        var entry = new DirectoryEntry(\"LDAP://srv\", \"user\", \"pass\");\n        Use(entry);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4433").is_empty());
}

#[test]
fn s4456_flags_validation_inside_iterators() {
    let violating = analyze_default(
        "class C {\n    System.Collections.Generic.IEnumerable<int> Nums(int[] data) {\n        ArgumentNullException.ThrowIfNull(data);\n        foreach (var x in data) {\n            yield return x;\n        }\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S4456").len(), 1);

    let clean = analyze_default(
        "class C {\n    System.Collections.Generic.IEnumerable<int> Nums(int[] data) {\n        foreach (var x in data) {\n            yield return x;\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4456").is_empty());
}

#[test]
fn s4457_flags_validation_after_the_first_await() {
    let violating = analyze_default(
        "class C {\n    async System.Threading.Tasks.Task WorkAsync(string name) {\n        await SendAsync();\n        ArgumentNullException.ThrowIfNull(name);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S4457").len(), 1);

    let clean = analyze_default(
        "class C {\n    async System.Threading.Tasks.Task WorkAsync(string name) {\n        ArgumentNullException.ThrowIfNull(name);\n        await SendAsync();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4457").is_empty());
}

#[test]
fn s6563_flags_local_now_recorded_into_instant_named_targets() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        var modified = DateTime.Now;\n        Log(modified);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S6563").len(), 1);

    let clean = analyze_default(
        "class C {\n    void M() {\n        var modified = DateTime.UtcNow;\n        Log(modified);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6563").is_empty());
}

#[test]
fn s6566_flags_datetime_stores_into_datetimeoffset_targets() {
    let violating = analyze_default(
        "class C {\n    DateTimeOffset created;\n    void M() {\n        created = DateTime.Now;\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S6566").len(), 1);

    let clean = analyze_default(
        "class C {\n    DateTimeOffset created;\n    void M() {\n        created = DateTimeOffset.Now;\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6566").is_empty());
}

#[test]
fn s4055_flags_literals_in_localizable_ui_members() {
    let violating = analyze_default(
        "class Form1 : Form {\n    void M() {\n        lbl.Text = \"hello\";\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S4055").len(), 1);
    let clean = analyze_default(
        "class Form1 : Form {\n    void M() {\n        lbl.Text = LoadResource();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4055").is_empty());
}

#[test]
fn s4057_flags_culture_less_convert_calls() {
    let violating = analyze_default(
        "class C {\n    void M(string text) {\n        var n = Convert.ToInt32(text);\n        Log(n);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S4057").len(), 1);
    let clean = analyze_default(
        "class C {\n    void M(string text) {\n        var n = Convert.ToInt32(text, CultureInfo.InvariantCulture);\n        Log(n);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4057").is_empty());
}

#[test]
fn s4226_flags_extensions_next_to_extended_types() {
    let violating = analyze_default(
        "class Repo {\n}\nstatic class Extensions {\n    public static int Count2(this Repo repo) => 1;\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S4226").len(), 1);
    let clean = analyze_default(
        "static class Extensions {\n    public static int Count2(this string s) => 1;\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4226").is_empty());
}

#[test]
fn s4583_flags_begin_invoke_without_end_invoke() {
    let violating = analyze_default(
        "class C {\n    void M(Handler d) {\n        d.BeginInvoke(Callback(), null);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S4583").len(), 1);
    let clean = analyze_default(
        "class C {\n    void M(Handler d) {\n        d.BeginInvoke(Callback(), null);\n        d.EndInvoke(null);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4583").is_empty());
}

#[test]
fn s4830_flags_certificate_callbacks_accepting_everything() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S4830").len(), 1);
    let clean = analyze_default(
        "class C {\n    void M() {\n        ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => errors == null;\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4830").is_empty());
}

#[test]
fn s5034_flags_value_tasks_consumed_twice() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        System.Threading.Tasks.ValueTask<int> pending = FetchAsync();\n        var a = await pending;\n        var b = await pending;\n        Log(a, b);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S5034").len(), 1);
    let clean = analyze_default(
        "class C {\n    void M() {\n        System.Threading.Tasks.ValueTask<int> pending = FetchAsync();\n        var a = await pending;\n        Log(a);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S5034").is_empty());
}

#[test]
fn s6377_flags_discarded_signature_checks() {
    let violating = analyze_default(
        "class C {\n    void M(SignedXml doc) {\n        doc.CheckSignature(\"cert\");\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S6377").len(), 1);
    let clean = analyze_default(
        "class C {\n    void M(SignedXml doc) {\n        var ok = doc.CheckSignature(\"cert\");\n        Log(ok);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6377").is_empty());
}

#[test]
fn s6668_flags_exceptions_passed_after_the_template() {
    let violating = analyze_default(
        "class C {\n    void M(ILogger logger, string name) {\n        try {\n            Work(name);\n        } catch (System.Exception ex) {\n            logger.LogError(\"Failed for {Name}\", name, ex);\n        }\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S6668").len(), 1);
    let clean = analyze_default(
        "class C {\n    void M(ILogger logger, string name) {\n        try {\n            Work(name);\n        } catch (System.Exception ex) {\n            logger.LogError(ex, \"Failed for {Name}\", name);\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6668").is_empty());
}

#[test]
fn s6781_flags_hardcoded_jwt_signing_keys() {
    let violating = analyze_default(
        "class C {\n    void M() {\n        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(\"hardcoded-secret\"));\n        Use(key);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S6781").len(), 1);
    let clean = analyze_default(
        "class C {\n    void M(byte[] configKey) {\n        var key = new SymmetricSecurityKey(configKey);\n        Use(key);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6781").is_empty());
}

#[test]
fn s6803_flags_query_binding_without_routes() {
    let violating = analyze_default(
        "class FilterView {\n    [SupplyParameterFromQuery]\n    public string Query { get; set; }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S6803").len(), 1);
    let clean = analyze_default(
        "[Route(\"/filter\")]\nclass FilterViewRouted {\n    [SupplyParameterFromQuery]\n    public string Query { get; set; }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6803").is_empty());
}

#[test]
fn s6964_flags_value_type_controller_inputs() {
    let violating = analyze_default(
        "[ApiController]\nclass SaveController {\n    [HttpPost]\n    public void Save(int count) {\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S6964").len(), 1);
    let clean = analyze_default(
        "[ApiController]\nclass SaveControllerNullable {\n    [HttpPost]\n    public void Save(int? count) {\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6964").is_empty());
}

#[test]
fn s6966_flags_discarded_async_calls() {
    let violating = analyze_default("class C {\n    void M() {\n        SendAsync();\n    }\n}\n");
    assert_eq!(with_key(&violating, "csharpsquid:S6966").len(), 1);
    let clean =
        analyze_default("class C {\n    async void M() {\n        await SendAsync();\n    }\n}\n");
    assert!(with_key(&clean, "csharpsquid:S6966").is_empty());
}

#[test]
fn s7131_flags_reader_writer_locks_without_matching_release() {
    let violating = analyze_default(
        "class C {\n    void M(Lock gate) {\n        gate.AcquireWriterLock(0);\n        Work();\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S7131").len(), 1);
    let clean = analyze_default(
        "class C {\n    void M(Lock gate) {\n        gate.AcquireWriterLock(0);\n        Work();\n        gate.ReleaseWriterLock();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S7131").is_empty());
}

#[test]
fn s7133_flags_monitors_never_released_in_the_member() {
    let violating = analyze_default(
        "class C {\n    void A(object gate) {\n        Monitor.Enter(gate);\n        Work();\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S7133").len(), 1);
    let clean = analyze_default(
        "class C {\n    void A(object gate) {\n        Monitor.Enter(gate);\n        try {\n            Work();\n        } finally {\n            Monitor.Exit(gate);\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S7133").is_empty());
}

#[test]
fn s2365_flags_getters_that_copy_collections() {
    let violating = analyze_default(
        "class C {\n    private System.Collections.Generic.List<int> items = new System.Collections.Generic.List<int>();\n    public System.Collections.Generic.List<int> Items {\n        get { return items.ToList(); }\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S2365").len(), 1);
    let clean = analyze_default(
        "class D {\n    private System.Collections.Generic.List<int> items = new System.Collections.Generic.List<int>();\n    public System.Collections.Generic.List<int> Items {\n        get { return items; }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2365").is_empty());
}

#[test]
fn s6602_flags_first_or_default_on_list_receivers() {
    let violating = analyze_default(
        "class C {\n    void M(System.Collections.Generic.List<int> data) {\n        var hit = data.FirstOrDefault(x => x > 0);\n        Log(hit);\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S6602").len(), 1);
    let clean = analyze_default(
        "class C {\n    void M(int[] data) {\n        var hit = data.FirstOrDefault(x => x > 0);\n        Log(hit);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6602").is_empty());
}

#[test]
fn s6603_flags_all_on_list_receivers() {
    let violating = analyze_default(
        "class C {\n    System.Collections.Generic.List<int> data = new System.Collections.Generic.List<int>();\n    bool M() => data.All(x => x > 0);\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S6603").len(), 1);
    let clean = analyze_default(
        "class C {\n    System.Collections.Generic.HashSet<int> data = new System.Collections.Generic.HashSet<int>();\n    bool M() => data.All(x => x > 0);\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6603").is_empty());
}

#[test]
fn s6605_flags_any_on_list_receivers() {
    let violating = analyze_default(
        "class C {\n    void M(System.Collections.Generic.IList<int> data) {\n        if (data.Any(x => x < 0)) {\n            Warn();\n        }\n    }\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S6605").len(), 1);
    let clean = analyze_default(
        "class C {\n    void M(System.Collections.Generic.List<int> data) {\n        if (data.Contains(3)) {\n            Warn();\n        }\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6605").is_empty());
}

#[test]
fn s6608_flags_enumerable_indexing_on_list_receivers() {
    let violating = analyze_default(
        "class C {\n    System.Collections.Generic.List<int> data = new System.Collections.Generic.List<int>();\n    int M() => data.First();\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S6608").len(), 1);
    let clean = analyze_default(
        "class C {\n    int M(System.Collections.Generic.List<int> data) => data[0];\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6608").is_empty());
}

#[test]
fn s6609_flags_min_max_extensions_on_sorted_sets() {
    let violating = analyze_default(
        "class C {\n    System.Collections.Generic.SortedSet<int> values = new System.Collections.Generic.SortedSet<int>();\n    int M() => values.Min();\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S6609").len(), 1);
    let clean = analyze_default(
        "class C {\n    int M(System.Collections.Generic.SortedSet<int> values) => values.Min;\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6609").is_empty());
}

#[test]
fn s6613_flags_first_last_extensions_on_linked_lists() {
    let violating = analyze_default(
        "class C {\n    System.Collections.Generic.LinkedList<int> chain = new System.Collections.Generic.LinkedList<int>();\n    int M() => chain.First();\n}\n",
    );
    assert_eq!(with_key(&violating, "csharpsquid:S6613").len(), 1);
    let clean = analyze_default(
        "class C {\n    System.Collections.Generic.LinkedList<int> chain = new System.Collections.Generic.LinkedList<int>();\n    int M() => chain.First.Value;\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6613").is_empty());
}

#[test]
fn s1858_flags_tostring_on_already_string_receivers() {
    let violating =
        analyze_default("\"abc\".ToString();\n'a'.ToString();\n$\"x{1}\".ToString();\n");
    let flagged = with_key(&violating, "csharpsquid:S1858");
    assert_eq!(flagged.len(), 3);
    assert_eq!(flagged[0].range.start.line, 1);

    let clean = analyze_default("object boxed = \"abc\";\nvar text = boxed.ToString();\n");
    assert!(with_key(&clean, "csharpsquid:S1858").is_empty());
}

#[test]
fn s1905_flags_casts_of_literals_to_their_own_type() {
    let violating = analyze_default(
        "var one = (int)5;\nvar two = (string)\"x\";\nvar three = (bool)true;\nvar four = (long)12L;\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S1905");
    assert_eq!(
        flagged.len(),
        4,
        "found: {:?}",
        flagged
            .iter()
            .map(|issue| (issue.range.start.line, issue.message.as_str()))
            .collect::<Vec<_>>()
    );
    assert_eq!(flagged[3].range.start.line, 4);

    let clean = analyze_default(
        "object o = new object();\nvar text = (string)o;\nvar size = (int)\"ab\".Length;\nvar maybe = (int?)5;\n",
    );
    assert!(with_key(&clean, "csharpsquid:S1905").is_empty());
}

#[test]
fn s3449_flags_non_integer_shift_operands() {
    let violating =
        analyze_default("var a = 1 << \"two\";\nvar b = 2 >> true;\nvar c = 3 << 1.5;\n");
    let flagged = with_key(&violating, "csharpsquid:S3449");
    assert_eq!(flagged.len(), 3);
    assert_eq!(flagged[2].range.start.line, 3);

    let clean = analyze_default("int amount = 2;\nvar a = 1 << amount;\nvar b = amount << 1;\n");
    assert!(with_key(&clean, "csharpsquid:S3449").is_empty());
}

#[test]
fn s2184_flags_integer_divisions_into_floating_declarations() {
    let violating =
        analyze_default("double ratio = 7 / 2;\nfloat scale = 10 / 4;\ndecimal fee = 9 / 5;\n");
    let flagged = with_key(&violating, "csharpsquid:S2184");
    assert_eq!(flagged.len(), 3);
    assert_eq!(flagged[1].range.start.line, 2);

    let clean = analyze_default(
        "double ok = 7.0 / 2;\nint exact = 7 / 2;\nint? maybe = 7 / 2;\nfloat casted = (float)(7 / 2);\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2184").is_empty());
}

#[test]
fn s2551_flags_locking_on_this_type_and_strings() {
    let violating =
        analyze_default("lock (this)\n{\n}\nlock (typeof(Sample))\n{\n}\nlock (\"gate\")\n{\n}\n");
    let flagged = with_key(&violating, "csharpsquid:S2551");
    assert_eq!(
        flagged.len(),
        3,
        "found: {:?}",
        flagged
            .iter()
            .map(|issue| (issue.range.start.line, issue.message.as_str()))
            .collect::<Vec<_>>()
    );
    assert_eq!(flagged[0].range.start.line, 1);
    assert_eq!(flagged[1].range.start.line, 4);
    assert_eq!(flagged[2].range.start.line, 7);

    let clean = analyze_default("object gate = new object();\nlock (gate)\n{\n}\n");
    assert!(with_key(&clean, "csharpsquid:S2551").is_empty());
}

#[test]
fn s2114_flags_collections_passed_to_their_own_methods() {
    let violating = analyze_default("items.AddRange(items);\nitems.InsertRange(items, 0);\n");
    let flagged = with_key(&violating, "csharpsquid:S2114");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[1].range.start.line, 2);

    let clean = analyze_default("items.AddRange(others);\nitems.Union(more);\n");
    assert!(with_key(&clean, "csharpsquid:S2114").is_empty());
}

#[test]
fn s2201_flags_discarded_pure_static_results() {
    let violating =
        analyze_default("Math.Abs(-3);\nstring.IsNullOrEmpty(name);\nDateTime.IsLeapYear(2020);\n");
    let flagged = with_key(&violating, "csharpsquid:S2201");
    assert_eq!(flagged.len(), 3);
    assert_eq!(flagged[2].range.start.line, 3);

    let clean = analyze_default(
        "var absolute = Math.Abs(-3);\nif (string.IsNullOrEmpty(name))\n{\n}\n_ = DateTime.DaysInMonth(2020, 1);\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2201").is_empty());
}

#[test]
fn s2053_flags_static_salts_in_password_hashing() {
    let violating = analyze_default(
        "byte[] Derive(byte[] password)\n{\n    var derive = new Rfc2898DeriveBytes(password, new byte[] { 1, 2, 3 });\n    var hash = HashPassword(password, \"pepper\");\n    var pbkdf = Rfc2898DeriveBytes.Pbkdf2(password, \"lit\", 1000, 32);\n    return derive.GetBytes(16);\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S2053");
    assert_eq!(flagged.len(), 3);
    assert_eq!(flagged[0].range.start.line, 3);
    assert_eq!(flagged[1].range.start.line, 4);
    assert_eq!(flagged[2].range.start.line, 5);

    let clean = analyze_default(
        "byte[] Good(byte[] password, byte[] salt)\n{\n    var derive = new Rfc2898DeriveBytes(password, salt);\n    var hash = HashPassword(password, salt);\n    return derive.GetBytes(16);\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2053").is_empty());
}

#[test]
fn s3329_flags_static_initialization_vectors() {
    let violating = analyze_default(
        "aes.IV = new byte[] { 1, 2, 3 };\nvar enc = aes.CreateEncryptor(key, new byte[] { 9 });\nvar s = new AesManaged { IV = \"0123456789abcdef\" };\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S3329");
    assert_eq!(flagged.len(), 3);
    assert_eq!(flagged[0].range.start.line, 1);
    assert_eq!(flagged[1].range.start.line, 2);
    assert_eq!(flagged[2].range.start.line, 3);

    let clean =
        analyze_default("aes.IV = GenerateIv();\nvar enc2 = aes.CreateEncryptor(key, iv);\n");
    assert!(with_key(&clean, "csharpsquid:S3329").is_empty());
}

#[test]
fn s2245_flags_random_in_security_named_contexts() {
    let violating = analyze_default(
        "class TokenHandler\n{\n    void Issue()\n    {\n        var token = new Random();\n        token.Next();\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S2245");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);

    let clean =
        analyze_default("void Sample()\n{\n    var count = new Random();\n    count.Next();\n}\n");
    assert!(with_key(&clean, "csharpsquid:S2245").is_empty());
}

#[test]
fn s2257_flags_xor_mixing_in_cipher_named_methods() {
    let violating = analyze_default(
        "class Crypto\n{\n    byte[] EncryptBlock(byte[] data)\n    {\n        var mixed = data[0] ^ 0x42;\n        return [mixed];\n    }\n}\n",
    );
    let flagged = with_key(&violating, "csharpsquid:S2257");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let clean = analyze_default("int Mix(int value)\n{\n    return value ^ 0xFF;\n}\n");
    assert!(with_key(&clean, "csharpsquid:S2257").is_empty());
}
