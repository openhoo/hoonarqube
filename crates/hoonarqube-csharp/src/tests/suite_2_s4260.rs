//! Test suite part; the full suite spans `tests/*.rs`.

use super::*;

#[test]
fn s3869_flags_dangerous_handle_reads() {
    let report = analyze_default(
        "class C\n{\n    IntPtr Leak(SafeHandle mySafeHandle)\n    {\n        return mySafeHandle.DangerousGetHandle();\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S3869").len(), 1);

    let clean = analyze_default(
        "class C\n{\n    IntPtr Peek(SafeHandle handle)\n    {\n        return handle.DangerousAddRef();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3869").is_empty());
}

#[test]
fn s3884_flags_com_security_invocations() {
    let report = analyze_default(
        "class C\n{\n    void Harden()\n    {\n        CoSetProxyBlanket(null, 0, 0, null, 0, 0, IntPtr.Zero, 0);\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S3884").len(), 1);

    let clean = analyze_default(
        "class C\n{\n    void Harden()\n    {\n        CoSetProxyBlanketSafely();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3884").is_empty());
}

#[test]
fn s3885_flags_assembly_load_from() {
    let report = analyze_default(
        "class Loader\n{\n    void Fetch(string path)\n    {\n        Assembly.LoadFrom(path);\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S3885").len(), 1);

    let clean = analyze_default(
        "class Loader\n{\n    void Fetch(string path)\n    {\n        Assembly.Load(path);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3885").is_empty());
}

#[test]
fn s3902_flags_get_executing_assembly() {
    let report = analyze_default(
        "class C\n{\n    void Who()\n    {\n        Assembly.GetExecutingAssembly();\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S3902").len(), 1);

    let clean = analyze_default(
        "class C\n{\n    void Who()\n    {\n        Assembly.GetCallingAssembly();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S3902").is_empty());
}

#[test]
fn s3216_requires_configure_await_false() {
    let blocking_context = analyze_default(
        "class C\n{\n    void Wait(Task task)\n    {\n        task.ConfigureAwait(true);\n    }\n}\n",
    );
    assert_eq!(with_key(&blocking_context, "csharpsquid:S3216").len(), 1);

    let off_context = analyze_default(
        "class C\n{\n    void Wait(Task task)\n    {\n        task.ConfigureAwait(false);\n    }\n}\n",
    );
    assert!(with_key(&off_context, "csharpsquid:S3216").is_empty());
}

#[test]
fn s4462_flags_all_blocking_shapes() {
    let report = analyze_default(
        "class C\n{\n    void Block(Task task)\n    {\n        var v = task.Result;\n        task.Wait();\n        task.GetAwaiter().GetResult();\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S4462").len(), 3);

    let clean = analyze_default(
        "class C\n{\n    async System.Threading.Tasks.Task Await(Task task)\n    {\n        await task;\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S4462").is_empty());
}

#[test]
fn s3169_flags_stacked_orderings() {
    let report = analyze_default(
        "class C\n{\n    void Sort(System.Collections.Generic.List<int> items)\n    {\n        items.OrderBy(a => a).OrderBy(b => -b);\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S3169").len(), 1);

    let single = analyze_default(
        "class C\n{\n    void Sort(System.Collections.Generic.List<int> items)\n    {\n        items.OrderBy(a => a);\n    }\n}\n",
    );
    assert!(with_key(&single, "csharpsquid:S3169").is_empty());
}

#[test]
fn s6607_flags_filtering_after_ordering() {
    let late_filter = analyze_default(
        "class C\n{\n    void Query(System.Collections.Generic.List<int> items)\n    {\n        items.Where(v => v > 0).OrderBy(v => v);\n    }\n}\n",
    );
    assert_eq!(with_key(&late_filter, "csharpsquid:S6607").len(), 1);

    let early_filter = analyze_default(
        "class C\n{\n    void Query(System.Collections.Generic.List<int> items)\n    {\n        items.OrderBy(v => v).Where(v => v > 0);\n    }\n}\n",
    );
    assert!(with_key(&early_filter, "csharpsquid:S6607").is_empty());
}

#[test]
fn s2971_flags_where_terminal_chains() {
    let report = analyze_default(
        "class C\n{\n    bool Any(System.Collections.Generic.List<int> items)\n    {\n        return items.Where(v => v > 0).Any();\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S2971").len(), 1);

    let clean = analyze_default(
        "class C\n{\n    bool Any(System.Collections.Generic.List<int> items)\n    {\n        return items.Any();\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2971").is_empty());
}

#[test]
fn s3267_flags_conditionally_appending_loops() {
    let report = analyze_default(
        "class C\n{\n    void Gather(int[] items, System.Collections.Generic.List<int> result)\n    {\n        foreach (var item in items)\n        {\n            if (item > 0)\n            {\n                result.Add(item);\n            }\n        }\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S3267").len(), 1);

    let complex = analyze_default(
        "class C\n{\n    void Gather(int[] items, System.Collections.Generic.List<int> result)\n    {\n        foreach (var item in items)\n        {\n            if (item > 0)\n            {\n                result.Add(item);\n            }\n            else\n            {\n                result.Add(-item);\n            }\n        }\n    }\n}\n",
    );
    assert!(with_key(&complex, "csharpsquid:S3267").is_empty());
}

#[test]
fn s4635_flags_zero_based_substrings() {
    let report = analyze_default(
        "class C\n{\n    string Head(string s)\n    {\n        return s.Substring(0, 3);\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S4635").len(), 1);

    let offset = analyze_default(
        "class C\n{\n    string Head(string s)\n    {\n        return s.Substring(1, 3);\n    }\n}\n",
    );
    assert!(with_key(&offset, "csharpsquid:S4635").is_empty());
}

#[test]
fn s6610_flags_single_character_string_arguments() {
    let report = analyze_default(
        "class C\n{\n    bool Starts(string s)\n    {\n        return s.StartsWith(\"a\");\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S6610").len(), 1);

    let longer = analyze_default(
        "class C\n{\n    bool Starts(string s)\n    {\n        return s.StartsWith(\"ab\");\n    }\n}\n",
    );
    assert!(with_key(&longer, "csharpsquid:S6610").is_empty());
}

#[test]
fn s6617_flags_any_with_parameter_equality_lambda() {
    let report = analyze_default(
        "class C\n{\n    bool Has(System.Collections.Generic.List<int> items)\n    {\n        return items.Any(v => v == 1);\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S6617").len(), 1);

    let predicate = analyze_default(
        "class C\n{\n    bool Has(System.Collections.Generic.List<int> items)\n    {\n        return items.All(v => v > 0);\n    }\n}\n",
    );
    assert!(with_key(&predicate, "csharpsquid:S6617").is_empty());
}

#[test]
fn s6612_requires_concurrent_dictionary_delegates() {
    let eager = analyze_default(
        "class C\n{\n    int Value(System.Collections.Concurrent.ConcurrentDictionary<int, int> map)\n    {\n        return map.GetOrAdd(1, ExpensiveBuild());\n    }\n}\n",
    );
    assert_eq!(with_key(&eager, "csharpsquid:S6612").len(), 1);

    let lazy = analyze_default(
        "class C\n{\n    int Value(System.Collections.Concurrent.ConcurrentDictionary<int, int> map)\n    {\n        return map.GetOrAdd(1, key => Build(key));\n    }\n}\n",
    );
    assert!(with_key(&lazy, "csharpsquid:S6612").is_empty());
}

#[test]
fn s6618_flags_formattable_string_flows() {
    let report = analyze_default(
        "class C\n{\n    string Text()\n    {\n        return FormattableString.Invariant($\"x{1}\");\n    }\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S6618").len(), 1);

    let clean = analyze_default(
        "class C\n{\n    string Text()\n    {\n        return string.Format(\"x{0}\", 1);\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6618").is_empty());
}

#[test]
fn s3456_flags_string_array_conversions() {
    let indexed = analyze_default(
        "class C\n{\n    char First(string s)\n    {\n        return s.ToCharArray()[0];\n    }\n}\n",
    );
    assert_eq!(with_key(&indexed, "csharpsquid:S3456").len(), 1);

    let iterated = analyze_default(
        "class C\n{\n    void Walk(string s)\n    {\n        foreach (char c in s.ToCharArray())\n        {\n            Use(c);\n        }\n    }\n}\n",
    );
    assert_eq!(with_key(&iterated, "csharpsquid:S3456").len(), 1);

    let direct = analyze_default(
        "class C\n{\n    void Walk(string s)\n    {\n        foreach (char c in s)\n        {\n            Use(c);\n        }\n    }\n}\n",
    );
    assert!(with_key(&direct, "csharpsquid:S3456").is_empty());
}

#[test]
fn s1643_flags_string_concatenation_inside_loops() {
    let looping = analyze_default(
        "class C\n{\n    string Build()\n    {\n        var text = \"\";\n        while (More())\n        {\n            text += \",\";\n        }\n        return text;\n    }\n}\n",
    );
    assert_eq!(with_key(&looping, "csharpsquid:S1643").len(), 1);

    let outside = analyze_default(
        "class C\n{\n    string Build()\n    {\n        var text = \"a\";\n        text += \"b\";\n        return text;\n    }\n}\n",
    );
    assert!(with_key(&outside, "csharpsquid:S1643").is_empty());

    let numeric = analyze_default(
        "class C\n{\n    int Count(int total)\n    {\n        while (More())\n        {\n            total += 1;\n        }\n        return total;\n    }\n}\n",
    );
    assert!(with_key(&numeric, "csharpsquid:S1643").is_empty());
}

#[test]
fn s1192_flags_repeated_literals_from_the_second_occurrence() {
    let repeated = analyze_default(
        "class C\n{\n    void M()\n    {\n        Use(\"alpha\");\n        Use(\"alpha\");\n\
             Use(\"alpha\");\n        Use(\"beta\");\n        Use(\"beta\");\n    }\n}\n",
    );
    let flagged = with_key(&repeated, "csharpsquid:S1192");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 6);
    assert_eq!(flagged[1].range.start.line, 7);
    assert!(flagged[0].message.contains("\"alpha\" 3 times."));

    let options = AnalyzerOptions {
        duplicate_string_threshold: 2,
        ..Default::default()
    };
    let lowered = analyze_options(
        "class C\n{\n    void M()\n    {\n        Use(\"beta\");\n        Use(\"beta\");\n    }\n}\n",
        &options,
    );
    assert_eq!(with_key(&lowered, "csharpsquid:S1192").len(), 1);
}

#[test]
fn s1192_exempts_empty_and_unique_literals() {
    let report = analyze_default(
        "class C\n{\n    void M()\n    {\n        Use(\"\");\n        Use(\"\");\n\
             Use(\"\");\n        Use(\"only once\");\n    }\n}\n",
    );
    assert!(with_key(&report, "csharpsquid:S1192").is_empty());
}

#[test]
fn s2068_flags_credential_named_assignments_and_declarators() {
    let report = analyze_default(
        "class C\n{\n    string pwd = \"s3cret\";\n\n    void Set()\n    {\n\
                 password = \"hunter2\";\n        this.passPhrase = \"z\";\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2068");
    assert_eq!(flagged.len(), 3);
    assert!(flagged[0].message.contains("pwd"));

    let clean = analyze_default(
        "class C\n{\n    string name = \"s3cret\";\n\n    void Set()\n    {\n\
                 password = string.Empty;\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S2068").is_empty());
}

#[test]
fn s6418_needs_secret_word_and_entropy_together() {
    let secret = analyze_default("var apiKey = \"aB3$xY9#kQ\";\n");
    assert_eq!(with_key(&secret, "csharpsquid:S6418").len(), 1);

    let low_entropy = analyze_default("var token = \"abc12345\";\n");
    assert!(with_key(&low_entropy, "csharpsquid:S6418").is_empty());

    let no_secret_word = analyze_default("var label = \"aB3$xY9#kQ\";\n");
    assert!(with_key(&no_secret_word, "csharpsquid:S6418").is_empty());

    let dashed = analyze_default("var My_ApiKey = \"aB3$xY9#kQ\";\n");
    assert_eq!(with_key(&dashed, "csharpsquid:S6418").len(), 1);
}

#[test]
fn s1313_flags_only_valid_dotted_quads() {
    let report = analyze_default(
        "class C\n{\n    string ip = \"192.168.0.1\";\n    string bad = \"999.9.9.9\";\n\
                 string short1 = \"1.2.3\";\n    string ver = \"v1.2.3.4\";\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1313");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);
}

#[test]
fn s1075_flags_scheme_prefixed_literals() {
    let report = analyze_default(
        "class C\n{\n    string a = \"https://example.com/x\";\n    string b = \"example.com/y\";\n\
                 string c = \"FTP://f.z\";\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S1075").len(), 2);
}

#[test]
fn s2857_flags_squeezed_sql_keywords_only() {
    let squeezed = analyze_default("var q = \"SELECT*FROM users WHERE id=@id\";\n");
    let flagged = with_key(&squeezed, "csharpsquid:S2857");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("'SELECT'"));

    let spaced = analyze_default("var q = \"SELECT * FROM users\";\n");
    assert!(with_key(&spaced, "csharpsquid:S2857").is_empty());

    let wordy = analyze_default("var w = \"SELECTION of items\";\n");
    assert!(with_key(&wordy, "csharpsquid:S2857").is_empty());
}

#[test]
fn s5856_rejects_syntactically_invalid_patterns() {
    let report = analyze_default(
        "class C\n{\n    Regex R = new Regex(\"[a-z+\");\n\n    bool Check(string input) =>\n\
                 Regex.IsMatch(input, \"*bad\");\n}\n",
    );
    assert_eq!(with_key(&report, "csharpsquid:S5856").len(), 2);

    let valid = analyze_default(
        "class C\n{\n    Regex R = new Regex(@\"^\\d{2,4}([a-z]|$)\", RegexOptions.Compiled);\n\
                 bool Look(string input) => Regex.IsMatch(input, \"(?<=x)y*\");\n}\n",
    );
    assert!(with_key(&valid, "csharpsquid:S5856").is_empty());

    let reversed = analyze_default("bool B = Regex.IsMatch(s, \"[z-a]\");\n");
    assert_eq!(with_key(&reversed, "csharpsquid:S5856").len(), 1);
}

#[test]
fn s6444_requires_timeouts_on_regex_apis() {
    let missing = analyze_default(
        "class C\n{\n    Regex R = new Regex(\"p\");\n\n    bool Find(string input) =>\n\
                 Regex.IsMatch(input, \"\\\\w\");\n}\n",
    );
    assert_eq!(with_key(&missing, "csharpsquid:S6444").len(), 2);

    let present = analyze_default(
        "class C\n{\n    Regex R = new Regex(\n        \"p\",\n\
                 RegexOptions.None,\n        TimeSpan.FromSeconds(2));\n\n    bool Find(string input) =>\n\
                 Regex.IsMatch(input, \"\\\\w\", RegexOptions.None, TimeSpan.FromSeconds(2));\n}\n",
    );
    assert!(with_key(&present, "csharpsquid:S6444").is_empty());
}

#[test]
fn s2479_flags_raw_whitespace_but_not_escapes() {
    let raw_tab = analyze_default("var t = \"a\tb\";\n");
    assert_eq!(with_key(&raw_tab, "csharpsquid:S2479").len(), 1);

    let escaped = analyze_default("var t = \"a\\tb\\n\";\n");
    assert!(with_key(&escaped, "csharpsquid:S2479").is_empty());
}

#[test]
fn s818_flags_lowercase_numeric_suffixes() {
    let flagged = analyze_default(
        "class C\n{\n    long a = 123l;\n    float b = 1.5f;\n    decimal c = 100m;\n}\n",
    );
    assert_eq!(with_key(&flagged, "csharpsquid:S818").len(), 3);

    let clean = analyze_default(
        "class C\n{\n    long a = 123L;\n    double b = 1.5D;\n    ulong c = 0xFFUL;\n\
                 int d = 0xd;\n    int e = 42;\n    double f = 1.5e3;\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S818").is_empty());
}

#[test]
fn s1128_flags_using_directives_without_file_references() {
    let unused = analyze_default("using System.Collections.Generic;\nclass C\n{\n}\n");
    let flagged = with_key(&unused, "csharpsquid:S1128");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);

    let aliased = analyze_default(
        "using Alias = System.IO.File;\nclass C\n{\n    string Read()\n    {\n\
                 return File.ReadAllText(\"x\");\n    }\n}\n",
    );
    assert!(with_key(&aliased, "csharpsquid:S1128").is_empty());

    let static_unused = analyze_default("using static System.Math;\nclass C\n{\n}\n");
    assert_eq!(with_key(&static_unused, "csharpsquid:S1128").len(), 1);
}

#[test]
fn s1144_flags_unreferenced_private_members_only() {
    let unused =
        analyze_default("class C\n{\n    int field;\n\n    void Method()\n    {\n    }\n}\n");
    assert_eq!(with_key(&unused, "csharpsquid:S1144").len(), 2);

    let overloads = analyze_default(
        "class C\n{\n    void Twice()\n    {\n    }\n\n    void Twice(int n)\n    {\n    }\n}\n",
    );
    assert_eq!(with_key(&overloads, "csharpsquid:S1144").len(), 2);

    let used = analyze_default(
        "class C\n{\n    int field;\n\n    public int Get()\n    {\n\
                 return field;\n    }\n}\n",
    );
    assert!(with_key(&used, "csharpsquid:S1144").is_empty());

    let partial = analyze_default("partial class C\n{\n    void Method()\n    {\n    }\n}\n");
    assert!(with_key(&partial, "csharpsquid:S1144").is_empty());

    let constant = analyze_default("class C\n{\n    const int Limit = 5;\n}\n");
    assert!(with_key(&constant, "csharpsquid:S1144").is_empty());
}

#[test]
fn s1481_flags_locals_nobody_reads() {
    let stale = analyze_default(
        "class C\n{\n    int M()\n    {\n        int stale = 1;\n        return 2;\n    }\n}\n",
    );
    assert_eq!(with_key(&stale, "csharpsquid:S1481").len(), 1);

    let read = analyze_default(
        "class C\n{\n    int M()\n    {\n        int fresh = 1;\n        return fresh;\n    }\n}\n",
    );
    assert!(with_key(&read, "csharpsquid:S1481").is_empty());

    let exempt = analyze_default(
        "class C\n{\n    void M()\n    {\n        int _ = 1;\n        const int kMax = 5;\n\
                 Use(kMax);\n    }\n}\n",
    );
    assert!(with_key(&exempt, "csharpsquid:S1481").is_empty());
}

#[test]
fn s1172_flags_parameters_no_body_reads() {
    let unused = analyze_default(
        "class C\n{\n    void Handle(int value)\n    {\n        Log();\n    }\n}\n",
    );
    let flagged = with_key(&unused, "csharpsquid:S1172");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("'value'"));

    let read = analyze_default(
        "class C\n{\n    void Handle(int value)\n    {\n        Log(value);\n    }\n}\n",
    );
    assert!(with_key(&read, "csharpsquid:S1172").is_empty());

    let visible = analyze_default(
        "class C\n{\n    public void Handle(int value)\n    {\n        Log();\n    }\n}\n",
    );
    assert!(with_key(&visible, "csharpsquid:S1172").is_empty());

    let discarded =
        analyze_default("class C\n{\n    void Handle(int _)\n    {\n        Log();\n    }\n}\n");
    assert!(with_key(&discarded, "csharpsquid:S1172").is_empty());
}

#[test]
fn s109_flags_numbers_beyond_the_small_allowance() {
    let magic = analyze_default("class C\n{\n    int M()\n    {\n        return 42;\n    }\n}\n");
    assert_eq!(with_key(&magic, "csharpsquid:S109").len(), 1);

    let hex = analyze_default("int mask = 0xFF;\n");
    assert_eq!(with_key(&hex, "csharpsquid:S109").len(), 1);

    let boundary_two = analyze_default("int x = 2;\n");
    assert_eq!(with_key(&boundary_two, "csharpsquid:S109").len(), 1);

    let allowed = analyze_default("int a = -1;\nint b = 0;\nint c = 1;\ndouble d = 1.0;\n");
    assert!(with_key(&allowed, "csharpsquid:S109").is_empty());

    let constants =
        analyze_default("class C\n{\n    const int Limit = 100;\n    int Read() => Limit;\n}\n");
    assert!(with_key(&constants, "csharpsquid:S109").is_empty());

    let enumerations = analyze_default("enum E\n{\n    Max = 200,\n}\n");
    assert!(with_key(&enumerations, "csharpsquid:S109").is_empty());

    let defaults = analyze_default(
        "class C\n{\n    void M(int retries = 3)\n    {\n        Use(retries);\n    }\n}\n",
    );
    assert!(with_key(&defaults, "csharpsquid:S109").is_empty());
}

#[test]
fn s3264_flags_events_that_are_never_raised() {
    let silent = analyze_default("class C\n{\n    event System.EventHandler Done;\n}\n");
    let flagged = with_key(&silent, "csharpsquid:S3264");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("'Done'"));

    let raised = analyze_default(
        "class C\n{\n    event System.EventHandler Done;\n\n    void Raise()\n    {\n        Done(this, System.EventArgs.Empty);\n    }\n}\n",
    );
    assert!(with_key(&raised, "csharpsquid:S3264").is_empty());

    // Documented heuristic limit: a bare subscription silences the check,
    // because distinguishing it from a raise needs type flow.
    let subscribed = analyze_default(
        "class C\n{\n    event System.EventHandler Done;\n\n    void Wire()\n    {\n        Done += OnDone;\n    }\n}\n",
    );
    assert!(with_key(&subscribed, "csharpsquid:S3264").is_empty());
}

#[test]
fn s3251_flags_partial_methods_without_implementations() {
    let orphan = analyze_default("partial class C\n{\n    partial void OnRaise();\n}\n");
    for f in &orphan.issues {
        println!("DBGA {}", f.rule_key);
    }
    let flagged = with_key(&orphan, "csharpsquid:S3251");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("'OnRaise'"));

    let paired = analyze_default(
        "partial class C\n{\n    partial void OnRaise();\n\n    partial void OnRaise()\n    {\n    }\n}\n",
    );
    assert!(with_key(&paired, "csharpsquid:S3251").is_empty());

    // Boundary: without the 'partial' modifier the method is out of scope.
    let plain = analyze_default("class C\n{\n    void Method();\n}\n");
    assert!(with_key(&plain, "csharpsquid:S3251").is_empty());
}

#[test]
fn s3253_flags_redundant_constructors_and_finalizers() {
    let redundant = analyze_default(
        "class C\n{\n    public C()\n    {\n    }\n\n    ~C()\n    {\n        base.Dispose();\n    }\n}\n",
    );
    assert_eq!(with_key(&redundant, "csharpsquid:S3253").len(), 2);

    let meaningful = analyze_default(
        "class C\n{\n    private C()\n    {\n    }\n\n    public C(int seed)\n    {\n        Use(seed);\n    }\n\n    ~C()\n    {\n        Log();\n    }\n}\n",
    );
    assert!(with_key(&meaningful, "csharpsquid:S3253").is_empty());
}

#[test]
fn s3052_flags_field_initializers_spelling_defaults() {
    let defaults = analyze_default(
        "class C\n{\n    int a = 0;\n    string b = null;\n    bool c = false;\n        char d = '\\0';\n    double e = 0.0;\n    object f = default;\n}\n",
    );
    assert_eq!(with_key(&defaults, "csharpsquid:S3052").len(), 6);

    let meaningful = analyze_default(
        "class C\n{\n    int a = 1;\n    string b = \"x\";\n    bool c = true;\n        double d = 0.5;\n    int[] e = new int[0];\n}\n",
    );
    assert!(with_key(&meaningful, "csharpsquid:S3052").is_empty());
}

#[test]
fn s3962_promotes_literal_backed_static_readonly_fields() {
    let literal = analyze_default("class C\n{\n    static readonly string Greeting = \"hi\";\n}\n");
    assert_eq!(with_key(&literal, "csharpsquid:S3962").len(), 1);

    let computed = analyze_default(
        "class C\n{\n    static readonly TimeSpan Wait = TimeSpan.FromSeconds(2);\n        readonly int local = 5;\n}\n",
    );
    assert!(with_key(&computed, "csharpsquid:S3962").is_empty());
}

#[test]
fn s3963_moves_static_ctor_only_initialization_inline() {
    let moved = analyze_default(
        "class C\n{\n    static int value;\n\n    static C()\n    {\n        value = Compute();\n    }\n}\n",
    );
    let flagged = with_key(&moved, "csharpsquid:S3963");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("'value'"));

    let inline = analyze_default(
        "class C\n{\n    static int value = Compute();\n\n    static C()\n    {\n        value++;\n    }\n}\n",
    );
    assert!(with_key(&inline, "csharpsquid:S3963").is_empty());

    let untouched = analyze_default(
        "class C\n{\n    static int value;\n\n    static C()\n    {\n        Log();\n    }\n}\n",
    );
    assert!(with_key(&untouched, "csharpsquid:S3963").is_empty());
}

#[test]
fn s3010_flags_static_writes_from_instance_constructors() {
    let leaking = analyze_default(
        "class C\n{\n    static int count;\n    int seen;\n\n    public C()\n    {\n        count = 1;\n        seen = 2;\n    }\n}\n",
    );
    let flagged = with_key(&leaking, "csharpsquid:S3010");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("'count'"));

    let proper = analyze_default(
        "class C\n{\n    static int count;\n\n    static C()\n    {\n        count = 1;\n    }\n        public C()\n    {\n        Use(count);\n    }\n}\n",
    );
    assert!(with_key(&proper, "csharpsquid:S3010").is_empty());
}

#[test]
fn s2996_flags_thread_static_field_initializers() {
    let initialized =
        analyze_default("class C\n{\n    [ThreadStatic]\n    static int perThread = 5;\n}\n");
    assert_eq!(with_key(&initialized, "csharpsquid:S2996").len(), 1);

    let bare = analyze_default("class C\n{\n    [ThreadStatic]\n    static int perThread;\n}\n");
    assert!(with_key(&bare, "csharpsquid:S2996").is_empty());
}

#[test]
fn s3005_requires_static_on_thread_static_fields() {
    let instance = analyze_default("class C\n{\n    [ThreadStatic]\n    int perThread;\n}\n");
    let flagged = with_key(&instance, "csharpsquid:S3005");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("'static'"));

    let proper = analyze_default("class C\n{\n    [ThreadStatic]\n    static int perThread;\n}\n");
    assert!(with_key(&proper, "csharpsquid:S3005").is_empty());
}

#[test]
fn s2743_flags_static_fields_inside_generic_types() {
    let shared = analyze_default("class Cache<T>\n{\n    static Dictionary<string, T> map;\n}\n");
    let flagged = with_key(&shared, "csharpsquid:S2743");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("'map'"));

    let instance_only = analyze_default(
        "class Cache<T>\n{\n    Dictionary<string, T> map;\n\n    const int Limit = 4;\n}\n",
    );
    assert!(with_key(&instance_only, "csharpsquid:S2743").is_empty());

    let non_generic = analyze_default("class Cache\n{\n    static int hits;\n}\n");
    assert!(with_key(&non_generic, "csharpsquid:S2743").is_empty());
}

#[test]
fn s3906_keeps_event_handler_delegates_void() {
    let returning = analyze_default("delegate int Op(object sender, MyEventArgs e);\n");
    for f in &returning.issues {
        println!("DBGB {}", f.rule_key);
    }
    let flagged = with_key(&returning, "csharpsquid:S3906");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("'void'"));

    let proper = analyze_default("delegate void Op(object sender, MyEventArgs e);\n");
    assert!(with_key(&proper, "csharpsquid:S3906").is_empty());

    let unshaped = analyze_default("delegate int Map(string input);\n");
    assert!(with_key(&unshaped, "csharpsquid:S3906").is_empty());
}

#[test]
fn s3908_prefers_event_handler_over_custom_shaped_delegates() {
    let custom = analyze_default(
        "delegate void Op(object sender, MyEventArgs e);\n\nclass C\n{\n    event Op Raised;\n}\n",
    );
    let flagged = with_key(&custom, "csharpsquid:S3908");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("'Raised'"));

    let framework =
        analyze_default("class C\n{\n    event System.EventHandler<MyEventArgs> Raised;\n}\n");
    assert!(with_key(&framework, "csharpsquid:S3908").is_empty());

    let unshaped =
        analyze_default("delegate void Op(int code);\n\nclass C\n{\n    event Op Failed;\n}\n");
    assert!(with_key(&unshaped, "csharpsquid:S3908").is_empty());
}

#[test]
fn s4225_flags_extension_methods_on_object() {
    let broad = analyze_default(
        "static class Ext\n{\n    public static bool Blank(this object item)\n    {\n        return item == null;\n    }\n}\n",
    );
    let flagged = with_key(&broad, "csharpsquid:S4225");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("'object'"));

    let specific = analyze_default(
        "static class Ext\n{\n    public static bool Blank(this string item)\n    {\n        return item == null;\n    }\n}\n",
    );
    assert!(with_key(&specific, "csharpsquid:S4225").is_empty());

    let plain_method = analyze_default(
        "static class Ext\n{\n    public static bool Blank(object item)\n    {\n        return item == null;\n    }\n}\n",
    );
    assert!(with_key(&plain_method, "csharpsquid:S4225").is_empty());
}

#[test]
fn s4220_flags_events_without_eventargs_payloads() {
    let raw_payload = analyze_default(
        "delegate void Handler(int code);\n\nclass C\n{\n    event Handler Failed;\n}\n",
    );
    let flagged = with_key(&raw_payload, "csharpsquid:S4220");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("'Failed'"));

    let proper = analyze_default(
        "delegate void Handler(object sender, MyEventArgs e);\n\nclass C\n{\n        event Handler Failed;\n}\n",
    );
    assert!(with_key(&proper, "csharpsquid:S4220").is_empty());

    let framework = analyze_default("class C\n{\n    event System.EventHandler Failed;\n}\n");
    assert!(with_key(&framework, "csharpsquid:S4220").is_empty());
}

#[test]
fn s3993_constrains_attribute_classes_with_usage() {
    let open = analyze_default("class Mine : System.Attribute\n{\n}\n");
    let flagged = with_key(&open, "csharpsquid:S3993");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("[AttributeUsage]"));

    let constrained = analyze_default(
        "[System.AttributeUsage(System.AttributeTargets.Class)]\nclass Mine : System.Attribute\n{\n}\n",
    );
    assert!(with_key(&constrained, "csharpsquid:S3993").is_empty());

    let plain_class = analyze_default("class Mine : Base\n{\n}\n");
    assert!(with_key(&plain_class, "csharpsquid:S3993").is_empty());
}

#[test]
fn s3990_s3992_s4026_flag_missing_assembly_annotations() {
    let partial = analyze_default("[assembly: System.ComVisible(true)]\nclass C\n{\n}\n");
    assert_eq!(with_key(&partial, "csharpsquid:S3990").len(), 1);
    assert!(with_key(&partial, "csharpsquid:S3992").is_empty());
    assert_eq!(with_key(&partial, "csharpsquid:S4026").len(), 1);

    let complete = analyze_default(
        "[assembly: System.CLSCompliant(false)]\n[assembly: System.ComVisible(false)]\n        [assembly: System.NeutralResourcesLanguage(\"en\")]\nclass C\n{\n}\n",
    );
    assert!(with_key(&complete, "csharpsquid:S3990").is_empty());
    assert!(with_key(&complete, "csharpsquid:S3992").is_empty());
    assert!(with_key(&complete, "csharpsquid:S4026").is_empty());

    // Boundary: files without any assembly attributes are not
    // assembly-info files and stay clean.
    let plain = analyze_default("class C\n{\n}\n");
    assert!(with_key(&plain, "csharpsquid:S3990").is_empty());
    assert!(with_key(&plain, "csharpsquid:S3992").is_empty());
    assert!(with_key(&plain, "csharpsquid:S4026").is_empty());
}

#[test]
fn s4016_renames_reserved_enum_members() {
    let reserved = analyze_default("enum Level\n{\n    Reserved,\n    High = 1,\n}\n");
    let flagged = with_key(&reserved, "csharpsquid:S4016");
    assert_eq!(flagged.len(), 1);

    let lowercase = analyze_default("enum Level\n{\n    reserved,\n    High = 1,\n}\n");
    assert_eq!(with_key(&lowercase, "csharpsquid:S4016").len(), 1);

    let clean = analyze_default("enum Level\n{\n    Low,\n    High = 1,\n}\n");
    assert!(with_key(&clean, "csharpsquid:S4016").is_empty());
}

#[test]
fn s4070_flags_unused_flags_enumerations() {
    let decorated_only =
        analyze_default("[System.Flags]\nenum Rights\n{\n    Read = 1,\n    Write = 2,\n}\n");
    let flagged = with_key(&decorated_only, "csharpsquid:S4070");
    assert_eq!(flagged.len(), 1);

    let combined = analyze_default(
        "[System.Flags]\nenum Rights\n{\n    Read = 1,\n    Write = 2,\n}\n\nclass C\n{\n        Rights All() => Rights.Read | Rights.Write;\n}\n",
    );
    assert!(with_key(&combined, "csharpsquid:S4070").is_empty());

    let undecorated = analyze_default("enum Rights\n{\n    Read = 1,\n    Write = 2,\n}\n");
    assert!(with_key(&undecorated, "csharpsquid:S4070").is_empty());
}

#[test]
fn s2345_requires_explicit_values_on_flags_members() {
    let implicit_tail =
        analyze_default("[System.Flags]\nenum Rights\n{\n    Read = 1,\n    Write,\n}\n");
    let flagged = with_key(&implicit_tail, "csharpsquid:S2345");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("'Write'"));

    let explicit_all =
        analyze_default("[System.Flags]\nenum Rights\n{\n    Read = 1,\n    Write = 2,\n}\n");
    assert!(with_key(&explicit_all, "csharpsquid:S2345").is_empty());

    // Boundary: without '[Flags]' implicit numbering is fine.
    let sequential = analyze_default("enum Stage\n{\n    Start,\n    Stop,\n}\n");
    assert!(with_key(&sequential, "csharpsquid:S2345").is_empty());
}

#[test]
fn s2346_names_the_zero_flags_member_none() {
    let misnamed_zero =
        analyze_default("[System.Flags]\nenum Rights\n{\n    Zero = 0,\n    Read = 1,\n}\n");
    let flagged = with_key(&misnamed_zero, "csharpsquid:S2346");
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].message.contains("'Zero'"));

    // Boundary: an uninitialized first member is implicitly zero and
    // equally needs the 'None' name.
    let implicit_zero =
        analyze_default("[System.Flags]\nenum Rights\n{\n    Read,\n    Write = 2,\n}\n");
    let flagged_implicit = with_key(&implicit_zero, "csharpsquid:S2346");
    assert_eq!(flagged_implicit.len(), 1);
    assert!(flagged_implicit[0].message.contains("'Read'"));

    // No zero-valued member at all: nothing to rename in-file.
    let no_zero =
        analyze_default("[System.Flags]\nenum Levels\n{\n    Read = 1,\n    Write = 2,\n}\n");
    assert!(with_key(&no_zero, "csharpsquid:S2346").is_empty());

    let named_none =
        analyze_default("[System.Flags]\nenum Rights\n{\n    None = 0,\n    Read = 1,\n}\n");
    assert!(with_key(&named_none, "csharpsquid:S2346").is_empty());
}

#[test]
fn s3597_requires_service_contract_on_operation_methods() {
    let orphan =
        analyze_default("class Repo\n{\n    [OperationContract]\n    void Do(int x) { }\n}\n");
    let flagged = with_key(&orphan, "csharpsquid:S3597");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let contracted = analyze_default(
        "[ServiceContract]\nclass Repo\n{\n    [OperationContract]\n    void Do(int x) { }\n}\n",
    );
    assert!(with_key(&contracted, "csharpsquid:S3597").is_empty());
}

#[test]
fn s3598_flags_one_way_operations_returning_values() {
    let one_way_result = analyze_default(
        "[ServiceContract]\nclass Repo\n{\n    [OperationContract(IsOneWay = true)]\n    int Count(string q) => 1;\n}\n",
    );
    let flagged = with_key(&one_way_result, "csharpsquid:S3598");
    assert_eq!(flagged.len(), 1);

    // Boundary: a void operation may be one-way.
    let one_way_void = analyze_default(
        "[ServiceContract]\nclass Repo\n{\n    [OperationContract(IsOneWay = true)]\n    void Fire(string q) { }\n}\n",
    );
    assert!(with_key(&one_way_void, "csharpsquid:S3598").is_empty());

    // Boundary: without 'IsOneWay' returning is fine.
    let two_way = analyze_default(
        "[ServiceContract]\nclass Repo\n{\n    [OperationContract]\n    int Count(string q) => 1;\n}\n",
    );
    assert!(with_key(&two_way, "csharpsquid:S3598").is_empty());
}

#[test]
fn s3603_flags_pure_void_methods() {
    let pure_void = analyze_default("class C\n{\n    [Pure]\n    void Save(int x) { }\n}\n");
    let flagged = with_key(&pure_void, "csharpsquid:S3603");
    assert_eq!(flagged.len(), 1);

    let pure_value = analyze_default("class C\n{\n    [Pure]\n    int Add(int x) => x;\n}\n");
    assert!(with_key(&pure_value, "csharpsquid:S3603").is_empty());
}

#[test]
fn s4210_requires_stathread_on_winforms_entry_points() {
    let plain_main = analyze_default(
        "using System.Windows.Forms;\nclass Program\n{\n    static void Main() { }\n}\n",
    );
    let flagged = with_key(&plain_main, "csharpsquid:S4210");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 4);

    let decorated_main = analyze_default(
        "using System.Windows.Forms;\nclass Program\n{\n    [STAThread]\n    static void Main() { }\n}\n",
    );
    assert!(with_key(&decorated_main, "csharpsquid:S4210").is_empty());

    // Boundary: outside WinForms an unadorned 'Main' stays clean.
    let console_main = analyze_default("class Program\n{\n    static void Main() { }\n}\n");
    assert!(with_key(&console_main, "csharpsquid:S4210").is_empty());
}

#[test]
fn s4211_flags_conflicting_transparency_annotations() {
    let both = analyze_default("[SecurityCritical]\n[SecuritySafeCritical]\nclass Vault\n{\n}\n");
    let flagged = with_key(&both, "csharpsquid:S4211");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 1);

    // Boundary: either level alone is consistent.
    let critical_only = analyze_default("[SecurityCritical]\nclass Vault\n{\n}\n");
    assert!(with_key(&critical_only, "csharpsquid:S4211").is_empty());
}

#[test]
fn s4212_secures_serialization_constructors() {
    let public_ctor = analyze_default(
        "class Item\n{\n    public Item(SerializationInfo info, StreamingContext ctx) { }\n}\n",
    );
    let flagged = with_key(&public_ctor, "csharpsquid:S4212");
    assert_eq!(flagged.len(), 1);

    // Boundary: protected serialization constructors are the convention.
    let protected_ctor = analyze_default(
        "class Item\n{\n    protected Item(SerializationInfo info, StreamingContext ctx) { }\n}\n",
    );
    assert!(with_key(&protected_ctor, "csharpsquid:S4212").is_empty());

    // Boundary: unrelated two-parameter constructors stay untouched.
    let plain_ctor = analyze_default("class Item\n{\n    public Item(int a, string b) { }\n}\n");
    assert!(with_key(&plain_ctor, "csharpsquid:S4212").is_empty());
}

#[test]
fn s3926_requires_deserialization_hook_for_optional_fields() {
    let unhooked = analyze_default(
        "[Serializable]\nclass Doc\n{\n    [OptionalField]\n    private int version;\n}\n",
    );
    let flagged = with_key(&unhooked, "csharpsquid:S3926");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 4);

    let hooked = analyze_default(
        "[Serializable]\nclass Doc\n{\n    [OptionalField]\n    private int version;\n\n    [OnDeserialized]\n    private void OnFixup(StreamingContext ctx) { }\n}\n",
    );
    assert!(with_key(&hooked, "csharpsquid:S3926").is_empty());
}

#[test]
fn s3927_checks_serialization_callback_shapes() {
    let wrong_shape = analyze_default(
        "class Doc\n{\n    [OnSerializing]\n    void Before(SerializationInfo info) { }\n}\n",
    );
    let flagged = with_key(&wrong_shape, "csharpsquid:S3927");
    assert_eq!(flagged.len(), 1);

    // Boundary: the canonical '(StreamingContext)' shape passes.
    let right_shape = analyze_default(
        "class Doc\n{\n    [OnSerializing]\n    void Before(StreamingContext ctx) { }\n}\n",
    );
    assert!(with_key(&right_shape, "csharpsquid:S3927").is_empty());
}

#[test]
fn s3928_matches_param_name_with_enclosing_parameters() {
    let mismatched = analyze_default(
        "class Guard\n{\n    void Check(int amount)\n    {\n        throw new ArgumentException(\"bad\", \"value\");\n    }\n}\n",
    );
    let flagged = with_key(&mismatched, "csharpsquid:S3928");
    assert_eq!(flagged.len(), 1);

    // Boundary: naming the real parameter stays clean; non-literal
    // arguments are unverifiable and skipped.
    let matched = analyze_default(
        "class Guard\n{\n    void Check(int amount)\n    {\n        throw new ArgumentException(\"bad\", nameof(amount));\n    }\n}\n",
    );
    assert!(with_key(&matched, "csharpsquid:S3928").is_empty());

    let named = analyze_default(
        "class Guard\n{\n    void Check(int amount)\n    {\n        throw new ArgumentException(\"bad\", \"amount\");\n    }\n}\n",
    );
    assert!(with_key(&named, "csharpsquid:S3928").is_empty());
}

#[test]
fn s4581_flags_parameterless_guid_creation() {
    let empty = analyze_default("class C\n{\n    Guid g = new Guid();\n}\n");
    let flagged = with_key(&empty, "csharpsquid:S4581");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.column, 13);

    // Boundary: byte-argument creation and NewGuid stay clean.
    let from_bytes = analyze_default("class C\n{\n    Guid g = new Guid(bytes);\n}\n");
    assert!(with_key(&from_bytes, "csharpsquid:S4581").is_empty());

    let fresh = analyze_default("class C\n{\n    Guid g = Guid.NewGuid();\n}\n");
    assert!(with_key(&fresh, "csharpsquid:S4581").is_empty());
}

#[test]
fn s4260_matches_constructor_argument_names_with_constructors() {
    let unknown_name = analyze_default(
        "class Shape\n{\n    [ConstructorArgument(\"radius\")]\n    public double Width { get; set; }\n}\n",
    );
    let flagged = with_key(&unknown_name, "csharpsquid:S4260");
    assert_eq!(flagged.len(), 1);

    let known_name = analyze_default(
        "class Shape\n{\n    public Shape(double radius) { }\n\n    [ConstructorArgument(\"radius\")]\n    public double Width { get; set; }\n}\n",
    );
    assert!(with_key(&known_name, "csharpsquid:S4260").is_empty());
}

#[test]
fn s4428_requires_export_besides_part_creation_policy() {
    let unexported =
        analyze_default("[PartCreationPolicy(CreationPolicy.NonShared)]\nclass Engine\n{\n}\n");
    let flagged = with_key(&unexported, "csharpsquid:S4428");
    assert_eq!(flagged.len(), 1);

    let exported = analyze_default(
        "[Export]\n[PartCreationPolicy(CreationPolicy.NonShared)]\nclass Engine\n{\n}\n",
    );
    assert!(with_key(&exported, "csharpsquid:S4428").is_empty());
}

#[test]
fn s4423_flags_deprecated_tls_protocols() {
    let deprecated = analyze_default(
        "class Net\n{\n    void Lock()\n    {\n        ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3;\n    }\n}\n",
    );
    let flagged = with_key(&deprecated, "csharpsquid:S4423");
    assert_eq!(flagged.len(), 1);

    // Boundary: modern protocol members stay clean.
    let modern = analyze_default(
        "class Net\n{\n    void Open()\n    {\n        var protocols = SslProtocols.Tls13 | SslProtocols.Tls12;\n    }\n}\n",
    );
    assert!(with_key(&modern, "csharpsquid:S4423").is_empty());
}

#[test]
fn s4790_flags_md5_and_sha1_usage() {
    let weak = analyze_default(
        "using System.Security.Cryptography;\nclass Hash\n{\n    byte[] Bad(byte[] data)\n    {\n        return MD5.Create().ComputeHash(data);\n    }\n}\n",
    );
    let flagged = with_key(&weak, "csharpsquid:S4790");
    assert_eq!(flagged.len(), 1);

    // Boundary: the using import alone is not a usage.
    let imported_only = analyze_default("using System.Security.Cryptography;\nclass Hash\n{\n}\n");
    assert!(with_key(&imported_only, "csharpsquid:S4790").is_empty());
}

#[test]
fn s5542_flags_insecure_cipher_modes_and_padding() {
    let insecure = analyze_default(
        "class Crypto\n{\n    Aes Make()\n    {\n        var aes = Aes.Create();\n        aes.Mode = CipherMode.ECB;\n        aes.Padding = PaddingMode.None;\n        return aes;\n    }\n}\n",
    );
    let flagged = with_key(&insecure, "csharpsquid:S5542");
    assert_eq!(flagged.len(), 2);

    let secure = analyze_default(
        "class Crypto\n{\n    Aes Make()\n    {\n        var aes = Aes.Create();\n        aes.Mode = CipherMode.CBC;\n        aes.Padding = PaddingMode.PKCS7;\n        return aes;\n    }\n}\n",
    );
    assert!(with_key(&secure, "csharpsquid:S5542").is_empty());
}

#[test]
fn s5547_flags_legacy_block_ciphers() {
    let legacy =
        analyze_default("class Vault\n{\n    DES des = DESCryptoServiceProvider.Create();\n}\n");
    let flagged = with_key(&legacy, "csharpsquid:S5547");
    assert_eq!(flagged.len(), 2);

    let robust = analyze_default("class Vault\n{\n    Aes aes = Aes.Create();\n}\n");
    assert!(with_key(&robust, "csharpsquid:S5547").is_empty());
}

#[test]
fn s4426_flags_weak_asymmetric_providers_and_short_keys() {
    let legacy_provider = analyze_default(
        "class Sign\n{\n    RSA Make() => new RSACryptoServiceProvider(1024);\n}\n",
    );
    assert!(!with_key(&legacy_provider, "csharpsquid:S4426").is_empty());

    let short_key = analyze_default(
        "class Sign\n{\n    void Configure(RSA rsa)\n    {\n        rsa.KeySize = 1024;\n    }\n}\n",
    );
    let flagged = with_key(&short_key, "csharpsquid:S4426");
    assert_eq!(flagged.len(), 1);

    // Boundary: 2048 bits meets the floor.
    let adequate_key = analyze_default(
        "class Sign\n{\n    void Configure(RSA rsa)\n    {\n        rsa.KeySize = 2048;\n    }\n}\n",
    );
    assert!(with_key(&adequate_key, "csharpsquid:S4426").is_empty());
}

#[test]
fn s5659_flags_weak_jwt_algorithms_in_token_contexts() {
    let weak = analyze_default(
        "class Auth\n{\n    TokenValidationParameters Make()\n    {\n        return new TokenValidationParameters { ValidAlgorithms = new[] { \"HS256\" } };\n    }\n}\n",
    );
    let flagged = with_key(&weak, "csharpsquid:S5659");
    assert_eq!(flagged.len(), 1);

    // Boundary: strong algorithms stay clean even in token contexts, and
    // weak spellings outside JWT contexts are untouched.
    let strong = analyze_default(
        "class Auth\n{\n    TokenValidationParameters Make()\n    {\n        return new TokenValidationParameters { ValidAlgorithms = new[] { \"RS256\" } };\n    }\n}\n",
    );
    assert!(with_key(&strong, "csharpsquid:S5659").is_empty());

    let outside_jwt = analyze_default("class Codec\n{\n    string Mode() => \"HS256\";\n}\n");
    assert!(with_key(&outside_jwt, "csharpsquid:S5659").is_empty());
}

#[test]
fn s5332_flags_clear_text_url_literals() {
    let clear_text = analyze_default(
        "class Feed\n{\n    string Endpoint() => \"http://api.example.com/v1\";\n}\n",
    );
    let flagged = with_key(&clear_text, "csharpsquid:S5332");
    assert_eq!(flagged.len(), 1);

    // Boundary: encrypted channels, loopback targets, and XML namespaces
    // stay clean.
    let secure = analyze_default(
        "class Feed\n{\n    string Endpoint() => \"https://api.example.com/v1\";\n}\n",
    );
    assert!(with_key(&secure, "csharpsquid:S5332").is_empty());

    let namespace_uri = analyze_default(
        "class Doc\n{\n    string Xmlns() => \"http://www.w3.org/2001/XMLSchema\";\n}\n",
    );
    assert!(with_key(&namespace_uri, "csharpsquid:S5332").is_empty());
}

#[test]
fn s5443_flags_publicly_writable_temp_paths() {
    let public_dir =
        analyze_default("class Scratch\n{\n    string Spot() => \"/tmp/build-cache\";\n}\n");
    let flagged = with_key(&public_dir, "csharpsquid:S5443");
    assert_eq!(flagged.len(), 1);

    // Boundary: app-private locations stay clean.
    let private_dir = analyze_default(
        "class Scratch\n{\n    string Spot() => Path.Combine(appData, \"cache\")\n;\n}\n",
    );
    assert!(with_key(&private_dir, "csharpsquid:S5443").is_empty());
}

#[test]
fn s5445_flags_predictable_temp_file_apis() {
    let predictable = analyze_default(
        "class Upload\n{\n    void Stash()\n    {\n        var path = Path.GetTempFileName();\n    }\n}\n",
    );
    let flagged = with_key(&predictable, "csharpsquid:S5445");
    assert_eq!(flagged.len(), 1);

    // Boundary: other 'Path' helpers stay untouched.
    let directory_helper =
        analyze_default("class Upload\n{\n    string Dir() => Path.GetTempPath();\n}\n");
    assert!(with_key(&directory_helper, "csharpsquid:S5445").is_empty());
}

#[test]
fn s4507_flags_debugging_enabled_in_config_literals() {
    let debug_on = analyze_default(
        "class Boot\n{\n    string Config() => \"<customErrors mode=\\\"Off\\\"/>\";\n}\n",
    );
    assert_eq!(with_key(&debug_on, "csharpsquid:S4507").len(), 1);

    let compile_debug = analyze_default(
        "class Boot\n{\n    string Config() => \"<compilation debug=\\\"true\\\">\";\n}\n",
    );
    assert_eq!(with_key(&compile_debug, "csharpsquid:S4507").len(), 1);

    // Boundary: production-safe spellings stay clean.
    let remote_only = analyze_default(
        "class Boot\n{\n    string Config() => \"<customErrors mode=\\\"RemoteOnly\\\"/>\";\n}\n",
    );
    assert!(with_key(&remote_only, "csharpsquid:S4507").is_empty());
}

#[test]
fn s5753_flags_request_validation_disabled() {
    let directive = analyze_default(
        "class Pages\n{\n    string Template() => \"<@ Page validateRequest=\\\"false\\\" %>\";\n}\n",
    );
    assert_eq!(with_key(&directive, "csharpsquid:S5753").len(), 1);

    let validate_input = analyze_default(
        "class Legacy\n{\n    void Post()\n    {\n        ValidateInput(false);\n    }\n}\n",
    );
    let flagged = with_key(&validate_input, "csharpsquid:S5753");
    assert_eq!(flagged.len(), 1);

    // Boundary: leaving validation on is clean.
    let enabled = analyze_default(
        "class Legacy\n{\n    void Post()\n    {\n        ValidateInput(true);\n    }\n}\n",
    );
    assert!(with_key(&enabled, "csharpsquid:S5753").is_empty());
}

#[test]
fn s4502_flags_antiforgery_disabled_assignments() {
    let disabled = analyze_default(
        "class Setup\n{\n    void Configure(AntiforgeryOptions options)\n    {\n        options.Antiforgery.Enabled = false;\n    }\n}\n",
    );
    assert_eq!(with_key(&disabled, "csharpsquid:S4502").len(), 1);

    // Boundary: unrelated or enabling assignments stay clean.
    let untouched = analyze_default(
        "class Setup\n{\n    void Configure(AntiforgeryOptions options)\n    {\n        options.Enabled = true;\n    }\n}\n",
    );
    assert!(with_key(&untouched, "csharpsquid:S4502").is_empty());
}

#[test]
fn s5773_flags_typename_handling_beyond_none() {
    let permissive = analyze_default(
        "class Wire\n{\n    JsonSerializerSettings Make() => new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };\n}\n",
    );
    let flagged = with_key(&permissive, "csharpsquid:S5773");
    assert_eq!(flagged.len(), 1);

    // Boundary: 'TypeNameHandling.None' (or no mention) stays clean.
    let safe = analyze_default(
        "class Wire\n{\n    JsonSerializerSettings Make() => new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };\n}\n",
    );
    assert!(with_key(&safe, "csharpsquid:S5773").is_empty());
}

#[test]
fn s5042_flags_unbounded_archive_extraction() {
    let unbounded = analyze_default(
        "class Unpack\n{\n    void Extract(ZipArchive archive, string target)\n    {\n        archive.ExtractToDirectory(target);\n        ZipFile.ExtractToDirectory(archivePath, target);\n    }\n}\n",
    );
    let flagged = with_key(&unbounded, "csharpsquid:S5042");
    assert_eq!(flagged.len(), 2);

    // Boundary: unrelated methods stay untouched.
    let unrelated = analyze_default("class Store\n{\n    void Put(string key) { }\n}\n");
    assert!(with_key(&unrelated, "csharpsquid:S5042").is_empty());
}

#[test]
fn s5122_flags_any_origin_cors_policies() {
    let any_origin = analyze_default(
        "class Api\n{\n    void Configure(CorsPolicyBuilder policy)\n    {\n        policy.AllowAnyOrigin();\n    }\n}\n",
    );
    assert_eq!(with_key(&any_origin, "csharpsquid:S5122").len(), 1);

    let wildcard_header = analyze_default(
        "class Api\n{\n    string Header() => \"Access-Control-Allow-Origin: *\";\n}\n",
    );
    assert_eq!(with_key(&wildcard_header, "csharpsquid:S5122").len(), 1);

    // Boundary: pinned origins stay clean.
    let pinned = analyze_default(
        "class Api\n{\n    void Configure(CorsPolicyBuilder policy)\n    {\n        policy.WithOrigins(\"https://app.example.com\");\n    }\n}\n",
    );
    assert!(with_key(&pinned, "csharpsquid:S5122").is_empty());
}

#[test]
fn s7039_flags_unsafe_csp_sources() {
    let unsafe_inline = analyze_default(
        "class Headers\n{\n    string Policy() => \"Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline'\";\n}\n",
    );
    assert_eq!(with_key(&unsafe_inline, "csharpsquid:S7039").len(), 1);

    // Boundary: a strict policy without unsafe sources stays clean.
    let strict = analyze_default(
        "class Headers\n{\n    string Policy() => \"Content-Security-Policy: default-src 'self'\";\n}\n",
    );
    assert!(with_key(&strict, "csharpsquid:S7039").is_empty());
}

#[test]
fn s5693_flags_oversized_request_body_limits() {
    let oversized = analyze_default(
        "class Limits\n{\n    void Configure(FormOptions options)\n    {\n        options.MultipartBodyLengthLimit = 16777216;\n    }\n}\n",
    );
    let flagged = with_key(&oversized, "csharpsquid:S5693");
    assert_eq!(flagged.len(), 1);

    // Boundary: the tolerated maximum itself passes.
    let at_limit = analyze_default(
        "class Limits\n{\n    void Configure(FormOptions options)\n    {\n        options.MultipartBodyLengthLimit = 8388608;\n    }\n}\n",
    );
    assert!(with_key(&at_limit, "csharpsquid:S5693").is_empty());
}

#[test]
fn s6354_flags_direct_system_clock_reads() {
    let direct =
        analyze_default("class Report\n{\n    string Stamp() => DateTime.UtcNow.ToString();\n}\n");
    let flagged = with_key(&direct, "csharpsquid:S6354");
    assert_eq!(flagged.len(), 1);

    // Boundary: a passed-in value carries no clock read.
    let injected = analyze_default(
        "class Report\n{\n    string Stamp(DateTime when) => when.ToString();\n}\n",
    );
    assert!(with_key(&injected, "csharpsquid:S6354").is_empty());
}

#[test]
fn s6561_flags_datetime_now_near_stopwatch() {
    let timing = analyze_default(
        "class Bench\n{\n    void Measure()\n    {\n        var watch = Stopwatch.StartNew();\n        var started = DateTime.Now;\n        watch.Stop();\n    }\n}\n",
    );
    let flagged = with_key(&timing, "csharpsquid:S6561");
    assert_eq!(flagged.len(), 1);

    // Boundary: 'DateTime.Now' outside a timing method is S6354's
    // territory, not this rule's.
    let untimed =
        analyze_default("class Report\n{\n    string Stamp() => DateTime.Now.ToString();\n}\n");
    assert!(with_key(&untimed, "csharpsquid:S6561").is_empty());
}

#[test]
fn s6562_requires_datetime_kind_on_construction() {
    let unspecified =
        analyze_default("class Clock\n{\n    DateTime Make() => new DateTime(2020, 5, 1);\n}\n");
    let flagged = with_key(&unspecified, "csharpsquid:S6562");
    assert_eq!(flagged.len(), 1);

    // Boundary: an explicit kind settles the meaning.
    let specified = analyze_default(
        "class Clock\n{\n    DateTime Make() => new DateTime(2020, 5, 1, 0, 0, 0, DateTimeKind.Utc);\n}\n",
    );
    assert!(with_key(&specified, "csharpsquid:S6562").is_empty());
}

#[test]
fn s6588_flags_unix_epoch_literals() {
    let epoch =
        analyze_default("class Sync\n{\n    DateTime Epoch() => new DateTime(1970, 1, 1);\n}\n");
    let flagged = with_key(&epoch, "csharpsquid:S6588");
    assert_eq!(flagged.len(), 1);

    // Boundary: any other date stays untouched.
    let other =
        analyze_default("class Sync\n{\n    DateTime Start() => new DateTime(1971, 1, 1);\n}\n");
    assert!(with_key(&other, "csharpsquid:S6588").is_empty());
}

#[test]
fn s6575_flags_windows_time_zone_lookups_without_converter() {
    let windows_only = analyze_default(
        "class Zones\n{\n    TimeZoneInfo Resolve(string id) => TimeZoneInfo.FindSystemTimeZoneById(id);\n}\n",
    );
    let flagged = with_key(&windows_only, "csharpsquid:S6575");
    assert_eq!(flagged.len(), 1);

    // Boundary: once 'TimeZoneConverter' is referenced the migration is
    // considered underway and the file stays clean.
    let converter_present = analyze_default(
        "using TimeZoneConverter;\nclass Zones\n{\n    TimeZoneInfo Resolve(string id) => TZConvert.GetTimeZoneInfo(id);\n}\n",
    );
    assert!(with_key(&converter_present, "csharpsquid:S6575").is_empty());
}

#[test]
fn s6580_flags_culture_less_date_parsing() {
    let culture_less = analyze_default(
        "class Feed\n{\n    DateTime Read(string raw) => DateTime.Parse(raw);\n}\n",
    );
    let flagged = with_key(&culture_less, "csharpsquid:S6580");
    assert_eq!(flagged.len(), 1);

    // Boundary: passing a culture satisfies the rule.
    let cultured = analyze_default(
        "class Feed\n{\n    DateTime Read(string raw) => DateTime.Parse(raw, CultureInfo.InvariantCulture);\n}\n",
    );
    assert!(with_key(&cultured, "csharpsquid:S6580").is_empty());
}

#[test]
fn s6585_flags_hardcoded_date_format_strings() {
    let fixed_format = analyze_default(
        "class Report\n{\n    string Stamp(DateTime when) => when.ToString(\"yyyy-MM-dd HH:mm:ss\");\n}\n",
    );
    let flagged = with_key(&fixed_format, "csharpsquid:S6585");
    assert_eq!(flagged.len(), 1);

    // Boundary: non-date format spellings stay clean.
    let currency_format = analyze_default(
        "class Report\n{\n    string Price(decimal amount) => amount.ToString(\"C\");\n}\n",
    );
    assert!(with_key(&currency_format, "csharpsquid:S6585").is_empty());
}

#[test]
fn s6419_flags_mutable_state_in_azure_function_classes() {
    let mutable = analyze_default(
        "class Greeter\n{\n    private int hits;\n\n    [FunctionName(\"Ping\")]\n    public void Ping() { }\n}\n",
    );
    let flagged = with_key(&mutable, "csharpsquid:S6419");
    assert_eq!(flagged.len(), 1);

    // Boundary: immutable members do not leak state between invocations.
    let immutable = analyze_default(
        "class Greeter\n{\n    private readonly int total = 0;\n\n    [FunctionName(\"Ping\")]\n    public void Ping() { }\n}\n",
    );
    assert!(with_key(&immutable, "csharpsquid:S6419").is_empty());
}

#[test]
fn s6421_requires_try_catch_in_azure_functions() {
    let unprotected = analyze_default(
        "class Greeter\n{\n    [FunctionName(\"Ping\")]\n    public void Ping()\n    {\n        Send();\n    }\n}\n",
    );
    let flagged = with_key(&unprotected, "csharpsquid:S6421");
    assert_eq!(flagged.len(), 1);

    // Boundary: a guarded body satisfies the rule.
    let guarded = analyze_default(
        "class Greeter\n{\n    [FunctionName(\"Ping\")]\n    public void Ping()\n    {\n        try { Send(); } catch (System.Exception ex) { logger.LogError(ex, \"failed\"); }\n    }\n}\n",
    );
    assert!(with_key(&guarded, "csharpsquid:S6421").is_empty());
}

#[test]
fn s6422_flags_blocking_inside_azure_function_classes() {
    let blocking = analyze_default(
        "class OrderFn\n{\n    [FunctionName(\"Run\")]\n    public int Run()\n    {\n        var task = System.Threading.Tasks.Task.Run(() => 1);\n        return task.Result;\n    }\n}\n",
    );
    assert!(!with_key(&blocking, "csharpsquid:S6422").is_empty());

    // Boundary: the same access outside a Function class is not this
    // rule's concern.
    let outside = analyze_default(
        "class Worker\n{\n    public int Block()\n    {\n        var task = System.Threading.Tasks.Task.Run(() => 1);\n        return task.Result;\n    }\n}\n",
    );
    assert!(with_key(&outside, "csharpsquid:S6422").is_empty());
}

#[test]
fn s6423_requires_logging_inside_azure_function_catches() {
    let silent = analyze_default(
        "class OrderFn\n{\n    [FunctionName(\"Run\")]\n    public void Run()\n    {\n        try { Send(); } catch (System.Exception ex) { throw; }\n    }\n}\n",
    );
    let flagged = with_key(&silent, "csharpsquid:S6423");
    assert_eq!(flagged.len(), 1);

    // Boundary: a catch that reports the failure stays clean.
    let reporting = analyze_default(
        "class OrderFn\n{\n    [FunctionName(\"Run\")]\n    public void Run()\n    {\n        try { Send(); } catch (System.Exception ex) { _log.Error(ex, \"run failed\"); }\n    }\n}\n",
    );
    assert!(with_key(&reporting, "csharpsquid:S6423").is_empty());
}

#[test]
fn s6420_flags_clients_built_per_invocation() {
    let per_call = analyze_default(
        "class OrderFn\n{\n    [FunctionName(\"Run\")]\n    public void Run()\n    {\n        var client = new BlobContainerClient(\"conn\", \"orders\");\n    }\n}\n",
    );
    let flagged = with_key(&per_call, "csharpsquid:S6420");
    assert_eq!(flagged.len(), 1);

    // Boundary: the same creation outside a Function is untouched here.
    let elsewhere = analyze_default(
        "class Hosted\n{\n    public void Start()\n    {\n        var client = new BlobContainerClient(\"conn\", \"orders\");\n    }\n}\n",
    );
    assert!(with_key(&elsewhere, "csharpsquid:S6420").is_empty());
}

#[test]
fn s6798_requires_public_on_js_invokable_methods() {
    let mixed = analyze_default(
        "class Counter\n{\n    [JSInvokable]\n    public void Increment() { }\n\n    [JSInvokable]\n    internal void Reset() { }\n}\n",
    );
    let flagged = with_key(&mixed, "csharpsquid:S6798");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 7);
}

#[test]
fn s6930_flags_backslashes_in_route_templates() {
    let windows_route = analyze_default(
        "class UsersController : ControllerBase\n{\n    [HttpGet(\"users\\\\list\")]\n    public IActionResult List() => Ok();\n}\n",
    );
    let flagged = with_key(&windows_route, "csharpsquid:S6930");
    assert_eq!(flagged.len(), 1);

    // Boundary: forward slashes are portable.
    let portable_route = analyze_default(
        "class UsersController : ControllerBase\n{\n    [HttpGet(\"users/list\")]\n    public IActionResult List() => Ok();\n}\n",
    );
    assert!(with_key(&portable_route, "csharpsquid:S6930").is_empty());
}

#[test]
fn s6931_flags_rooted_action_route_templates() {
    let rooted = analyze_default(
        "class UsersController : ControllerBase\n{\n    [HttpGet(\"/users\")]\n    public IActionResult List() => Ok();\n}\n",
    );
    let flagged = with_key(&rooted, "csharpsquid:S6931");
    assert_eq!(flagged.len(), 1);

    // Boundary: tilde-rooted and controller-level templates stay clean.
    let tilde_rooted = analyze_default(
        "class UsersController : ControllerBase\n{\n    [HttpGet(\"~/users\")]\n    public IActionResult List() => Ok();\n}\n",
    );
    assert!(with_key(&tilde_rooted, "csharpsquid:S6931").is_empty());

    let controller_level =
        analyze_default("[Route(\"api/users\")]\nclass UsersController : ControllerBase\n{\n}\n");
    assert!(with_key(&controller_level, "csharpsquid:S6931").is_empty());
}

#[test]
fn s6934_requires_controller_level_route_for_action_templates() {
    let missing = analyze_default(
        "class UsersController\n{\n    [Route(\"list\")]\n    public IActionResult List() => Ok();\n}\n",
    );
    let flagged = with_key(&missing, "csharpsquid:S6934");
    assert_eq!(flagged.len(), 1);

    // Boundary: a controller-level route covers the actions.
    let present = analyze_default(
        "[Route(\"api/users\")]\nclass UsersController\n{\n    [HttpGet(\"list\")]\n    public IActionResult List() => Ok();\n}\n",
    );
    assert!(with_key(&present, "csharpsquid:S6934").is_empty());
}

#[test]
fn s6932_flags_raw_request_reads() {
    let raw_read = analyze_default(
        "class LegacyApi\n{\n    void Read()\n    {\n        var form = Request.Form;\n    }\n}\n",
    );
    let flagged = with_key(&raw_read, "csharpsquid:S6932");
    assert_eq!(flagged.len(), 1);

    // Boundary: other request members stay untouched.
    let headers_only = analyze_default(
        "class LegacyApi\n{\n    void Read()\n    {\n        var agent = Request.Headers[\"User-Agent\"];\n    }\n}\n",
    );
    assert!(with_key(&headers_only, "csharpsquid:S6932").is_empty());
}

#[test]
fn s6961_prefers_controller_base_for_api_controllers() {
    let view_base =
        analyze_default("[ApiController]\nclass ProductsController : Controller\n{\n}\n");
    let flagged = with_key(&view_base, "csharpsquid:S6961");
    assert_eq!(flagged.len(), 1);

    // Boundary: 'ControllerBase' and MVC view controllers without API
    // markers both stay clean.
    let base_ok =
        analyze_default("[ApiController]\nclass ProductsController : ControllerBase\n{\n}\n");
    assert!(with_key(&base_ok, "csharpsquid:S6961").is_empty());

    let mvc_views = analyze_default(
        "class HomeController : Controller\n{\n    public IActionResult Index() => View();\n}\n",
    );
    assert!(with_key(&mvc_views, "csharpsquid:S6961").is_empty());
}

#[test]
fn s6962_flags_hand_rolled_http_clients() {
    let manual =
        analyze_default("class Fetcher\n{\n    HttpClient Make() => new HttpClient();\n}\n");
    let flagged = with_key(&manual, "csharpsquid:S6962");
    assert_eq!(flagged.len(), 1);

    // Boundary: similarly named handlers are not clients.
    let handler =
        analyze_default("class Fetcher\n{\n    var handler = new HttpClientHandler();\n}\n");
    assert!(with_key(&handler, "csharpsquid:S6962").is_empty());
}

#[test]
fn s6965_requires_verb_attributes_on_actions() {
    let unannotated = analyze_default(
        "class WidgetsController\n{\n    public IActionResult Get() => Ok();\n\n    [HttpGet]\n    public IActionResult List() => Ok();\n\n    public void Utility() { }\n}\n",
    );
    let flagged = with_key(&unannotated, "csharpsquid:S6965");
    assert_eq!(flagged.len(), 2);
}

#[test]
fn s6967_requires_model_state_check_for_bound_models() {
    let unchecked = analyze_default(
        "class OrdersController\n{\n    public IActionResult Create(OrderDto dto) => Ok();\n}\n",
    );
    let flagged = with_key(&unchecked, "csharpsquid:S6967");
    assert_eq!(flagged.len(), 1);

    // Boundary: validated bodies and primitive parameters stay clean.
    let checked = analyze_default(
        "class OrdersController\n{\n    public IActionResult Create(OrderDto dto)\n    {\n        if (!ModelState.IsValid) return BadRequest();\n        return Ok();\n    }\n}\n",
    );
    assert!(with_key(&checked, "csharpsquid:S6967").is_empty());

    let primitive = analyze_default(
        "class OrdersController\n{\n    public IActionResult Get(int id) => Ok();\n}\n",
    );
    assert!(with_key(&primitive, "csharpsquid:S6967").is_empty());
}

#[test]
fn s6968_requires_produces_response_type_on_actions() {
    let undeclared = analyze_default(
        "class OrdersController\n{\n    [HttpPost]\n    public IActionResult Create(OrderDto dto) => Ok();\n}\n",
    );
    let flagged = with_key(&undeclared, "csharpsquid:S6968");
    assert_eq!(flagged.len(), 1);

    // Boundary: declared responses and void commands stay clean.
    let declared = analyze_default(
        "class OrdersController\n{\n    [HttpPost]\n    [ProducesResponseType(typeof(OrderDto), 200)]\n    public IActionResult Create(OrderDto dto) => Ok();\n}\n",
    );
    assert!(with_key(&declared, "csharpsquid:S6968").is_empty());

    let void_action = analyze_default(
        "class OrdersController\n{\n    [HttpPost]\n    public void Queue(OrderDto dto) { }\n}\n",
    );
    assert!(with_key(&void_action, "csharpsquid:S6968").is_empty());
}

#[test]
fn s6670_flags_trace_writes() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        Trace.WriteLine(\"m\");\n            System.Diagnostics.Trace.Write(\"x\");\n        logger.Log(\"fine\");\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S6670");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);

    let clean = analyze_default(
        "class A\n{\n    void M()\n    {\n        logger.Log(\"fine\");\n    }\n}\n",
    );
    assert!(with_key(&clean, "csharpsquid:S6670").is_empty());
}

#[test]
fn s6675_flags_trace_switch_gates() {
    let report = analyze_default(
        "class A\n{\n    void M(bool enabled)\n    {\n        Trace.WriteLineIf(traceSwitch.TraceInfo, \"m\");\n        Trace.WriteLineIf(enabled, \"m\");\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S6675");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s6664_limits_log_calls_per_method() {
    let chatty = "class A\n{\n    void M()\n    {\n        logger.LogDebug(\"a\");\n            logger.LogDebug(\"b\");\n        logger.LogDebug(\"c\");\n        logger.LogDebug(\"d\");\n        logger.LogDebug(\"e\");\n    }\n}\n";
    let report = analyze_default(chatty);
    let flagged = with_key(&report, "csharpsquid:S6664");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 3);

    let at_limit = analyze_default(
        "class A\n{\n    void M()\n    {\n        logger.LogDebug(\"a\");\n            logger.LogDebug(\"b\");\n        logger.LogDebug(\"c\");\n        logger.LogDebug(\"d\");\n    }\n}\n",
    );
    assert!(with_key(&at_limit, "csharpsquid:S6664").is_empty());

    let warnings = analyze_default(
        "class A\n{\n    void M()\n    {\n        logger.LogWarning(\"one\");\n            logger.LogWarning(\"two\");\n    }\n}\n",
    );
    assert_eq!(with_key(&warnings, "csharpsquid:S6664").len(), 1);
}

#[test]
fn s6673_flags_swapped_placeholders() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        logger.LogWarning(\"{Y} and {X}\", x, y);\n            logger.LogInformation(\"{X} and {Y}\", x, y);\n        logger.LogError(\"{n} of {m}\", a, b);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S6673");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s6674_flags_malformed_templates() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        logger.LogDebug(\"Broken {Count\");\n            logger.LogInformation(\"oops } done\");\n        logger.LogWarning(\"Fine {Total}\", total);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S6674");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s6677_flags_duplicate_placeholders() {
    let report = analyze_default(
        "class A\n{\n    void M(int id)\n    {\n        logger.LogInformation(\"{Id} then {Id}\", id, id);\n        logger.LogDebug(\"{Name} not {Name2}\", name, name2);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S6677");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s6678_flags_placeholder_casing() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        logger.LogDebug(\"User {userName} did {Action}\", user, action);\n            logger.LogError(\"Code {0} fired\", code);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S6678");
    assert_eq!(flagged.len(), 1);
    assert_eq!(
        flagged[0].message,
        "Rename the placeholder {userName} to PascalCase."
    );
}

#[test]
fn s6667_requires_exception_in_catch_logging() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        try { Run(); } catch (System.Exception ex) { logger.LogError(\"Failed\"); }\n            try { Run(); } catch (System.Exception ex) { logger.LogError(\"Failed {Cause}\", ex); }\n        try { Run(); } catch (System.Exception) { logger.LogError(\"Failed again\"); }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S6667");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s2629_requires_constant_templates() {
    let report = analyze_default(
        "class A\n{\n    void M(string template)\n    {\n        logger.LogDebug(template);\n            logger.LogInformation($\"Value {Value}\");\n        logger.LogWarning(\"Plain {Name}\", name);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2629");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 6);
}

#[test]
fn s1312_shapes_logger_fields() {
    let flagged_report = analyze_default("class A\n{\n    Logger _logger;\n}\n");
    assert_eq!(with_key(&flagged_report, "csharpsquid:S1312").len(), 1);

    let clean = analyze_default("class A\n{\n    private static readonly Logger _logger;\n}\n");
    assert!(with_key(&clean, "csharpsquid:S1312").is_empty());

    let untyped = analyze_default("class A\n{\n    private int count;\n}\n");
    assert!(with_key(&untyped, "csharpsquid:S1312").is_empty());
}

#[test]
fn s3416_names_create_logger_after_type() {
    let report = analyze_default(
        "class Order\n{\n    void M()\n    {\n        var wrong = factory.CreateLogger<Customer>();\n            var right = factory.CreateLogger<Order>();\n        var typed = factory.CreateLogger(typeof(Order));\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3416");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s6672_matches_ilogger_generic_to_type() {
    let report = analyze_default(
        "class Order\n{\n    private ILogger<Customer> wrong;\n    private ILogger<Order> right;\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S6672");
    assert_eq!(flagged.len(), 1);
    assert_eq!(
        flagged[0].message,
        "Use 'ILogger<Order>' for loggers of this type."
    );
}

#[test]
fn s1155_prefers_any_for_emptiness() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        if (items.Count() == 0) return;\n        if (0 == items.Count) return;\n        if (items.Count > 0) return;\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S1155");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 6);
}

#[test]
fn s2275_checks_format_argument_counts() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        text = string.Format(\"{0}-{1}\", one);\n        Console.WriteLine(\"{0}:{1}\", x, y);\n        text = string.Format(CultureInfo.InvariantCulture, \"{0}\", v);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S2275");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}

#[test]
fn s3457_validates_composite_formats() {
    let report = analyze_default(
        "class A\n{\n    void M()\n    {\n        text = string.Format(\"Malformed {0\", one);\n        text = string.Format(\"No slots here\", one);\n        text = string.Format(\"Ok {0}\", one);\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3457");
    assert_eq!(flagged.len(), 2);
    assert_eq!(flagged[0].range.start.line, 5);
    assert_eq!(flagged[1].range.start.line, 6);
}

#[test]
fn s3937_flags_irregular_number_patterns() {
    let report = analyze_default(
        "class A\n{\n    void M(int code)\n    {\n        if (code == 1 || code == 2 || code == 5) { }\n        if (code == 1 || code == 3 || code == 5) { }\n        if (code == 7) { }\n    }\n}\n",
    );
    let flagged = with_key(&report, "csharpsquid:S3937");
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].range.start.line, 5);
}
