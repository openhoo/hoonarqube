use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "csharpsquid:S1006";
const REMOVE: &str =
    "Remove the default parameter value to match the signature of overridden method.";
const ACTION: &str = "csharpsquid:S1006=csharp.s1006.synchronize-default";
const LOCAL: &str = "namespace Triage;\nclass B { public virtual int M(int x) => x; }\nclass D : B { public override int M(int x = 2) => x; }\n";
const BASE: &str = "namespace Triage;\npublic class B { public virtual int M(int x) => x; }\n";
const DERIVED: &str =
    "namespace Triage;\npublic class D : B { public override int M(int x = 2) => x; }\n";

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s1006-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("owned fixture directory");
        Self(path)
    }

    fn write(&self, name: &str, source: &str) {
        std::fs::write(self.0.join(name), source).expect("fixture source");
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.0.join(name)).expect("source readback")
    }

    fn cli(&self, argv: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(argv)
            .output()
            .expect("actual CLI")
    }

    fn analyze(&self, format: &str, paths: &[&str]) -> Value {
        let mut argv = vec![
            "analyze",
            "--profile",
            "sonar-parity",
            "--format",
            format,
            "--",
        ];
        argv.extend(paths);
        document(&self.cli(&argv), 0)
    }

    fn dotnet(&self, argv: &[&str]) -> Output {
        let executable = std::env::var_os("HOONARQUBE_DOTNET")
            .map_or_else(|| PathBuf::from("dotnet"), PathBuf::from);
        let output = Command::new(executable)
            .current_dir(&self.0)
            .args(argv)
            .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
            .env("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1")
            .env("DOTNET_NOLOGO", "1")
            .output()
            .expect(".NET 10 SDK/runtime required for S1006 safety regression");
        assert!(output.status.success(), "{output:?}");
        output
    }

    fn prepare_project(&self, source: &str) {
        self.write("Control.cs", source);
        self.write(
            "Control.csproj",
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><EnableDefaultCompileItems>false</EnableDefaultCompileItems><AssemblyName>S1006Runtime</AssemblyName><TreatWarningsAsErrors>true</TreatWarningsAsErrors></PropertyGroup><ItemGroup><Compile Include=\"Control.cs\" /></ItemGroup></Project>\n",
        );
        self.write(
            "NuGet.Config",
            "<configuration><packageSources><clear /></packageSources></configuration>\n",
        );
        self.dotnet(&[
            "restore",
            "Control.csproj",
            "--configfile",
            "NuGet.Config",
            "--disable-parallel",
            "--nologo",
        ]);
    }

    fn runtime(&self) -> Output {
        self.dotnet(&[
            "build",
            "Control.csproj",
            "--no-restore",
            "--disable-build-servers",
            "--nologo",
            "-t:Rebuild",
            "--output",
            "compiled",
        ]);
        self.dotnet(&["compiled/S1006Runtime.dll"])
    }

    fn semantic_report(&self) -> Value {
        let doc = document(
            &self.cli(&[
                "analyze",
                "--profile",
                "sonar-parity",
                "--format",
                "json",
                "--csharp-project",
                "Control.csproj",
                "--allow-project-build",
                "--csharp-timeout-ms",
                "120000",
                "Control.cs",
            ]),
            0,
        );
        assert_eq!(
            doc["parity"]["semantic_context"]["csharp"], "supplied",
            "{doc}"
        );
        doc
    }

    fn semantic_apply(&self, mode: &str) -> Output {
        self.cli(&[
            "fix",
            "--json",
            "--rule",
            KEY,
            "--suggestion",
            ACTION,
            mode,
            "--csharp-project",
            "Control.csproj",
            "--allow-project-build",
            "--csharp-timeout-ms",
            "120000",
            "Control.cs",
        ])
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn document(output: &Output, exit: i32) -> Value {
    assert_eq!(output.status.code(), Some(exit), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("complete JSON")
}

fn targets<'a>(report: &'a Value, format: &str) -> Vec<&'a Value> {
    if format == "json" {
        assert_eq!(report["project"]["complete"], true);
        report["files"]
            .as_array()
            .expect("native files")
            .iter()
            .flat_map(|file| file["issues"].as_array().expect("native issues"))
            .filter(|issue| issue["rule_key"] == KEY)
            .collect()
    } else {
        report["issues"]
            .as_array()
            .expect("Generic issues")
            .iter()
            .filter(|issue| issue["ruleId"] == KEY)
            .collect()
    }
}

fn removal(report: &Value, format: &str, path: &str, span: (u32, u32, u32)) {
    let issues = targets(report, format);
    assert_eq!(issues.len(), 1, "{issues:?}");
    let (line, start, end) = span;
    if format == "json" {
        assert_eq!(issues[0]["message"], REMOVE);
        assert_eq!(
            issues[0]["range"],
            json!({"start":{"line":line,"column":start},"end":{"line":line,"column":end}})
        );
        for key in ["fix", "alternatives", "flows"] {
            assert!(issues[0].get(key).is_none());
        }
    } else {
        assert_eq!(
            issues[0]["primaryLocation"],
            json!({"filePath":path,"message":REMOVE,"textRange":{"startLine":line,"startColumn":start,"endLine":line,"endColumn":end}})
        );
        assert!(issues[0].get("secondaryLocations").is_none());
        let descriptor = report["rules"]
            .as_array()
            .expect("descriptors")
            .iter()
            .find(|rule| rule["id"] == KEY)
            .expect("new S1006 descriptor");
        assert_eq!(
            descriptor,
            &json!({"cleanCodeAttribute":"CLEAR","description":"Hoonarqube finding for `csharpsquid:S1006`.","engineId":"hoonarqube","id":KEY,"impacts":[{"severity":"HIGH","softwareQuality":"MAINTAINABILITY"}],"name":KEY,"severity":"CRITICAL","type":"CODE_SMELL"})
        );
    }
}

#[test]
fn csharp_s1006_added_default_cli_has_exact_native_and_generic_identity_in_all_profiles() {
    let fixture = Fixture::new("profiles");
    fixture.write("Control.cs", LOCAL);
    for profile in [
        "default",
        "sonar-parity",
        "recommended",
        "extended",
        "strict",
    ] {
        for format in ["json", "sonar"] {
            let mut argv = vec!["analyze", "--format", format];
            if profile != "default" {
                argv.extend(["--profile", profile]);
            }
            argv.extend(["--", "Control.cs"]);
            let first = document(&fixture.cli(&argv), 0);
            removal(&first, format, "Control.cs", (3, 42, 45));
            assert_eq!(first, document(&fixture.cli(&argv), 0));
        }
    }
    assert_eq!(fixture.read("Control.cs"), LOCAL.as_bytes());
}

#[test]
fn csharp_s1006_added_default_cli_resolves_indexed_bases_and_refuses_out_of_scope_base() {
    let fixture = Fixture::new("indexed");
    fixture.write("Base.cs", BASE);
    fixture.write("Derived.cs", DERIVED);
    for format in ["json", "sonar"] {
        removal(
            &fixture.analyze(format, &["Base.cs", "Derived.cs"]),
            format,
            "Derived.cs",
            (2, 49, 52),
        );
        assert!(targets(&fixture.analyze(format, &["Derived.cs"]), format).is_empty());
        fixture.write("Derived.cs", "namespace Triage;\npublic class D : B { public override int M(string x = \"x\") => x.Length; }\n");
        assert!(targets(&fixture.analyze(format, &["Base.cs", "Derived.cs"]), format).is_empty());
        fixture.write("Derived.cs", DERIVED);
    }
    assert_eq!(fixture.read("Base.cs"), BASE.as_bytes());
    assert_eq!(fixture.read("Derived.cs"), DERIVED.as_bytes());
}

#[test]
fn csharp_s1006_added_default_cli_keeps_first_difference_and_trivia_coordinates() {
    let fixture = Fixture::new("boundaries");
    for (source, span) in [
        (
            "namespace Triage;\nclass B { public virtual int M(int a, int b = 1) => a + b; }\nclass D : B { public override int M(int a = 2, int b = 3) => a + b; }\n",
            (3, 42, 45),
        ),
        (
            "namespace Triage;\nclass B { public virtual int M(int a, int b) => a + b; }\nclass D : B { public override int M(int a = 2, int b = 3) => a + b; }\n",
            (3, 42, 45),
        ),
        (
            "namespace Triage; // π\r\nclass B { public virtual int M(int x) => x; }\r\nclass D : B { /* π */ public override int M(int x = /* note */ 2) => x; }\r\n",
            (3, 50, 64),
        ),
    ] {
        fixture.write("Control.cs", source);
        for format in ["json", "sonar"] {
            removal(
                &fixture.analyze(format, &["Control.cs"]),
                format,
                "Control.cs",
                span,
            );
        }
        assert_eq!(fixture.read("Control.cs"), source.as_bytes());
    }
}

#[test]
fn csharp_s1006_added_default_cli_keeps_existing_differences_and_clean_controls() {
    let fixture = Fixture::new("existing");
    let source = "namespace Triage;\nclass B { public virtual int Changed(int x = 1) => x; public virtual int Dropped(int x = 1) => x; public virtual int Match(int x = 1) => x; public virtual int Required(int x) => x; public virtual int Hidden(int x) => x; }\nclass D : B { public override int Changed(int x = 2) => x; public override int Dropped(int x) => x; public override int Match(int x = 1) => x; public override int Required(int x) => x; public new int Hidden(int x = 2) => x; }\n";
    fixture.write("Control.cs", source);
    let report = fixture.analyze("json", &["Control.cs"]);
    let found = targets(&report, "json");
    assert_eq!(
        found,
        vec![
            &json!({"rule_key":KEY,"message":"Use the default parameter value defined in the overridden method.","range":{"start":{"line":3,"column":50},"end":{"line":3,"column":51}}}),
            &json!({"rule_key":KEY,"message":"Add the default parameter value defined in the overridden method.","range":{"start":{"line":3,"column":91},"end":{"line":3,"column":92}}})
        ]
    );
    assert_eq!(fixture.read("Control.cs"), source.as_bytes());
}

#[test]
fn csharp_s1006_added_default_cli_without_context_refuses_selected_removal_without_write() {
    let fixture = Fixture::new("refusal");
    fixture.write("Control.cs", LOCAL);
    let before = fixture.analyze("json", &["Control.cs"]);
    removal(&before, "json", "Control.cs", (3, 42, 45));
    for mode in ["--diff", "--apply", "--apply"] {
        let output = fixture.cli(&[
            "fix",
            "--json",
            "--rule",
            KEY,
            "--suggestion",
            ACTION,
            mode,
            "Control.cs",
        ]);
        let refused = document(&output, 1);
        assert_eq!(refused["applied"], 0);
        assert_eq!(refused["mechanical"], 0);
        assert_eq!(refused["files"], json!([]));
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            "selected suggestion csharpsquid:S1006=csharp.s1006.synchronize-default is unavailable\n"
        );
        assert_eq!(fixture.read("Control.cs"), LOCAL.as_bytes());
        assert_eq!(before, fixture.analyze("json", &["Control.cs"]));
    }
}

#[test]
fn csharp_s1006_added_default_semantic_explicit_arguments_preserve_compiler_and_runtime() {
    let fixture = Fixture::new("semantic-safe");
    let source = "using System;\nnamespace Triage;\npublic class B { public virtual int M(int x) => x; }\npublic class D : B { public override int M(int x = 2) => x; public int M(string x) => x.Length; }\npublic static class Program { public static void Main() { D d = new(); B b = d; Console.WriteLine($\"{d.M(2)}:{b.M(2)}:{d.M(\"abc\")}\"); } }\n";
    fixture.prepare_project(source);
    let before = fixture.runtime();
    assert_eq!(before.stdout, b"2:2:3\n");
    assert!(before.stderr.is_empty());
    let report = fixture.semantic_report();
    let issues = targets(&report, "json");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0]["message"], REMOVE);
    assert!(issues[0].get("fix").is_none());
    assert!(
        issues[0]["alternatives"]
            .as_array()
            .expect("semantic alternatives")
            .iter()
            .any(|action| action["id"] == "csharp.s1006.synchronize-default")
    );
    let preview = fixture.semantic_apply("--diff");
    assert!(preview.status.success(), "{preview:?}");
    assert_eq!(fixture.read("Control.cs"), source.as_bytes());
    let applied = document(&fixture.semantic_apply("--apply"), 0);
    assert_eq!(applied["applied"], 1, "{applied}");
    let expected = source.replacen("int x = 2", "int x", 1);
    assert_eq!(fixture.read("Control.cs"), expected.as_bytes());
    let after = fixture.runtime();
    assert_eq!(before.status.code(), after.status.code());
    assert_eq!(before.stdout, after.stdout);
    assert_eq!(before.stderr, after.stderr);
    assert!(targets(&fixture.semantic_report(), "json").is_empty());
    let repeated = document(&fixture.semantic_apply("--apply"), 1);
    assert_eq!(repeated["applied"], 0);
    assert_eq!(fixture.read("Control.cs"), expected.as_bytes());
}

#[test]
fn csharp_s1006_added_default_semantic_omitted_derived_argument_refuses_without_write() {
    let fixture = Fixture::new("semantic-omitted");
    let source = "using System;\nnamespace Triage;\npublic class B { public virtual int M(int x) => x; }\npublic class D : B { public override int M(int x = 2) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M()); } }\n";
    fixture.prepare_project(source);
    let before = fixture.runtime();
    assert_eq!(before.stdout, b"2\n");
    let report = fixture.semantic_report();
    assert_eq!(targets(&report, "json").len(), 1);
    for _ in 0..2 {
        let refused = document(&fixture.semantic_apply("--apply"), 1);
        assert_eq!(refused["applied"], 0, "{refused}");
        assert_eq!(fixture.read("Control.cs"), source.as_bytes());
        let after = fixture.runtime();
        assert_eq!(before.status.code(), after.status.code());
        assert_eq!(before.stdout, after.stdout);
        assert_eq!(before.stderr, after.stderr);
    }
}

fn local_overload_source(base_methods: &str, method: &str) -> String {
    format!("namespace Triage;\nclass B {{ {base_methods} }}\nclass D : B {{ {method} }}\n")
}

#[test]
fn csharp_s1006_local_overload_cli_matching_defaults_ignore_type_ref_count_and_generic_decoys() {
    let fixture = Fixture::new("overload-clean");
    for (matching, decoy, method) in [
        (
            "public virtual int M(int x = 1) => x;",
            "public virtual int M(string x) => x.Length;",
            "public override int M(int x = 1) => x;",
        ),
        (
            "public virtual int M(int x = 1) => x;",
            "public virtual int M(string x = \"hi\") => x.Length;",
            "public override int M(int x = 1) => x;",
        ),
        (
            "public virtual int M(int x = 1) => x;",
            "public virtual int M(ref int x) => x;",
            "public override int M(int x = 1) => x;",
        ),
        (
            "public virtual int M(int x = 1) => x;",
            "public virtual int M(int x, int y) => x + y;",
            "public override int M(int x = 1) => x;",
        ),
        (
            "public virtual int M(int x = 1) => x;",
            "public virtual int M<T>(int x) => x;",
            "public override int M(int x = 1) => x;",
        ),
        (
            "public virtual int M<T>(int x = 1) => x;",
            "public virtual int M(int x) => x;",
            "public override int M<T>(int x = 1) => x;",
        ),
        (
            "public virtual int M<T>(int x = 1) => x;",
            "public virtual int M<T, U>(int x) => x;",
            "public override int M<T>(int x = 1) => x;",
        ),
    ] {
        for methods in [format!("{matching} {decoy}"), format!("{decoy} {matching}")] {
            let source = local_overload_source(&methods, method);
            fixture.write("Control.cs", &source);
            for format in ["json", "sonar"] {
                assert!(targets(&fixture.analyze(format, &["Control.cs"]), format).is_empty());
            }
            assert_eq!(fixture.read("Control.cs"), source.as_bytes());
        }
    }
}

#[test]
fn csharp_s1006_local_overload_cli_added_defaults_use_the_matching_signature_in_both_orders() {
    let fixture = Fixture::new("overload-added");
    for (matching, decoy, method, span) in [
        (
            "public virtual int M(int x) => x;",
            "public virtual int M(string x) => x.Length;",
            "public override int M(int x = 2) => x;",
            (3, 42, 45),
        ),
        (
            "public virtual int M(int x) => x;",
            "public virtual int M(string x = \"x\") => x.Length;",
            "public override int M(int x = 2) => x;",
            (3, 42, 45),
        ),
        (
            "public virtual int M<T>(int x) => x;",
            "public virtual int M(int x = 1) => x;",
            "public override int M<T>(int x = 2) => x;",
            (3, 45, 48),
        ),
        (
            "public virtual int M<T>(int x) => x;",
            "public virtual int M<T, U>(int x = 2) => x;",
            "public override int M<T>(int x = 1) => x;",
            (3, 45, 48),
        ),
    ] {
        for methods in [format!("{matching} {decoy}"), format!("{decoy} {matching}")] {
            let source = local_overload_source(&methods, method);
            fixture.write("Control.cs", &source);
            for format in ["json", "sonar"] {
                removal(
                    &fixture.analyze(format, &["Control.cs"]),
                    format,
                    "Control.cs",
                    span,
                );
            }
            assert_eq!(fixture.read("Control.cs"), source.as_bytes());
        }
    }
}

#[test]
fn csharp_s1006_local_overload_cli_changed_and_dropped_defaults_keep_exact_identity() {
    let fixture = Fixture::new("overload-existing");
    for methods in [
        "public virtual int M(int x = 1) => x; public virtual int M(string x) => x.Length;",
        "public virtual int M(string x) => x.Length; public virtual int M(int x = 1) => x;",
    ] {
        for (method, message, start, end) in [
            (
                "public override int M(int x = 2) => x;",
                "Use the default parameter value defined in the overridden method.",
                44,
                45,
            ),
            (
                "public override int M(int x) => x;",
                "Add the default parameter value defined in the overridden method.",
                40,
                41,
            ),
        ] {
            let source = local_overload_source(methods, method);
            fixture.write("Control.cs", &source);
            let report = fixture.analyze("json", &["Control.cs"]);
            assert_eq!(
                targets(&report, "json"),
                vec![&json!({
                    "rule_key":KEY,"message":message,"range":{"start":{"line":3,"column":start},"end":{"line":3,"column":end}}
                })]
            );
            assert_eq!(fixture.read("Control.cs"), source.as_bytes());
        }
    }
}

#[test]
fn csharp_s1006_local_overload_compiler_controls_preserve_matching_and_added_defaults() {
    let fixture = Fixture::new("overload-compiled");
    let source = "using System;\nnamespace Triage;\npublic class B { public virtual int M(int x = 1) => x; public virtual int M(string x) => x.Length; public virtual int G<T>(int x = 1) => x; public virtual int G<T, U>(int x) => x; public virtual int R(int x = 1) => x; public virtual int R(ref int x) => x; public virtual int C(int x = 1) => x; public virtual int C(int x, int y) => x + y; public virtual int Added<T>(int x) => x; public virtual int Added<T, U>(int x = 2) => x; }\npublic class D : B { public override int M(int x = 1) => x; public override int G<T>(int x = 1) => x; public override int R(int x = 1) => x; public override int C(int x = 1) => x; public override int Added<T>(int x = 1) => x; }\npublic static class Program { public static void Main() { D d = new(); Console.WriteLine($\"{d.M(1)}:{d.G<int>(1)}:{d.R(1)}:{d.C(1)}:{d.Added<int>(1)}\"); } }\n";
    fixture.prepare_project(source);
    let before = fixture.runtime();
    assert_eq!(before.stdout, b"1:1:1:1:1\n");
    assert!(before.stderr.is_empty());
    let native = fixture.analyze("json", &["Control.cs"]);
    let issues = targets(&native, "json");
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert_eq!(issues[0]["message"], REMOVE);
    assert_eq!(issues[0]["range"]["start"]["line"], 4);
    let semantic = fixture.semantic_report();
    assert_eq!(targets(&semantic, "json").len(), 1);
    assert_eq!(fixture.read("Control.cs"), source.as_bytes());
    let after = fixture.runtime();
    assert_eq!(before.status.code(), after.status.code());
    assert_eq!(before.stdout, after.stdout);
    assert_eq!(before.stderr, after.stderr);
}

fn assert_local_generic_cli_difference(
    source: &str,
    message: Option<&str>,
    span: Option<(u32, u32, u32)>,
) {
    let fixture = Fixture::new("generic-identity");
    fixture.write("Control.cs", source);
    for format in ["json", "sonar"] {
        let report = fixture.analyze(format, &["Control.cs"]);
        let issues = targets(&report, format);
        if let Some(message) = message {
            let (line, start, end) = span.expect("known generic finding span");
            assert_eq!(issues.len(), 1, "{issues:?}");
            let expected = if format == "json" {
                json!({"rule_key":KEY,"message":message,"range":{"start":{"line":line,"column":start},"end":{"line":line,"column":end}}})
            } else {
                json!({"ruleId":KEY,"primaryLocation":{"filePath":"Control.cs","message":message,"textRange":{"startLine":line,"startColumn":start,"endLine":line,"endColumn":end}}})
            };
            assert_eq!(issues[0], &expected);
        } else {
            assert!(issues.is_empty(), "{issues:?}");
        }
        assert_eq!(report, fixture.analyze(format, &["Control.cs"]));
    }
    assert_eq!(fixture.read("Control.cs"), source.as_bytes());
}

#[test]
fn csharp_s1006_local_generic_identity_preserves_scalar_default_differences() {
    for (source, message, span) in [
        (
            "using System;\nnamespace Triage;\npublic class B { public virtual T M<T>(T x = default) => x; }\npublic class D : B { public override U M<U>(U x) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M<int>(1)); } }\n",
            Some("Add the default parameter value defined in the overridden method."),
            Some((4, 46, 47)),
        ),
        (
            "using System;\nnamespace Triage;\npublic class B { public virtual T M<T>(T x = default) => x; }\npublic class D : B { public override U M<U>(U x = default) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M<int>(1)); } }\n",
            None,
            None,
        ),
        (
            "using System;\nnamespace Triage;\npublic class B<T> { public virtual T M(T x = default) => x; }\npublic class D : B<int> { public override int M(int x) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M(1)); } }\n",
            Some("Add the default parameter value defined in the overridden method."),
            Some((4, 52, 53)),
        ),
        (
            "using System;\nnamespace Triage;\npublic class B<T> { public virtual T M(T x = default) => x; }\npublic class D : B<int> { public override int M(int x = default) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M(1)); } }\n",
            None,
            None,
        ),
        (
            "using System;\nnamespace Triage;\npublic class B { public virtual T M<T>(T x) => x; }\npublic class D : B { public override U M<U>(U x = default) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M<int>(1)); } }\n",
            Some("Remove the default parameter value to match the signature of overridden method."),
            Some((4, 48, 57)),
        ),
        (
            "using System;\nnamespace Triage;\npublic class B<T> { public virtual T M(T x) => x; }\npublic class D : B<int> { public override int M(int x = default) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M(1)); } }\n",
            Some("Remove the default parameter value to match the signature of overridden method."),
            Some((4, 54, 63)),
        ),
        (
            "using System;\nnamespace Triage;\npublic class B<T> { public virtual T M(T x = default) => x; }\npublic class D : B<int> { public override int M(int x = 2) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M(1)); } }\n",
            Some("Use the default parameter value defined in the overridden method."),
            Some((4, 56, 57)),
        ),
    ] {
        assert_local_generic_cli_difference(source, message, span);
    }
}

#[test]
fn csharp_s1006_local_generic_identity_preserves_composite_signatures_and_decoys() {
    for (source, message, span) in [
        (
            "using System;\nnamespace Triage;\npublic class B { public virtual T[] M<T>(T[] x = null) => x; }\npublic class D : B { public override U[] M<U>(U[] x) => x; }\n",
            Some("Add the default parameter value defined in the overridden method."),
            Some((4, 50, 51)),
        ),
        (
            "using System;\nnamespace Triage;\npublic class B { public virtual System.Collections.Generic.List<T> M<T>(System.Collections.Generic.List<T> x = null) => x; }\npublic class D : B { public override System.Collections.Generic.List<U> M<U>(System.Collections.Generic.List<U> x) => x; }\n",
            Some("Add the default parameter value defined in the overridden method."),
            Some((4, 112, 113)),
        ),
        (
            "using System;\nnamespace Triage;\npublic class B<T> { public virtual T[] M(T[] x = null) => x; }\npublic class D : B<int> { public override int[] M(int[] x) => x; }\n",
            Some("Add the default parameter value defined in the overridden method."),
            Some((4, 56, 57)),
        ),
        (
            "using System;\nnamespace Triage;\npublic class B<T> { public virtual T M(T x = default) => x; public virtual int M(string x) => x.Length; }\npublic class D : B<int> { public override int M(int x) => x; }\n",
            Some("Add the default parameter value defined in the overridden method."),
            Some((4, 52, 53)),
        ),
        (
            "using System;\nnamespace Triage;\npublic class B<T> { public virtual U M<U>(T x, U y = default) => y; }\npublic class D<T> : B<int> { public override V M<V>(int x, V y) => y; }\n",
            Some("Add the default parameter value defined in the overridden method."),
            Some((4, 61, 62)),
        ),
    ] {
        assert_local_generic_cli_difference(source, message, span);
    }
}

#[test]
fn csharp_s1006_local_generic_identity_controls_compile_and_preserve_runtime() {
    let fixture = Fixture::new("generic-identity-compiled");
    let source = "using System;\nnamespace Triage;\npublic class B { public virtual T M<T>(T x = default) => x; public virtual T Added<T>(T x) => x; public virtual T[] Array<T>(T[] x = null) => x; }\npublic class D : B { public override U M<U>(U x) => x; public override U Added<U>(U x = default) => x; public override U[] Array<U>(U[] x) => x; }\npublic class GenericBase<T> { public virtual T M(T x = default) => x; public virtual T Changed(T x = default) => x; public virtual T Added(T x) => x; public virtual T[] Array(T[] x = null) => x; }\npublic class IntDerived : GenericBase<int> { public override int M(int x) => x; public override int Changed(int x = 2) => x; public override int Added(int x = default) => x; public override int[] Array(int[] x) => x; }\npublic static class Program { public static void Main() { D d = new(); IntDerived i = new(); Console.WriteLine($\"{d.M<int>(1)}:{d.Added<int>(1)}:{d.Array<int>(new[] { 1 }).Length}:{i.M(1)}:{i.Changed(1)}:{i.Added(1)}:{i.Array(new[] { 1 }).Length}\"); } }\n";
    fixture.prepare_project(source);
    let before = fixture.runtime();
    assert_eq!(before.stdout, b"1:1:1:1:1:1:1\n");
    assert!(before.stderr.is_empty());
    let native = fixture.analyze("json", &["Control.cs"]);
    let found = targets(&native, "json");
    assert_eq!(found.len(), 7, "{found:?}");
    let count = |message: &str| {
        found
            .iter()
            .filter(|issue| issue["message"] == message)
            .count()
    };
    assert_eq!(
        count("Add the default parameter value defined in the overridden method."),
        4
    );
    assert_eq!(count(REMOVE), 2);
    assert_eq!(
        count("Use the default parameter value defined in the overridden method."),
        1
    );
    let semantic = fixture.semantic_report();
    assert_eq!(targets(&semantic, "json").len(), 7);
    assert_eq!(fixture.read("Control.cs"), source.as_bytes());
    let after = fixture.runtime();
    assert_eq!(before.status.code(), after.status.code());
    assert_eq!(before.stdout, after.stdout);
    assert_eq!(before.stderr, after.stderr);
}

#[test]
fn csharp_s1006_local_generic_scope_controls_compile_and_preserve_exact_findings() {
    let fixture = Fixture::new("generic-scope-compiled");
    let source = "using System;\n#pragma warning disable CS0693\nnamespace Concrete { public sealed class T {} }\nnamespace Triage {\npublic class B<T> { public virtual U Combined<U>(T x, U y = default) => y; public virtual T Shadow<T>(T x = default) => x; public virtual Concrete.T Qualified<U>(Concrete.T x = null, U y = default) => x; }\npublic class D<U> : B<U> { public override V Combined<V>(U x, V y) => y; public override V Shadow<V>(V x) => x; public override Concrete.T Qualified<V>(Concrete.T x, V y = default) => x; }\npublic static class Program { public static void Main() { D<int> d = new(); Console.WriteLine($\"{d.Combined<int>(1, 1)}:{d.Shadow<int>(1)}:{(d.Qualified<int>(new Concrete.T(), 1) is not null ? 1 : 0)}\"); } }\n}\n";
    fixture.prepare_project(source);
    let before = fixture.runtime();
    assert_eq!(before.stdout, b"1:1:1\n");
    assert!(before.stderr.is_empty());
    let report = fixture.analyze("json", &["Control.cs"]);
    let issues = targets(&report, "json");
    let expected = [64, 103, 163].map(|column| json!({"rule_key":KEY,"message":"Add the default parameter value defined in the overridden method.","range":{"start":{"line":6,"column":column},"end":{"line":6,"column":column+1}}}));
    assert_eq!(issues, expected.iter().collect::<Vec<_>>());
    assert_eq!(targets(&fixture.semantic_report(), "json").len(), 3);
    assert_eq!(fixture.read("Control.cs"), source.as_bytes());
    let matching = source
        .replace("V y) =>", "V y = default) =>")
        .replace("V x) =>", "V x = default) =>")
        .replace(
            "Concrete.T x, V y = default",
            "Concrete.T x = null, V y = default",
        );
    fixture.write("Control.cs", &matching);
    assert!(targets(&fixture.analyze("json", &["Control.cs"]), "json").is_empty());
    assert!(targets(&fixture.semantic_report(), "json").is_empty());
    let after = fixture.runtime();
    assert_eq!(before.status.code(), after.status.code());
    assert_eq!(before.stdout, after.stdout);
    assert_eq!(before.stderr, after.stderr);
    assert_eq!(fixture.read("Control.cs"), matching.as_bytes());
}

#[test]
fn csharp_s1006_local_scalar_identity_preserves_exact_bcl_and_alias_findings() {
    for (using, base_type) in [
        ("using System;", "System.Int32"),
        ("using I = global::System.Int32;", "I"),
        ("using S = global::System;", "S.Int32"),
        ("using S = global::System;", "S::Int32"),
        ("using System;", "global::System.Int32"),
    ] {
        let source = format!(
            "{using}\nnamespace Triage;\npublic class B {{ public virtual int M({base_type} x = 1) => x; }}\npublic class D : B {{ public override int M(int x) => x; }}\n"
        );
        assert_local_generic_cli_difference(
            &source,
            Some("Add the default parameter value defined in the overridden method."),
            Some((4, 47, 48)),
        );
        assert_local_generic_cli_difference(
            &source.replace("M(int x)", "M(int x = 2)"),
            Some("Use the default parameter value defined in the overridden method."),
            Some((4, 51, 52)),
        );
        assert_local_generic_cli_difference(
            &source.replace("M(int x)", "M(int x = 1)"),
            None,
            None,
        );
    }
}

#[test]
fn csharp_s1006_local_scalar_identity_compiler_controls_preserve_exact_findings() {
    let fixture = Fixture::new("scalar-identity-compiled");
    let source = "using I = global::System.Int32;\nusing S = global::System;\nnamespace Triage;\npublic class B { public virtual int Qualified(System.Int32 x = 1) => x; public virtual int Alias(I x = 1) => x; public virtual int Namespace(S::Int32 x = 1) => x; public virtual int Changed(I x = 1) => x; }\npublic class D : B { public override int Qualified(int x) => x; public override int Alias(int x) => x; public override int Namespace(int x) => x; public override int Changed(int x = 2) => x; }\npublic static class Program { public static void Main() { D d = new(); global::System.Console.WriteLine($\"{d.Qualified(1)}:{d.Alias(1)}:{d.Namespace(1)}:{d.Changed(1)}\"); } }\n";
    fixture.prepare_project(source);
    let before = fixture.runtime();
    assert_eq!(before.stdout, b"1:1:1:1\n");
    assert!(before.stderr.is_empty());
    let expected = [
        (
            55,
            56,
            "Add the default parameter value defined in the overridden method.",
        ),
        (
            94,
            95,
            "Add the default parameter value defined in the overridden method.",
        ),
        (
            137,
            138,
            "Add the default parameter value defined in the overridden method.",
        ),
        (
            182,
            183,
            "Use the default parameter value defined in the overridden method.",
        ),
    ];
    for format in ["json", "sonar"] {
        let report = fixture.analyze(format, &["Control.cs"]);
        let found = targets(&report, format);
        let exact = expected.map(|(start,end,message)| if format == "json" {json!({"rule_key":KEY,"message":message,"range":{"start":{"line":5,"column":start},"end":{"line":5,"column":end}}})} else {json!({"ruleId":KEY,"primaryLocation":{"filePath":"Control.cs","message":message,"textRange":{"startLine":5,"startColumn":start,"endLine":5,"endColumn":end}}})});
        assert_eq!(found, exact.iter().collect::<Vec<_>>());
        assert_eq!(report, fixture.analyze(format, &["Control.cs"]));
    }
    assert_eq!(fixture.read("Control.cs"), source.as_bytes());
    let matching = source
        .replace("Qualified(int x)", "Qualified(int x = 1)")
        .replace("Alias(int x)", "Alias(int x = 1)")
        .replace("Namespace(int x)", "Namespace(int x = 1)")
        .replace("Changed(int x = 2)", "Changed(int x = 1)");
    fixture.write("Control.cs", &matching);
    for format in ["json", "sonar"] {
        assert!(targets(&fixture.analyze(format, &["Control.cs"]), format).is_empty());
    }
    let after = fixture.runtime();
    assert_eq!(before.status.code(), after.status.code());
    assert_eq!(before.stdout, after.stdout);
    assert_eq!(before.stderr, after.stderr);
    assert_eq!(fixture.read("Control.cs"), matching.as_bytes());
}

#[test]
fn csharp_s1006_local_scalar_identity_compiler_rejects_shadowed_system_decoys() {
    for (prefix, scope_using) in [
        ("namespace Triage.System { public class Int32 {} }\n", ""),
        (
            "namespace Shadow { public class Int32 {} }\n",
            "using System = global::Shadow;\n",
        ),
    ] {
        let matching = "public virtual int M(int x) => x;";
        let decoy = "public virtual int M(System.Int32 x = null) => 1;";
        for methods in [format!("{matching} {decoy}"), format!("{decoy} {matching}")] {
            let fixture = Fixture::new("scalar-system-decoy-compiled");
            let source = format!(
                "{prefix}namespace Triage {{\n{scope_using}public class B {{ {methods} }}\npublic class D : B {{ public override int M(int x = 2) => x; }}\npublic static class Program {{ public static void Main() {{ global::System.Console.WriteLine(new D().M(2)); }} }}\n}}\n"
            );
            fixture.prepare_project(&source);
            let before = fixture.runtime();
            assert_eq!(before.stdout, b"2\n");
            assert!(before.stderr.is_empty());
            for format in ["json", "sonar"] {
                removal(
                    &fixture.analyze(format, &["Control.cs"]),
                    format,
                    "Control.cs",
                    (
                        u32::try_from(prefix.lines().count() + scope_using.lines().count())
                            .expect("short fixture prefix")
                            + 3,
                        49,
                        52,
                    ),
                );
            }
            assert_eq!(fixture.read("Control.cs"), source.as_bytes());
            let clean = source.replace("M(int x = 2)", "M(int x)");
            fixture.write("Control.cs", &clean);
            for format in ["json", "sonar"] {
                assert!(targets(&fixture.analyze(format, &["Control.cs"]), format).is_empty());
            }
            let after = fixture.runtime();
            assert_eq!(before.status.code(), after.status.code());
            assert_eq!(before.stdout, after.stdout);
            assert_eq!(before.stderr, after.stderr);
            assert_eq!(fixture.read("Control.cs"), clean.as_bytes());
        }
    }
}

#[test]
fn csharp_s1006_local_review_inherited_nested_system_preserves_exact_findings_and_runtime() {
    let source = "namespace Triage { public class B { public class System { public class Int32 {} } public virtual int M(System.Int32 x = null) => 1; } public class D : B { public override int M(System.Int32 x) => 1; } public static class Program { public static void Main() { global::System.Console.WriteLine(new D().M(null)); } } }\n";
    let matching = source.replace(
        "public override int M(System.Int32 x)",
        "public override int M(System.Int32 x = null)",
    );
    for (source, message, span) in [
        (
            source,
            Some("Add the default parameter value defined in the overridden method."),
            Some((1, 190, 191)),
        ),
        (matching.as_str(), None, None),
    ] {
        let fixture = Fixture::new("review-inherited-system-compiled");
        fixture.prepare_project(source);
        let runtime = fixture.runtime();
        assert_eq!(runtime.stdout, b"1\n");
        assert!(runtime.stderr.is_empty());
        assert_local_generic_cli_difference(source, message, span);
        assert_eq!(fixture.read("Control.cs"), source.as_bytes());
    }
}

#[test]
fn csharp_s1006_local_review_nullable_value_type_decoys_compile_and_stay_clean() {
    for source in [
        "namespace Triage {\npublic class B {\n  public virtual int M(int? x) => 0;\n  public virtual int M(int x = 1) => x;\n}\npublic class D : B { public override int M(int x = 1) => x; }\npublic static class Program { public static void Main() { global::System.Console.WriteLine(new D().M(1)); } }\n}\n",
        "namespace Triage {\npublic class B {\n  public virtual int M(int x = 1) => x;\n  public virtual int M(int? x) => 0;\n}\npublic class D : B { public override int M(int x = 1) => x; }\npublic static class Program { public static void Main() { global::System.Console.WriteLine(new D().M(1)); } }\n}\n",
    ] {
        let fixture = Fixture::new("review-nullable_value_type_decoys-compiled");
        fixture.prepare_project(source);
        let runtime = fixture.runtime();
        assert_eq!(runtime.stdout, b"1\n");
        assert!(runtime.stderr.is_empty());
        assert_local_generic_cli_difference(source, None, None);
        assert_eq!(fixture.read("Control.cs"), source.as_bytes());
    }
}

#[test]
fn csharp_s1006_local_review_namespace_import_decoys_compile_and_stay_clean() {
    for source in [
        "namespace Left { public class Item {} }\nnamespace Right { public class Item {} }\nnamespace Parent {\nusing Left;\npublic class B {\n  public virtual int M(Item x) => 0;\n  public virtual int M(global::Right.Item x = null) => 1;\n}\n}\nnamespace Child {\nusing Right;\npublic class D : Parent.B { public override int M(Item x = null) => 1; }\npublic static class Program { public static void Main() { global::System.Console.WriteLine(new D().M(new global::Right.Item())); } }\n}\n",
        "namespace Left { public class Item {} }\nnamespace Right { public class Item {} }\nnamespace Parent {\nusing Left;\npublic class B {\n  public virtual int M(global::Right.Item x = null) => 1;\n  public virtual int M(Item x) => 0;\n}\n}\nnamespace Child {\nusing Right;\npublic class D : Parent.B { public override int M(Item x = null) => 1; }\npublic static class Program { public static void Main() { global::System.Console.WriteLine(new D().M(new global::Right.Item())); } }\n}\n",
    ] {
        let fixture = Fixture::new("review-distinct_namespace_import_decoys-compiled");
        fixture.prepare_project(source);
        let runtime = fixture.runtime();
        assert_eq!(runtime.stdout, b"1\n");
        assert!(runtime.stderr.is_empty());
        assert_local_generic_cli_difference(source, None, None);
        assert_eq!(fixture.read("Control.cs"), source.as_bytes());
    }
}
