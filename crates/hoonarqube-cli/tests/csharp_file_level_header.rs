use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const HEADER: &str = "// Copyright Example\n";
const HEADER_ACTION: &str = "csharpsquid:S1451=csharp.s1451.add-or-update-license-header";
const PROGRAM: &str = r#"#nullable enable
using System;
// Preserve the following program and its effects.
internal static class Program
{
    private static int calls;
    private static int Next() { calls++; return 40; }
    private static void Main()
    {
        var value = Next() + 2;
        Console.WriteLine($"{value}:{calls}:{value.GetType().FullName}");
    }
}
"#;

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-csharp-file-header-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create owned fixture directory");
        Self(path)
    }

    fn write(&self, name: &str, source: &str) {
        std::fs::write(self.0.join(name), source).expect("write fixture");
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.0.join(name)).expect("read exact fixture content")
    }

    fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("run hoonarqube CLI")
    }

    fn analyze(&self, name: &str, format: &str) -> Value {
        document(
            &self.cli(&[
                "analyze",
                name,
                "--csharp-header-format",
                HEADER,
                "--format",
                format,
            ]),
            0,
        )
    }

    fn dotnet(&self, args: &[&str]) -> Output {
        let executable = std::env::var_os("HOONARQUBE_DOTNET")
            .map_or_else(|| PathBuf::from("dotnet"), PathBuf::from);
        let output = Command::new(executable)
            .current_dir(&self.0)
            .args(args)
            .env("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1")
            .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
            .env("DOTNET_NOLOGO", "1")
            .output()
            .expect(".NET 10 SDK/runtime is required for CLI header regression coverage");
        assert_success(&output);
        output
    }

    fn prepare_runtime(&self) {
        self.write(
            "header.csproj",
            r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable><TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>
    <AssemblyName>HeaderRuntime</AssemblyName>
  </PropertyGroup>
  <ItemGroup><Compile Include="Program.cs" /></ItemGroup>
</Project>
"#,
        );
        self.write(
            "NuGet.Config",
            "<configuration><packageSources><clear /></packageSources></configuration>\n",
        );
        self.dotnet(&[
            "restore",
            "header.csproj",
            "--configfile",
            "NuGet.Config",
            "--disable-parallel",
            "--nologo",
        ]);
    }

    fn runtime_stdout(&self) -> Vec<u8> {
        self.dotnet(&[
            "build",
            "header.csproj",
            "--no-restore",
            "--disable-build-servers",
            "--nologo",
            "--configuration",
            "Release",
            "-t:Rebuild",
            "--output",
            "compiled",
        ]);
        let output = self.dotnet(&["compiled/HeaderRuntime.dll"]);
        assert!(output.stderr.is_empty(), "{output:?}");
        output.stdout
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn document(output: &Output, expected_exit: i32) -> Value {
    assert_eq!(output.status.code(), Some(expected_exit), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("complete CLI JSON document")
}

fn header_issues(report: &Value) -> Vec<&Value> {
    report["files"][0]["issues"]
        .as_array()
        .expect("native issues")
        .iter()
        .filter(|issue| issue["rule_key"] == "csharpsquid:S1451")
        .collect()
}

fn assert_file_level_header(report: &Value) {
    assert_eq!(report["project"]["complete"], true);
    let issues = header_issues(report);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0]["range"],
        json!({"start": {"line": 0, "column": 0}, "end": {"line": 0, "column": 0}})
    );
    assert_eq!(
        issues[0]["message"],
        "Add or update the header of this file."
    );
    let actions = issues[0]["alternatives"]
        .as_array()
        .expect("header actions");
    assert_eq!(
        actions.len(),
        1,
        "file-level header must retain its safe action"
    );
    assert_eq!(
        actions[0]["id"],
        "csharp.s1451.add-or-update-license-header"
    );
    assert_eq!(
        actions[0]["fix"]["edits"],
        json!([{"range": {"start": {"line": 1, "column": 0}, "end": {"line": 1, "column": 0}},
                "replacement": HEADER}])
    );
}

#[test]
fn configured_header_has_file_level_json_and_sonar_identity_with_concrete_action() {
    let fixture = Fixture::new("identity");
    let source = "class C { public int Value => 42; }\n";
    fixture.write("Header.cs", source);
    assert_file_level_header(&fixture.analyze("Header.cs", "json"));
    let sonar = fixture.analyze("Header.cs", "sonar");
    let issues: Vec<_> = sonar["issues"]
        .as_array()
        .expect("generic issues")
        .iter()
        .filter(|issue| issue["ruleId"] == "csharpsquid:S1451")
        .collect();
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0]["primaryLocation"],
        json!({"filePath": "Header.cs", "message": "Add or update the header of this file."})
    );

    fixture.write("Header.cs", &format!("{HEADER}{source}"));
    assert!(header_issues(&fixture.analyze("Header.cs", "json")).is_empty());
    let compliant = fixture.analyze("Header.cs", "sonar");
    assert!(
        compliant["issues"]
            .as_array()
            .expect("compliant generic issues")
            .iter()
            .all(|issue| issue["ruleId"] != "csharpsquid:S1451")
    );
}

#[test]
fn header_diff_apply_preserves_compiled_runtime_types_and_effects() {
    let fixture = Fixture::new("runtime");
    fixture.write("Program.cs", PROGRAM);
    fixture.prepare_runtime();
    let before = fixture.runtime_stdout();
    assert_eq!(
        String::from_utf8_lossy(&before).trim_end(),
        "42:1:System.Int32"
    );
    assert_file_level_header(&fixture.analyze("Program.cs", "json"));

    let preview = fixture.cli(&[
        "fix",
        "Program.cs",
        "--csharp-header-format",
        HEADER,
        "--suggestion",
        HEADER_ACTION,
        "--diff",
    ]);
    assert_success(&preview);
    assert!(String::from_utf8_lossy(&preview.stdout).contains("+// Copyright Example"));
    assert_eq!(fixture.read("Program.cs"), PROGRAM);

    let applied = document(
        &fixture.cli(&[
            "fix",
            "Program.cs",
            "--csharp-header-format",
            HEADER,
            "--suggestion",
            HEADER_ACTION,
            "--apply",
            "--diff",
            "--json",
        ]),
        0,
    );
    assert_eq!(applied["applied"], 1);
    assert_eq!(applied["verified"], 1);
    assert_eq!(applied["unverified"], 0);
    assert_eq!(applied["regressions"], 0);
    assert_eq!(fixture.read("Program.cs"), format!("{HEADER}{PROGRAM}"));
    let reanalyzed = fixture.analyze("Program.cs", "json");
    assert_eq!(reanalyzed["project"]["complete"], true);
    assert!(header_issues(&reanalyzed).is_empty());

    let clean = document(
        &fixture.cli(&[
            "fix",
            "Program.cs",
            "--csharp-header-format",
            HEADER,
            "--rule",
            "csharpsquid:S1451",
            "--apply",
            "--json",
        ]),
        0,
    );
    assert_eq!(clean["files"], json!([]));
    assert_eq!(fixture.read("Program.cs"), format!("{HEADER}{PROGRAM}"));
    assert_eq!(fixture.runtime_stdout(), before);
}

#[test]
fn header_apply_refuses_unsafe_templates_and_malformed_source_without_writing() {
    let fixture = Fixture::new("refusal");
    for (name, source, header) in [
        ("Unsafe.cs", "class C { }\n", "using System;"),
        ("Disabled.cs", "class C { }\n", ""),
        ("Malformed.cs", "\tclass {{{ ;;; ???\n", HEADER),
    ] {
        fixture.write(name, source);
        let refused = document(
            &fixture.cli(&[
                "fix",
                name,
                "--csharp-header-format",
                header,
                "--suggestion",
                HEADER_ACTION,
                "--apply",
                "--json",
            ]),
            1,
        );
        assert_eq!(fixture.read(name), source);
        assert_eq!(refused["applied"], 0);
        assert!(
            !refused["warnings"]
                .as_array()
                .expect("refusal warnings")
                .is_empty()
        );
    }
}

#[test]
fn header_conflict_skips_the_entire_header_fix_and_retains_its_finding() {
    let fixture = Fixture::new("conflict");
    let source = "// int removed = 1;\nclass C { int Value => 42; }\n";
    fixture.write("Conflict.cs", source);
    assert_file_level_header(&fixture.analyze("Conflict.cs", "json"));
    let args = [
        "fix",
        "Conflict.cs",
        "--csharp-header-format",
        HEADER,
        "--suggestion",
        HEADER_ACTION,
        "--suggestion",
        "csharpsquid:S125=csharp.s125.remove-commented-out-code",
    ];
    let mut preview_args = args.to_vec();
    preview_args.extend(["--diff", "--json"]);
    let preview = document(&fixture.cli(&preview_args), 1);
    assert_eq!(preview["files"][0]["skipped"], 1);
    assert_eq!(fixture.read("Conflict.cs"), source);

    let mut apply_args = args.to_vec();
    apply_args.extend(["--apply", "--json"]);
    let applied = document(&fixture.cli(&apply_args), 1);
    assert_eq!(applied["applied"], 1);
    assert_eq!(applied["skipped"], 1);
    assert_eq!(applied["verified"], 1);
    assert_eq!(applied["unverified"], 0);
    assert_eq!(applied["regressions"], 0);
    assert!(
        applied["warnings"]
            .as_array()
            .expect("conflict warnings")
            .iter()
            .any(|warning| {
                warning
                    .as_str()
                    .is_some_and(|message| message.contains("conflicting"))
            })
    );
    assert_eq!(
        fixture.read("Conflict.cs"),
        "class C { int Value => 42; }\n"
    );
    assert_file_level_header(&fixture.analyze("Conflict.cs", "json"));
}
