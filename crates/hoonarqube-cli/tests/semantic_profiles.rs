use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);

fn cli() -> std::ffi::OsString {
    // Qualify the same committed regressions against a frozen pre-fix CLI.
    std::env::var_os("HOONARQUBE_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_hoonarqube").into())
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "hoonarqube-semantic-profiles-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join("src")).unwrap();
        Self(root)
    }

    fn write(&self, path: &str, source: &str) {
        std::fs::write(self.0.join(path), source).unwrap();
    }

    fn analyze(&self, profile: &str, context: &[&str]) -> Value {
        let output = Command::new(cli())
            .current_dir(&self.0)
            .args([
                "analyze",
                "src",
                "--profile",
                profile,
                "--format",
                "json",
                "--exclude",
                "**/obj/**",
                "--exclude",
                "**/bin/**",
                "--duplication-exclude",
                "**",
            ])
            .args(context)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["project"]["complete"], true, "{report}");
        report
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn native_findings(report: &Value) -> Vec<String> {
    let mut findings: Vec<_> = report["files"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|file| {
            file["issues"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|issue| {
                    issue["rule_key"]
                        .as_str()
                        .unwrap()
                        .starts_with("hoonarqube-")
                })
                .map(|issue| serde_json::to_string(&(&file["path"], issue)).unwrap())
        })
        .collect();
    findings.sort();
    findings
}

#[test]
fn typescript_context_keeps_native_profiles_and_clean_controls() {
    let Some(package) = std::env::var_os("HOONARQUBE_TYPESCRIPT_PACKAGE") else {
        eprintln!("requires the pinned TypeScript package (installed in CI)");
        return;
    };
    let package = package.to_str().unwrap();
    let fixture = Fixture::new();
    fixture.write("smoke-tsconfig.json", r#"{"compilerOptions":{"allowJs":true,"checkJs":false,"noEmit":true,"target":"ESNext","module":"ESNext"},"include":["src/**/*"]}"#);
    for extension in ["js", "ts"] {
        fixture.write(
            &format!("src/bad.{extension}"),
            "new Promise(async resolve => { resolve(1); });\n",
        );
        fixture.write(
            &format!("src/good.{extension}"),
            "new Promise(resolve => { resolve(1); });\n",
        );
    }
    let context = [
        "--typescript-project",
        "smoke-tsconfig.json",
        "--typescript-module",
        package,
    ];
    for profile in ["recommended", "strict"] {
        let syntax = fixture.analyze(profile, &[]);
        let semantic = fixture.analyze(profile, &context);
        let expected = native_findings(&syntax);
        assert_eq!(expected.len(), 2, "one native positive per language");
        assert_eq!(
            native_findings(&semantic),
            expected,
            "{profile} native identities"
        );
        for file in semantic["files"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|file| file["path"].as_str().unwrap().contains("good."))
        {
            assert!(file["issues"].as_array().unwrap().iter().all(|issue| {
                !issue["rule_key"]
                    .as_str()
                    .unwrap()
                    .starts_with("hoonarqube-")
            }));
        }
        assert_eq!(
            native_findings(&fixture.analyze(profile, &context)),
            expected,
            "cached native identities"
        );
    }
    assert!(native_findings(&fixture.analyze("sonar-parity", &context)).is_empty());
}

#[test]
fn csharp_context_keeps_cumulative_native_profiles() {
    if Command::new("dotnet").arg("--version").output().is_err() {
        eprintln!("requires the .NET SDK (installed in CI)");
        return;
    }
    let fixture = Fixture::new();
    fixture.write("src/NativeRules.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net10.0</TargetFramework><EnableNETAnalyzers>false</EnableNETAnalyzers></PropertyGroup></Project>");
    fixture.write("src/Bad.cs", "using System.IO; using System.Threading.Tasks; using System.Text.Json; class Bad { void Read(Stream stream, byte[] buffer) { stream.Read(buffer, 0, buffer.Length); } async Task<bool> End(StreamReader reader) { await Task.Yield(); return reader.EndOfStream; } JsonElement Parse(string text) { return JsonDocument.Parse(text).RootElement; } }\n");
    fixture.write("src/Good.cs", "using System.IO; class Good { int Read(Stream stream, byte[] buffer) { return stream.Read(buffer, 0, buffer.Length); } }\n");
    let context = [
        "--csharp-project",
        "src/NativeRules.csproj",
        "--allow-project-build",
        "--csharp-timeout-ms",
        "60000",
    ];
    for (profile, count) in [("recommended", 2), ("strict", 3)] {
        let expected = native_findings(&fixture.analyze(profile, &[]));
        assert_eq!(expected.len(), count, "{profile} positive controls");
        let semantic = fixture.analyze(profile, &context);
        assert_eq!(
            native_findings(&semantic),
            expected,
            "{profile} native identities"
        );
        assert_eq!(
            native_findings(&fixture.analyze(profile, &context)),
            expected,
            "cached native identities"
        );
    }
    assert!(native_findings(&fixture.analyze("sonar-parity", &context)).is_empty());
}

#[test]
fn missing_compiler_context_remains_incomplete() {
    let fixture = Fixture::new();
    fixture.write(
        "src/bad.ts",
        "new Promise(async resolve => { resolve(1); });\n",
    );
    let output = Command::new(cli())
        .current_dir(&fixture.0)
        .args([
            "analyze",
            "src",
            "--profile",
            "strict",
            "--format",
            "json",
            "--typescript-project",
            "missing.json",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["project"]["complete"], false, "{report}");
}

#[test]
fn python_context_keeps_native_findings_and_caller_paths() {
    let fixture = Fixture::new();
    fixture.write(
        "src/bad.py",
        "import subprocess\nassert subprocess.call(['backup']) == 0\n",
    );
    fixture.write(
        "src/good.py",
        "import subprocess\nresult = subprocess.call(['backup'])\nassert result == 0\n",
    );
    let syntax = fixture.analyze("strict", &[]);
    let expected = native_findings(&syntax);
    assert_eq!(expected.len(), 1);
    let context = ["--python-project", "src"];
    let semantic = fixture.analyze("strict", &context);
    assert_eq!(native_findings(&semantic), expected);
    assert_eq!(semantic["files"][0]["path"], "src/bad.py");
    assert_eq!(semantic["files"][1]["path"], "src/good.py");
    assert_eq!(
        native_findings(&fixture.analyze("strict", &context)),
        expected
    );
    assert!(native_findings(&fixture.analyze("sonar-parity", &context)).is_empty());
}
