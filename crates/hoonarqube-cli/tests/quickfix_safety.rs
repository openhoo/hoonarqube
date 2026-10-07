use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-quickfix-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("fixture directory");
        Self(path)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("run hoonarqube")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn unsupported_extension_mechanical_apply_is_refused_without_writing() {
    let fixture = Fixture::new("unsupported");
    let path = fixture.0.join("t.xyz");
    std::fs::write(&path, b"x").expect("fixture");

    let analysis = fixture.run(&["analyze", "--json", "t.xyz"]);
    assert_eq!(analysis.status.code(), Some(2));
    let analysis: serde_json::Value =
        serde_json::from_slice(&analysis.stdout).expect("analysis JSON");
    assert_eq!(analysis["project"]["files"][0]["status"], "unsupported");

    let preview = fixture.run(&["fix", "--diff", "t.xyz"]);
    assert!(preview.status.success());
    assert!(String::from_utf8_lossy(&preview.stdout).contains("+x"));
    assert_eq!(std::fs::read(&path).expect("preview readback"), b"x");

    let apply = fixture.run(&["fix", "--apply", "--json", "t.xyz"]);
    assert_eq!(apply.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&apply.stderr).contains("source is not analyzable"));
    let applied: serde_json::Value = serde_json::from_slice(&apply.stdout).expect("apply JSON");
    assert_eq!(applied["files"][0]["written"], false);
    assert_eq!(applied["mechanical"], 0);
    assert_eq!(std::fs::read(&path).expect("apply readback"), b"x");
}

#[test]
fn supported_extension_mechanical_apply_preserves_source_and_is_idempotent() {
    let fixture = Fixture::new("supported");
    let path = fixture.0.join("t.py");
    std::fs::write(&path, b"x").expect("fixture");

    let preview = fixture.run(&["fix", "--diff", "t.py"]);
    assert!(preview.status.success());
    assert_eq!(std::fs::read(&path).expect("preview readback"), b"x");
    let apply = fixture.run(&["fix", "--apply", "--json", "t.py"]);
    assert!(apply.status.success(), "{:?}", apply);
    let applied: serde_json::Value = serde_json::from_slice(&apply.stdout).expect("apply JSON");
    assert_eq!(applied["files"][0]["written"], true);
    assert_eq!(applied["mechanical"], 1);
    assert_eq!(applied["regressions"], 0);
    assert_eq!(std::fs::read(&path).expect("apply readback"), b"x\n");

    let analysis = fixture.run(&["analyze", "--json", "t.py"]);
    assert!(analysis.status.success());
    let analysis: serde_json::Value =
        serde_json::from_slice(&analysis.stdout).expect("analysis JSON");
    assert_eq!(analysis["project"]["files"][0]["status"], "complete");
    assert!(
        analysis["files"][0]["issues"]
            .as_array()
            .expect("issues")
            .iter()
            .all(|issue| issue["rule_key"] != "python:S113")
    );

    let clean = fixture.run(&["fix", "--apply", "--json", "t.py"]);
    assert!(clean.status.success());
    let clean: serde_json::Value = serde_json::from_slice(&clean.stdout).expect("clean JSON");
    assert_eq!(clean["files"], serde_json::json!([]));
    assert_eq!(std::fs::read(&path).expect("clean readback"), b"x\n");
}

#[test]
fn missing_razor_context_mechanical_apply_is_refused_without_writing() {
    let fixture = Fixture::new("razor");
    let path = fixture.0.join("r.razor");
    std::fs::write(&path, b"hello").expect("fixture");
    let apply = fixture.run(&["fix", "--apply", "--json", "r.razor"]);
    assert_eq!(apply.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&apply.stderr).contains("cannot analyze fixes"));
    assert_eq!(std::fs::read(&path).expect("apply readback"), b"hello");
}

#[test]
fn supported_mechanical_apply_preserves_python_runtime_types_and_effects() {
    let fixture = Fixture::new("runtime");
    let path = fixture.0.join("runtime.py");
    let source =
        b"VALUE = \"preserve trailing spaces  \"\nprint(type(VALUE).__name__, repr(VALUE))";
    std::fs::write(&path, source).expect("fixture");
    let run_python = || {
        Command::new("python3")
            .current_dir(&fixture.0)
            .args(["-B", "runtime.py"])
            .output()
            .expect("Python 3 is required for quickfix runtime qualification")
    };
    let before = run_python();
    assert!(before.status.success());
    assert_eq!(before.stdout, b"str 'preserve trailing spaces  '\n");
    assert!(before.stderr.is_empty());

    let apply = fixture.run(&["fix", "--apply", "--json", "runtime.py"]);
    assert!(apply.status.success(), "{:?}", apply);
    let mut expected = source.to_vec();
    expected.push(b'\n');
    assert_eq!(std::fs::read(&path).expect("apply readback"), expected);
    let after = run_python();
    assert_eq!(before.status.code(), after.status.code());
    assert_eq!(before.stdout, after.stdout);
    assert_eq!(before.stderr, after.stderr);
}
