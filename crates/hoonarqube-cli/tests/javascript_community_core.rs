use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

const CORE: &str = "community-26.11-javascript-core";
const LEGACY: &str = "sonar-parity";

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "hoonarqube-javascript-core-{label}-{}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        for file in ["case.js", "side.ts"] {
            std::fs::write(
                root.join(file),
                "export function check(value = 42) { return isNaN(value); }\n",
            )
            .unwrap();
        }
        std::fs::write(
            root.join("gate.json"),
            json!({"schema_version":1,"conditions":[{"scope":"overall","metric":"files","operator":"eq","threshold":2}]}).to_string(),
        ).unwrap();
        Self(root)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .unwrap()
    }

    fn scan(&self, profile: &str, opts: &[&str], exit: i32) -> Value {
        let mut args = vec![
            "analyze",
            "case.js",
            "side.ts",
            "--format",
            "json",
            "--profile",
            profile,
            "--cache-dir",
            "cache",
        ];
        args.extend_from_slice(opts);
        let output = self.run(&args);
        assert_eq!(output.status.code(), Some(exit), "{output:?}");
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

fn issues<'a>(report: &'a Value, rule: &str) -> Vec<&'a Value> {
    report["files"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|file| file["issues"].as_array().unwrap())
        .filter(|issue| issue["rule_key"] == rule)
        .collect()
}

fn assert_javascript_only_selection(legacy: &Value, core: &Value) {
    assert_eq!(issues(legacy, "javascript:S1451").len(), 1);
    assert!(issues(core, "javascript:S1451").is_empty());
    assert_eq!(issues(core, "javascript:S7773").len(), 1);
    assert_eq!(
        issues(core, "javascript:S7773"),
        issues(legacy, "javascript:S7773"),
    );
    assert_eq!(issues(core, "typescript:S1451").len(), 1);
    assert_eq!(core["files"][1], legacy["files"][1]);
    assert_eq!(core["project"]["metrics"], legacy["project"]["metrics"]);
    assert_eq!(
        core["partial_rule_selection"]["fallback_languages"],
        json!(["typescript"])
    );
    assert_eq!(core["project"]["warnings"], json!([]));
}

#[test]
fn javascript_core_is_language_scoped_and_keeps_assessments_partial() {
    let fixture = Fixture::new("selection");
    let legacy = fixture.scan(LEGACY, &["--write-baseline", "legacy.json"], 0);
    let core = fixture.scan(CORE, &["--write-baseline", "core.json"], 2);
    assert_javascript_only_selection(&legacy, &core);
    assert!(legacy.get("partial_rule_selection").is_none());
    assert!(core.get("parity").is_none());
    let selection = &core["partial_rule_selection"];
    assert_eq!(selection["profile"], CORE);
    assert_eq!(selection["reference_active_rules"], 200);
    assert_eq!(selection["selected_catalog_keys"], 159);
    assert_eq!(
        selection["missing_catalog_keys"].as_array().unwrap().len(),
        36
    );
    assert_eq!(
        selection["unmapped_parameter_keys"],
        json!([
            "javascript:S2068",
            "javascript:S2999",
            "javascript:S4275",
            "javascript:S5693",
            "javascript:S6418"
        ])
    );

    let assessed = fixture.scan(
        CORE,
        &["--baseline", "core.json", "--quality-gate", "gate.json"],
        2,
    );
    assert_eq!(assessed["files"], core["files"]);
    assert_eq!(assessed["assessment"]["new_code"]["status"], "complete");
    assert_eq!(assessed["assessment"]["gate"]["status"], "unavailable");
    assert_eq!(
        assessed["assessment"]["gate"]["conditions"][0]["actual"],
        Value::Null
    );
    assert_eq!(fixture.scan(LEGACY, &[], 0)["files"], legacy["files"]);

    let mismatch = fixture.scan(CORE, &["--baseline", "legacy.json"], 2);
    assert_eq!(mismatch["assessment"]["new_code"]["status"], "incomplete");
    assert!(
        mismatch["assessment"]["new_code"]["diagnostics"]
            .to_string()
            .contains("incompatible")
    );
    let fix = fixture.run(&["fix", "case.js", "--profile", CORE]);
    assert_eq!(fix.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&fix.stderr).contains("partial selection for analyze only"));
}

#[test]
fn script_core_filters_compiler_backed_findings_for_the_selected_language() {
    let Some(package) = std::env::var_os("HOONARQUBE_TYPESCRIPT_PACKAGE") else {
        eprintln!("requires the pinned TypeScript package (installed in CI)");
        return;
    };
    let fixture = Fixture::new("compiler");
    std::fs::write(
        fixture.0.join("project.json"),
        r#"{"compilerOptions":{"allowJs":true,"checkJs":false,"noEmit":true,"target":"ESNext","module":"ESNext"},"files":["case.js","side.ts"]}"#,
    )
    .unwrap();
    let opts = [
        "--typescript-project",
        "project.json",
        "--typescript-module",
        package.to_str().unwrap(),
    ];
    let legacy = fixture.scan(LEGACY, &opts, 0);
    let core = fixture.scan(CORE, &opts, 2);
    assert_javascript_only_selection(&legacy, &core);
    let ts = fixture.scan("community-26.11-typescript-core", &opts, 2);
    assert_eq!(ts["files"][0], legacy["files"][0]);
    assert!(issues(&ts, "typescript:S1451").is_empty());
    assert_eq!(
        issues(&ts, "typescript:S7773"),
        issues(&legacy, "typescript:S7773")
    );
    assert_eq!(issues(&ts, "typescript:S7773").len(), 1);
}

#[test]
fn typescript_core_selects_only_typescript_and_cannot_certify_gates() {
    let fixture = Fixture::new("typescript-selection");
    let profile = "community-26.11-typescript-core";
    let legacy = fixture.scan(LEGACY, &[], 0);
    let javascript = fixture.scan(CORE, &["--write-baseline", "js.json"], 2);
    let core = fixture.scan(profile, &["--write-baseline", "ts.json"], 2);
    let selection = &core["partial_rule_selection"];
    assert_eq!(selection["profile"], profile);
    assert_eq!(selection["fallback_languages"], json!(["javascript"]));
    assert_ne!(
        selection["membership_sha256"],
        javascript["partial_rule_selection"]["membership_sha256"]
    );
    assert_eq!(selection["reference_active_rules"], 199);
    assert_eq!(selection["selected_catalog_keys"], 148);
    assert_eq!(
        selection["missing_catalog_keys"].as_array().unwrap().len(),
        46
    );
    assert_eq!(
        selection["unmapped_parameter_keys"],
        json!([
            "typescript:S2068",
            "typescript:S2999",
            "typescript:S4275",
            "typescript:S5693",
            "typescript:S6418"
        ])
    );
    assert_eq!(core["files"][0], legacy["files"][0]);
    assert_eq!(issues(&legacy, "typescript:S1451").len(), 1);
    assert!(issues(&core, "typescript:S1451").is_empty());
    assert_eq!(issues(&core, "typescript:S7773").len(), 1);
    assert_eq!(
        issues(&core, "typescript:S7773"),
        issues(&legacy, "typescript:S7773")
    );
    assert_eq!(core["project"]["metrics"], legacy["project"]["metrics"]);
    assert!(core.get("parity").is_none());
    let assessed = fixture.scan(
        profile,
        &["--baseline", "ts.json", "--quality-gate", "gate.json"],
        2,
    );
    assert_eq!(assessed["files"], core["files"]);
    assert_eq!(assessed["assessment"]["new_code"]["status"], "complete");
    assert_eq!(assessed["assessment"]["gate"]["status"], "unavailable");
    assert!(assessed["assessment"]["gate"]["conditions"][0]["actual"].is_null());
    let wrong = fixture.scan(profile, &["--baseline", "js.json"], 2);
    assert_eq!(wrong["assessment"]["new_code"]["status"], "incomplete");
    let fix = fixture.run(&["fix", "side.ts", "--profile", profile]);
    assert_eq!(fix.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&fix.stderr).contains("partial selection for analyze only"));
}
