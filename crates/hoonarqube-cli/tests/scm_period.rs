//! Period dates are analysis timestamps; a Git revision is not a clock.
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::process::Command;

fn git(root: &Path, args: &[&str], time: &str) -> String {
    let out = Command::new("git")
        .args(["-c", "core.hooksPath=", "-c", "commit.gpgSign=false"])
        .args(args)
        .current_dir(root)
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", time)
        .output()
        .unwrap();
    assert!(out.status.success(), "{:?}", out.stderr);
    String::from_utf8(out.stdout).unwrap().trim().into()
}

fn scan(root: &Path, args: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
        .current_dir(root)
        .args(["analyze", "src.js", "--json", "--profile", "sonar-parity"])
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        serde_json::from_slice(&out.stdout).unwrap(),
    )
}

#[test]
fn specific_analysis_uses_committer_time_strictly_after_selected_snapshot() {
    let root = std::env::temp_dir().join(format!(
        "hq-period-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let base_time = "2020-01-01T00:00:00Z";
    let new_time = "2021-01-01T00:00:00Z";
    git(&root, &["init", "-q"], base_time);
    fs::write(root.join("src.js"), "export const previous = 1;\n").unwrap();
    git(&root, &["add", "src.js"], base_time);
    git(&root, &["commit", "-qm", "baseline"], base_time);
    let base = git(&root, &["rev-parse", "HEAD"], base_time);
    assert_eq!(scan(&root, &["--write-baseline", "base.json"]).0, 0);
    fs::write(
        root.join("src.js"),
        "export   const previous = 1;\nexport const next = Math.random();\n",
    )
    .unwrap();
    git(&root, &["commit", "-qam", "candidate"], new_time);
    fs::write(root.join("gate.json"),json!({"schema_version":1,"conditions":[{"metric":"community_26_9_violations","scope":"new_code","operator":"lte","threshold":0}]}).to_string()).unwrap();
    for (time, want, lines) in [
        (1_609_459_199_999_i64, 1, json!([2, 3])),
        (1_609_459_200_000, 0, json!([])),
    ] {
        fs::write(
            root.join("period.json"),
            json!({"analysis_id":"analysis-1","revision":base,"timestamp_ms":time}).to_string(),
        )
        .unwrap();
        let (code, report) = scan(
            &root,
            &[
                "--baseline",
                "base.json",
                "--specific-analysis",
                "period.json",
                "--quality-gate",
                "gate.json",
            ],
        );
        assert_eq!(code, want, "{}", report["assessment"]);
        let inventory = &report["assessment"]["new_code"]["changed_source_lines"];
        let got = inventory
            .get(0)
            .map_or_else(|| json!([]), |e| e["lines"].clone());
        assert_eq!(got, lines);
        assert_eq!(
            report["assessment"]["gate"]["conditions"][0]["actual"],
            f64::from(want)
        );
    }
    fs::write(root.join("src.js"), "export const dirty = 2;\n").unwrap();
    let (code, report) = scan(
        &root,
        &[
            "--baseline",
            "base.json",
            "--specific-analysis",
            "period.json",
            "--quality-gate",
            "gate.json",
        ],
    );
    assert_eq!(code, 2);
    assert_eq!(report["assessment"]["gate"]["status"], "unavailable");
    assert!(report["assessment"]["new_code"]["changed_source_lines"].is_null());
    fs::remove_dir_all(root).unwrap();
}
