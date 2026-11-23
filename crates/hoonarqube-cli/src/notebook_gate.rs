//! A bounded CI decision for the explicitly selected one-rule notebook profile.
//! It cannot qualify a project report or a different quality profile.
use hoonarqube_ir::assessment::{GateOperator, GateStatus};
use hoonarqube_python::notebook::{self, RULE};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_FILES: usize = 256;
const MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Serialize)]
struct Input {
    path: String,
    /// Digest of bytes actually passed to the inspector, even for a parse refusal.
    sha256: Option<String>,
    violations: Option<usize>,
    diagnostic: Option<String>,
}

fn inspect(path: &Path, seen: &mut BTreeSet<PathBuf>, remaining: &mut usize) -> Input {
    let mut row = Input {
        path: path.to_string_lossy().into_owned(),
        sha256: None,
        violations: None,
        diagnostic: None,
    };
    let mut read = || -> Result<usize, String> {
        if path.to_str().is_none() {
            return Err("path is not valid UTF-8".into());
        }
        let identity = std::fs::canonicalize(path).map_err(|e| e.to_string())?;
        if !seen.insert(identity) {
            return Err("duplicate notebook path".into());
        }
        let raw = super::notebook::read_file(path, *remaining)?;
        *remaining -= raw.len();
        row.sha256 = Some(format!("{:x}", Sha256::digest(raw.as_bytes())));
        Ok(notebook::inspect(&raw)?.findings.len())
    };
    match read() {
        Ok(count) => row.violations = Some(count),
        Err(error) => row.diagnostic = Some(error),
    }
    row
}

#[derive(Serialize)]
struct Decision {
    schema_version: u32,
    profile_rules: [&'static str; 1],
    metric: &'static str,
    operator: GateOperator,
    threshold: u32,
    status: GateStatus,
    actual: Option<usize>,
    inputs: Vec<Input>,
    diagnostic: Option<&'static str>,
}

fn evaluate(paths: &[PathBuf], max: u32) -> Decision {
    let mut gate = Decision {
        schema_version: 1,
        profile_rules: [RULE],
        metric: "violations",
        operator: GateOperator::Lte,
        threshold: max,
        status: GateStatus::Unavailable,
        actual: None,
        inputs: Vec::new(),
        diagnostic: None,
    };
    if paths.is_empty() || paths.len() > MAX_FILES {
        gate.diagnostic = Some("select between 1 and 256 explicit notebook files");
        return gate;
    }
    let mut sorted = paths.iter().collect::<Vec<_>>();
    sorted.sort_unstable();
    let mut remaining = MAX_BYTES;
    let mut seen = BTreeSet::new();
    gate.inputs = sorted
        .into_iter()
        .map(|p| inspect(p, &mut seen, &mut remaining))
        .collect();
    gate.actual = gate.inputs.iter().map(|f| f.violations).sum();
    if let Some(actual) = gate.actual {
        gate.status = if actual <= max as usize {
            GateStatus::Pass
        } else {
            GateStatus::Fail
        };
    } else {
        gate.diagnostic = Some("at least one requested notebook could not be inspected");
    }
    gate
}

pub(super) fn run(paths: &[PathBuf], max: u32, json: bool) -> ExitCode {
    let gate = evaluate(paths, max);
    if json {
        println!(
            "{}",
            serde_json::to_string(&gate).expect("notebook decision serializes")
        );
    } else {
        println!(
            "{RULE} notebook gate: {} (actual: {}, maximum: {max})",
            super::assessment_cli::gate_status_name(gate.status),
            gate.actual
                .map_or_else(|| "unavailable".into(), |v| v.to_string())
        );
        if let Some(reason) = gate.diagnostic {
            eprintln!("{reason}");
        }
        for file in &gate.inputs {
            if let Some(msg) = &file.diagnostic {
                eprintln!("{}: {msg}", file.path);
            } else if let Some(n) = file.violations.filter(|v| *v > 0) {
                println!("{}: {n} findings", file.path);
            }
        }
    }
    match gate.status {
        GateStatus::Pass => ExitCode::SUCCESS,
        GateStatus::Fail => ExitCode::from(1),
        GateStatus::Unavailable | GateStatus::NoValue => ExitCode::from(2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_path;
    use std::fs;
    #[test]
    fn any_uninspected_input_invalidates_a_known_positive_and_a_known_zero() {
        let root = temp_path("notebook-gate");
        fs::create_dir(&root).unwrap();
        let file = root.join("valid.ipynb");
        let mk = |stmt: &str| {
            serde_json::json!({"nbformat":4,"metadata":{"language_info":{"name":"python"}},
            "cells":[{"cell_type":"code","source":stmt}]})
            .to_string()
        };
        fs::write(&file, mk("import asyncio\nasyncio.create_task(f())")).unwrap();
        let one = std::slice::from_ref(&file);
        assert_eq!(evaluate(one, 0).status, GateStatus::Fail);
        assert_eq!(evaluate(one, 1).status, GateStatus::Pass);
        for other in [
            root.join("./valid.ipynb"),
            root.join("missing.ipynb"),
            root.clone(),
        ] {
            let status = evaluate(&[file.clone(), other], 10);
            assert_eq!(status.status, GateStatus::Unavailable);
            assert_eq!(status.actual, None);
        }
        fs::write(&file, mk("keep = None")).unwrap();
        assert_eq!(
            evaluate(&[file, root.join("missing.ipynb")], 0).actual,
            None
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn oversized_or_empty_input_sets_do_not_read_an_arbitrary_prefix() {
        for paths in [
            &[][..],
            &vec![PathBuf::from("not-opened.ipynb"); MAX_FILES + 1],
        ] {
            let result = evaluate(paths, 0);
            assert_eq!(result.status, GateStatus::Unavailable);
            assert!(result.actual.is_none() && result.inputs.is_empty());
        }
    }
    #[test]
    fn exceeding_remaining_byte_budget_does_not_hash_or_count_the_file() {
        let file = temp_path("notebook-budget").with_extension("ipynb");
        fs::write(&file, br#"{"nbformat":4,"metadata":{},"cells":[]}"#).unwrap();
        let mut budget = 3;
        let row = inspect(&file, &mut BTreeSet::new(), &mut budget);
        assert!(
            row.diagnostic.unwrap().contains("budget")
                && row.violations.is_none()
                && row.sha256.is_none()
        );
        assert_eq!(budget, 3);
        fs::remove_file(file).unwrap();
    }
}
