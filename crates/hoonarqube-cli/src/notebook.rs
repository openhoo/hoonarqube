//! Independent diagnostics: one notebook rule cannot qualify a project gate.
use hoonarqube_python::notebook::{self, RULE};
use std::path::Path;
use std::process::ExitCode;

pub(super) fn read_file(path: &Path, remaining: usize) -> Result<String, String> {
    if !path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("ipynb"))
    {
        return Err("expected a .ipynb file".into());
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("expected a regular notebook file".into());
    }
    let limit = remaining.min(notebook::MAX_JSON_BYTES);
    if metadata.len() > limit as u64 {
        return Err("notebook exceeds the per-file or remaining input budget".into());
    }
    let raw = hoonarqube_core::read_bounded_source(path).map_err(|e| e.to_string())?;
    if raw.len() > limit {
        return Err("notebook exceeds the per-file or remaining input budget".into());
    }
    Ok(raw)
}

pub(super) fn run(path: &Path, json: bool) -> ExitCode {
    let result = read_file(path, notebook::MAX_JSON_BYTES).and_then(|raw| notebook::inspect(&raw));
    if json {
        let (status, inspection, reason) = match &result {
            Ok(report) => ("inspected", Some(report), None),
            Err(msg) => ("unavailable", None, Some(msg)),
        };
        println!(
            "{}",
            serde_json::json!({"schema_version":1,"path":path.to_string_lossy(),"rule":RULE,
            "status":status,"inspection":inspection,"reason":reason})
        );
    } else {
        match &result {
            Ok(report) => {
                println!(
                    "{}: inspected {} code cells for {RULE}; {} findings",
                    path.display(),
                    report.code_cells,
                    report.findings.len()
                );
                for f in &report.findings {
                    println!(
                        "{}:{}:{} (cell {}): {} {}",
                        path.display(),
                        f.range.start.line,
                        f.range.start.column,
                        f.cell_index,
                        f.rule_key,
                        f.message
                    );
                }
            }
            Err(msg) => eprintln!("{}: {RULE} unavailable: {msg}", path.display()),
        }
    }
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}
