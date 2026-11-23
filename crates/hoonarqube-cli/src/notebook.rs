//! Independent diagnostics: one notebook rule cannot qualify a project gate.
use hoonarqube_python::notebook::{self, RULE};
use std::path::Path;
use std::process::ExitCode;

fn inspect_file(path: &Path) -> Result<notebook::Inspection, String> {
    if !path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("ipynb"))
    {
        return Err("expected a .ipynb file".into());
    }
    if !std::fs::symlink_metadata(path)
        .map_err(|e| e.to_string())?
        .is_file()
    {
        return Err("expected a regular notebook file".into());
    }
    let raw = hoonarqube_core::read_bounded_source(path).map_err(|e| e.to_string())?;
    notebook::inspect(&raw)
}

pub(super) fn run(path: &Path, json: bool) -> ExitCode {
    let result = inspect_file(path);
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
