//! Static inspection of saved nbformat 4 Python code cells. This API reports one
//! rule only and supplies no project metrics or quality-gate decision.
mod bounded;
mod locations;
use crate::engine::bindings::KnownBindings;
use crate::rules::unreferenced_asyncio_tasks::unreferenced_task;
use crate::support::for_each_stmt;
use locations::Projection;
use ruff_python_parser::{Mode, ParseOptions, parse_cells_unchecked};
use ruff_text_size::Ranged;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

const MAX_CELLS: usize = 4096;
const MAX_PROJECTED_BYTES: usize = 1024 * 1024;
const MAX_FRAGMENTS: usize = 65_536;
/// Maximum byte length of an original JSON notebook accepted by this inspector.
pub const MAX_JSON_BYTES: usize = 4 * 1024 * 1024;

/// Community rule selected for this inspection.
pub const RULE: &str = "ipython:S7502";
/// Message captured with the pinned positive control for this rule.
pub const MESSAGE: &str = "Save this task in a variable to prevent premature garbage collection.";

#[derive(Deserialize)]
struct Notebook<'a> {
    nbformat: u32,
    metadata: Metadata,
    #[serde(borrow)]
    cells: bounded::Bounded<Cell<'a>, MAX_CELLS>,
}

#[derive(Default, Deserialize)]
struct Metadata {
    language_info: Option<LanguageInfo>,
    kernelspec: Option<KernelSpec>,
}
#[derive(Deserialize)]
struct LanguageInfo {
    name: String,
}
#[derive(Deserialize)]
struct KernelSpec {
    language: Option<String>,
}
#[derive(Default, Deserialize)]
struct CellMetadata {
    vscode: Option<Vscode>,
}
#[derive(Deserialize)]
struct Vscode {
    #[serde(rename = "languageId")]
    language_id: Option<String>,
}

#[derive(Deserialize)]
struct Cell<'a> {
    #[serde(rename = "cell_type")]
    kind: String,
    #[serde(default)]
    metadata: CellMetadata,
    #[serde(borrow)]
    source: &'a RawValue,
}

/// One primary range in the original notebook JSON, in physical UTF-16 columns.
#[derive(Debug, Serialize)]
pub struct Finding {
    pub rule_key: &'static str,
    pub message: &'static str,
    /// Index into the saved notebook's cells array, including non-code cells.
    pub cell_index: usize,
    pub range: hoonarqube_ir::Range,
}
/// Result for the one explicitly selected rule, without project measures.
#[derive(Debug, Serialize)]
pub struct Inspection {
    pub cells: usize,
    pub code_cells: usize,
    pub findings: Vec<Finding>,
}

/// Inspect the notebook in saved cell order without running code.
///
/// # Errors
/// Returns an error rather than a silent negative for unsupported languages,
/// syntax, sizes or source spans that cannot be represented faithfully.
pub fn inspect(raw: &str) -> Result<Inspection, String> {
    if raw.len() > MAX_JSON_BYTES {
        return Err("notebook exceeds the 4 MiB inspection limit".into());
    }
    let doc: Notebook<'_> = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    if doc.nbformat != 4 {
        return Err("inspection requires nbformat 4".into());
    }
    let cells = doc.cells.0.len();
    let mut p = Projection::default();
    for (index, cell) in doc.cells.0.iter().enumerate() {
        match cell.kind.as_str() {
            "raw" | "markdown" => continue,
            "code" => {}
            _ => return Err(format!("unrecognized cell type at index {index}")),
        }
        if cell
            .metadata
            .vscode
            .as_ref()
            .and_then(|v| v.language_id.as_deref())
            .is_some_and(|id| !id.eq_ignore_ascii_case("python"))
        {
            return Err(format!("non-Python cell at index {index}"));
        }
        p.push(raw, index, cell.source)?;
    }
    let code_cells = p.cells.len();
    let mut languages = [
        doc.metadata.language_info.as_ref().map(|x| x.name.as_str()),
        doc.metadata
            .kernelspec
            .as_ref()
            .and_then(|x| x.language.as_deref()),
    ]
    .into_iter()
    .flatten()
    .peekable();
    if (code_cells > 0 && languages.peek().is_none())
        || languages.any(|s| !s.eq_ignore_ascii_case("python"))
    {
        return Err("Python notebook language is absent, unsupported or conflicting".into());
    }
    let parsed = parse_cells_unchecked(
        &p.text,
        p.cells.iter().copied(),
        &ParseOptions::from(Mode::Ipython),
    );
    if !parsed.errors().is_empty() || !parsed.unsupported_syntax_errors().is_empty() {
        return Err("one or more code cells have unsupported IPython syntax".into());
    }
    let bindings = KnownBindings::build(&parsed);
    let mut ranges = Vec::new();
    for_each_stmt(&parsed.syntax().body, &mut |stmt| {
        if let Some(call) = unreferenced_task(stmt, &bindings) {
            ranges.push(call.func.range());
        }
    });
    Ok(Inspection {
        cells,
        code_cells,
        findings: p.findings(raw, ranges)?,
    })
}

#[cfg(test)]
mod tests;
