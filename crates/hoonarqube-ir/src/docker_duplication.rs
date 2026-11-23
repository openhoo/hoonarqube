//! Evidence for overall duplication density when Dockerfiles have no issue analyzer.
//! The scanner attests to file bytes and Go's native duplicate counts. The store
//! and gate validate the same inventory and sums before accepting that evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    AnalysisReport, FileClassification as Class, FileMetrics, MeasurementStatus as Status,
    ProjectFileMeasurement, ProjectReport,
};

/// An indexed Dockerfile adds physical lines, but no duplicate blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerfileLines {
    pub path: PathBuf,
    pub bytes: u32,
    pub lines: u32,
}

/// A native per-file count after Go's duplication detector has finished.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoDuplicateLines {
    pub path: PathBuf,
    pub duplicated_lines: u64,
}

/// Restricted to regular Dockerfiles and otherwise fully measured Go projects.
/// Other metrics and languages require independent qualification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerDuplicationEvidence {
    pub dockerfiles: Vec<DockerfileLines>,
    pub go_files: Vec<GoDuplicateLines>,
    pub go_duplicated_lines: u64,
}

pub const UNSUPPORTED: &str = "language is unsupported";
/// Wire bound on a measured Dockerfile, also enforced by the scanner.
pub const MAX_DOCKERFILE_BYTES: u32 = 16 * 1024 * 1024;

fn relative(path: &Path) -> Option<&str> {
    let raw = path.to_str()?;
    let key = raw.strip_prefix("./").unwrap_or(raw);
    (!key.contains(['\\', ':'])
        && !key.chars().any(char::is_control)
        && key.split('/').all(|p| !matches!(p, "" | "." | "..")))
    .then_some(key)
}

impl DockerDuplicationEvidence {
    /// Returns (eligible physical lines, duplicated lines) only when the
    /// inventory accounts for every input. Missing and extra rows both fail.
    #[must_use]
    pub fn counters(&self, report: &AnalysisReport) -> Option<(u64, u64)> {
        let p = &report.project;
        if p.complete
            || self.dockerfiles.is_empty()
            || p.duplication.is_some()
            || !p.duplications.is_empty()
        {
            return None;
        }
        let mut inventory = Inventory::new(self, report)?;
        for f in &p.files {
            inventory.consume(f)?;
        }
        inventory.finish(p, self.go_duplicated_lines)
    }

    fn docker_lines(&self, warnings: &[String]) -> Option<BTreeMap<&str, u32>> {
        let mut docker = BTreeMap::new();
        let mut expected = BTreeSet::new();
        for row in &self.dockerfiles {
            let key = relative(&row.path)?;
            if row.path.file_name()? != "Dockerfile"
                || row.bytes > MAX_DOCKERFILE_BYTES
                || row.lines == 0
                || row.lines > row.bytes + 1
                || docker.insert(key, row.lines).is_some()
            {
                return None;
            }
            expected.insert(format!("{}: {UNSUPPORTED}", row.path.display()));
        }
        (expected.len() == warnings.len() && warnings.iter().all(|w| expected.remove(w)))
            .then_some(docker)
    }
}

#[derive(Default)]
struct Inventory<'a> {
    docker: BTreeMap<&'a str, u32>,
    native: BTreeMap<&'a str, u64>,
    reports: BTreeMap<&'a str, &'a FileMetrics>,
    seen: BTreeSet<&'a str>,
    go_files: u64,
    go_lines: u64,
    docker_lines: u64,
    duplicated_lines: u64,
}

impl<'a> Inventory<'a> {
    fn new(e: &'a DockerDuplicationEvidence, r: &'a AnalysisReport) -> Option<Self> {
        let mut inventory = Self {
            docker: e.docker_lines(&r.project.warnings)?,
            ..Self::default()
        };
        for row in &e.go_files {
            if inventory
                .native
                .insert(relative(&row.path)?, row.duplicated_lines)
                .is_some()
            {
                return None;
            }
        }
        for f in &r.files {
            if f.language != "go"
                || inventory
                    .reports
                    .insert(relative(&f.path)?, &f.metrics)
                    .is_some()
            {
                return None;
            }
        }
        Some(inventory)
    }

    fn consume(&mut self, f: &'a ProjectFileMeasurement) -> Option<()> {
        let key = relative(&f.path)?;
        if !self.seen.insert(key) || f.duplication.is_some() {
            return None;
        }
        match (f.classification, f.status) {
            (Class::Source, Status::Unsupported) if is_unsupported(f) => {
                self.docker_lines = self
                    .docker_lines
                    .checked_add(u64::from(self.docker.remove(key)?))?;
            }
            (Class::Test | Class::Source, Status::Complete) => self.consume_go(key, f)?,
            (Class::Excluded | Class::Generated | Class::Vendor, Status::Excluded)
                if f.metrics.is_none() => {}
            _ => return None,
        }
        Some(())
    }

    fn consume_go(&mut self, key: &str, f: &ProjectFileMeasurement) -> Option<()> {
        let m = f.metrics.as_ref()?;
        if f.path.extension().is_none_or(|ext| ext != "go")
            || f.reason.is_some()
            || self.reports.remove(key)? != m
            || m.code_lines > m.lines
            || m.comment_lines > m.lines
        {
            return None;
        }
        if f.classification == Class::Source {
            let count = self.native.remove(key)?;
            if count > u64::from(m.lines) {
                return None;
            }
            self.go_files += 1;
            self.go_lines = self.go_lines.checked_add(u64::from(m.lines))?;
            self.duplicated_lines = self.duplicated_lines.checked_add(count)?;
        }
        Some(())
    }

    fn finish(&self, p: &ProjectReport, expected: u64) -> Option<(u64, u64)> {
        if !self.docker.is_empty()
            || !self.native.is_empty()
            || !self.reports.is_empty()
            || self.duplicated_lines != expected
            || self.go_lines != p.metrics.lines
            || self.go_files != p.metrics.files
        {
            return None;
        }
        Some((
            self.go_lines.checked_add(self.docker_lines)?,
            self.duplicated_lines,
        ))
    }
}

fn is_unsupported(f: &ProjectFileMeasurement) -> bool {
    f.metrics.is_none() && f.reason.as_deref() == Some(UNSUPPORTED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn specimen() -> Value {
        let m = json!({"lines":10,"code_lines":5,"comment_lines":0});
        json!({
            "schema_version":1, "files":[{"path":"lib.go","language":"go","metrics":m,"issues":[]}],
            "project":{"roots":["."],"complete":false, "warnings":["./build/Dockerfile: language is unsupported"],
                "metrics":{"files":1,"lines":10,"code_lines":5,"comment_lines":0},
                "duplication":null,"duplications":[],"files":[
                    {"path":"lib.go","classification":"source","status":"complete","metrics":m},
                    {"path":"./build/Dockerfile","classification":"source","status":"unsupported","reason":UNSUPPORTED}],
                "docker_duplication":{"dockerfiles":[{"path":"./build/Dockerfile","bytes":41,"lines":4}],
                    "go_files":[{"path":"lib.go","duplicated_lines":3}],"go_duplicated_lines":3}}
        })
    }

    fn counters(value: Value) -> Option<(u64, u64)> {
        let r: AnalysisReport = serde_json::from_value(value).ok()?;
        r.project.docker_duplication.as_ref()?.counters(&r)
    }

    #[test]
    fn docker_density_binds_counts_to_a_complete_source_inventory() {
        assert_eq!(counters(specimen()), Some((14, 3)));
        let mut alias = specimen();
        let row = alias["project"]["files"][0].clone();
        alias["project"]["files"].as_array_mut().unwrap().push(row);
        alias["project"]["files"][2]["path"] = json!("./lib.go");
        assert_eq!(counters(alias), None);
        for (pointer, bad) in [
            ("/project/complete", json!(true)),
            ("/project/warnings", json!([])),
            ("/project/warnings/0", json!("read failed")),
            ("/project/files/0/classification", json!("test")),
            ("/project/files/1/status", json!("failed")),
            ("/project/files/1/reason", json!("not measured")),
            ("/project/files/1/classification", json!("excluded")),
            ("/files/0/language", json!("python")),
            ("/files/0/path", json!("another.go")),
            ("/files/0/metrics/lines", json!(9)),
            ("/project/metrics/lines", json!(11)),
            ("/project/docker_duplication/go_files", json!([])),
            (
                "/project/docker_duplication/go_files/0/duplicated_lines",
                json!(11),
            ),
            ("/project/docker_duplication/go_duplicated_lines", json!(4)),
            ("/project/docker_duplication/dockerfiles", json!([])),
            (
                "/project/docker_duplication/dockerfiles/0/path",
                json!("build/../Dockerfile"),
            ),
            (
                "/project/docker_duplication/dockerfiles/0/path",
                json!("build/dockerfile"),
            ),
            ("/project/docker_duplication/dockerfiles/0/bytes", json!(2)),
            ("/project/docker_duplication/dockerfiles/0/lines", json!(0)),
            (
                "/project/docker_duplication/dockerfiles/0/bytes",
                json!(MAX_DOCKERFILE_BYTES + 1),
            ),
        ] {
            let mut report = specimen();
            *report.pointer_mut(pointer).unwrap() = bad;
            assert_eq!(counters(report), None, "{pointer}");
        }
    }
}
