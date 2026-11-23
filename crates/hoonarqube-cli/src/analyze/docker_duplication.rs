//! Measure the line denominator for Dockerfiles without claiming issue coverage.
use std::{fs, path::Path};

use hoonarqube_core::source_facts::read_bounded_source;
use hoonarqube_ir::docker_duplication::{
    DockerDuplicationEvidence, DockerfileLines, GoDuplicateLines, UNSUPPORTED,
};
use hoonarqube_ir::{
    AnalysisReport, FileClassification, MeasurementStatus, ProjectFileMeasurement,
};

use super::ProjectAnalysisOptions;

pub(super) fn measure(path: &Path) -> Option<DockerfileLines> {
    if path.file_name()? != "Dockerfile" || !fs::symlink_metadata(path).ok()?.is_file() {
        return None;
    }
    let source = read_bounded_source(path).ok()?;
    if source.contains('\0') {
        return None;
    }
    let bytes = u32::try_from(source.len()).ok()?;
    let mut lines = 1u32;
    let mut previous = 0;
    for byte in source.bytes() {
        if byte == b'\r' || (byte == b'\n' && previous != b'\r') {
            lines += 1;
        }
        previous = byte;
    }
    Some(DockerfileLines {
        path: path.to_owned(),
        bytes,
        lines,
    })
}

pub(super) fn attach(
    report: &mut AnalysisReport,
    dockerfiles: Vec<DockerfileLines>,
    options: &ProjectAnalysisOptions,
) {
    if dockerfiles.is_empty() {
        return;
    }
    let p = &mut report.project;
    let native_complete = p.complete
        && options.duplication == hoonarqube_core::duplication::DuplicationOptions::default();
    let go_duplicated_lines = p.duplication.take().map(|d| d.duplicated_lines);
    p.duplications.clear();
    let mut go_files = Vec::new();
    for f in &mut p.files {
        if let Some(d) = f.duplication.take() {
            go_files.push(GoDuplicateLines {
                path: f.path.clone(),
                duplicated_lines: d.duplicated_lines,
            });
        }
    }
    for row in &dockerfiles {
        p.warnings
            .push(format!("{}: {UNSUPPORTED}", row.path.display()));
        p.files.push(ProjectFileMeasurement {
            path: row.path.clone(),
            classification: FileClassification::Source,
            status: MeasurementStatus::Unsupported,
            metrics: None,
            duplication: None,
            reason: Some(UNSUPPORTED.to_owned()),
        });
    }
    p.complete = false;
    p.warnings.sort();
    p.warnings.dedup();
    p.files.sort_by(|l, r| l.path.cmp(&r.path));
    if native_complete && let Some(go_duplicated_lines) = go_duplicated_lines {
        let evidence = DockerDuplicationEvidence {
            dockerfiles,
            go_files,
            go_duplicated_lines,
        };
        if evidence.counters(report).is_some() {
            report.project.docker_duplication = Some(evidence);
        }
    }
}
