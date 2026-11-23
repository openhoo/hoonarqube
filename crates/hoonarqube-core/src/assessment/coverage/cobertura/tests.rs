use std::path::{Path, PathBuf};

use hoonarqube_ir::FileClassification;
use hoonarqube_ir::assessment::{AssessmentStatus, CoverageCounter};

use super::super::{CoverageFile, CoverageFormat, CoverageSource, import_coverage};

fn python(path: &str) -> CoverageFile<'_> {
    CoverageFile {
        path: Path::new(path),
        source: "x = 1\ny = 2\n",
        classification: FileClassification::Source,
    }
}

fn line_report(source: &str, filename: &str) -> CoverageSource {
    CoverageSource {
        format: CoverageFormat::Cobertura,
        path: PathBuf::from("coverage.xml"),
        content: format!(
            r#"<coverage lines-valid="1" lines-covered="1" branches-valid="0" branches-covered="0">
  <sources><source>{source}</source></sources>
  <packages><package><classes><class filename="{filename}">
    <methods/><lines><line number="1" hits="1"/></lines>
  </class></classes></package></packages>
</coverage>"#
        ),
    }
}

#[test]
fn joins_cobertura_class_to_a_unique_analyzed_python_path() {
    let root = Path::new("/repo");
    let sources = [python("src/pkg & utils/a.py")];
    for (source, filename) in [
        ("src/pkg &amp; utils", "a.py"),
        ("/repo/src/pkg &amp; utils", "a.py"),
        (r"Z:\ci\checkout", "src/pkg &amp; utils/a.py"),
    ] {
        let report = import_coverage(root, &[line_report(source, filename)], &sources);
        assert_eq!(report.status, AssessmentStatus::Complete, "{source}");
        assert_eq!(report.files[0].path, Path::new("src/pkg & utils/a.py"));
        assert_eq!(report.lines.covered, 1);
        assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    }
}

#[test]
fn rejects_ambiguous_or_outside_cobertura_paths() {
    let root = Path::new("/repo");
    let sources = [python("a.py"), python("src/a.py")];
    for (source, filename, diagnostic) in [
        ("src", "a.py", "ambiguous analyzed Cobertura source path"),
        (".", "/other/src/a.py", "outside the explicit coverage root"),
        (".", "src/../a.py", "invalid coverage path"),
        ("src/..", "src/a.py", "invalid Cobertura source path"),
        (
            "/foreign/src",
            "absent.py",
            "unknown analyzed Cobertura source path",
        ),
    ] {
        let report = import_coverage(root, &[line_report(source, filename)], &sources);
        assert_eq!(report.status, AssessmentStatus::Invalid, "{filename}");
        assert_eq!(report.lines.eligible, 0);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|msg| msg.contains(diagnostic)),
            "{:?}",
            report.diagnostics
        );
    }
    let relative_root = import_coverage(Path::new("."), &[line_report(".", "/a.py")], &sources);
    assert_eq!(relative_root.status, AssessmentStatus::Invalid);
    assert_eq!(relative_root.lines.eligible, 0);
}

fn branch_report(line: u32) -> CoverageSource {
    CoverageSource {
        format: CoverageFormat::Cobertura,
        path: PathBuf::from(format!("coverage-{line}.xml")),
        content: format!(
            r#"<coverage lines-valid="1" lines-covered="1" branches-valid="2" branches-covered="1">
  <packages><package><classes><class filename="a.py">
    <lines><line number="{line}" hits="1" branch="true" condition-coverage="50% (1/2)" missing-branches="exit"/></lines>
  </class></classes></package></packages>
</coverage>"#
        ),
    }
}

#[test]
fn permits_disjoint_branch_counts_but_refuses_overlap_in_either_order() {
    let root = Path::new("/repo");
    let sources = [python("a.py")];
    let identified = CoverageSource {
        format: CoverageFormat::Lcov,
        path: PathBuf::from("coverage.lcov"),
        content: "SF:a.py\nDA:1,1\nBRDA:1,0,0,1\nBRDA:1,0,1,0\nend_of_record\n".into(),
    };
    for inputs in [
        [branch_report(1), branch_report(2)],
        [identified.clone(), branch_report(2)],
    ] {
        let report = import_coverage(root, &inputs, &sources);
        assert_eq!(report.status, AssessmentStatus::Complete);
        assert_eq!(
            report.branches,
            CoverageCounter {
                eligible: 4,
                covered: 2
            }
        );
        assert_eq!(
            report.lines,
            CoverageCounter {
                eligible: 2,
                covered: 2
            }
        );
    }
    for mut inputs in [
        [branch_report(1), branch_report(1)],
        [identified, branch_report(1)],
    ] {
        let report = import_coverage(root, &inputs, &sources);
        assert_eq!(report.status, AssessmentStatus::Invalid);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|msg| msg.contains("overlapping branch coverage at line 1"))
        );
        inputs.reverse();
        assert_eq!(import_coverage(root, &inputs, &sources), report);
    }
}
