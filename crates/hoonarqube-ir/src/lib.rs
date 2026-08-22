//! Findings-oriented intermediate representation for analyzer output.
//!
//! Language analyzers lower their findings into these plain data types; nothing
//! here parses source code or runs analysis. [`Issue::rule_key`] references a
//! `RuleRecord::external_key` from the frozen `hoonarqube-catalog` catalog, so
//! severity and type always resolve through the catalog and are deliberately not
//! duplicated in this crate.
//!
//! Positions follow the `SonarQube` text-range convention: `line` is 1-based,
//! `column` is 0-based.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Source position. `line` is 1-based, `column` is 0-based (`SonarQube`
/// text-range convention).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pos {
    pub line: u32,
    pub column: u32,
}

/// Half-open-inclusive source span; invariant `start <= end` lexicographic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    pub start: Pos,
    pub end: Pos,
}

/// One finding. `rule_key` is a `RuleRecord::external_key` from the frozen
/// catalog (e.g. `python:BackticksUsage`); severity/type resolve through the
/// catalog, never duplicated here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issue {
    pub rule_key: String,
    pub message: String,
    pub range: Range,
}

/// SonarQube-style size metrics for one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetrics {
    pub lines: u32,
    pub code_lines: u32,
    pub comment_lines: u32,
}

/// Findings and metrics for one analyzed file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileReport {
    pub path: PathBuf,
    pub language: String,
    pub issues: Vec<Issue>,
    pub metrics: FileMetrics,
}

/// Complete result of analyzing one target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub files: Vec<FileReport>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Documented field semantics via literal construction: first line is 1,
    /// first column is 0, spans are half-open inclusive.
    #[test]
    fn pos_and_range_field_semantics() {
        let start = Pos { line: 1, column: 0 };
        assert_eq!(start.line, 1);
        assert_eq!(start.column, 0);

        let end = Pos {
            line: 3,
            column: 12,
        };
        let range = Range { start, end };
        assert_eq!(range.start.line, 1);
        assert_eq!(range.start.column, 0);
        assert_eq!(range.end.line, 3);
        assert_eq!(range.end.column, 12);
    }

    #[test]
    fn analysis_report_json_round_trip() {
        let report = AnalysisReport {
            files: vec![FileReport {
                path: PathBuf::from("src/app.py"),
                language: "python".to_string(),
                issues: vec![Issue {
                    rule_key: "python:BackticksUsage".to_string(),
                    message: "Replace the backticks with regular quotes.".to_string(),
                    range: Range {
                        start: Pos { line: 4, column: 8 },
                        end: Pos {
                            line: 4,
                            column: 23,
                        },
                    },
                }],
                metrics: FileMetrics {
                    lines: 42,
                    code_lines: 30,
                    comment_lines: 5,
                },
            }],
        };

        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: AnalysisReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }
}
