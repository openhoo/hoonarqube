//! Findings-oriented intermediate representation for analyzer output.
//!
//! Language analyzers lower their findings into these plain data types; nothing
//! here parses source code or runs analysis. [`Issue::rule_key`] references
//! either a captured Sonar rule or an independently defined native rule from
//! `hoonarqube-catalog`; severity and type remain catalog-owned and are not
//! duplicated in this crate.
//!
//! Positions follow the `SonarQube` text-range convention: `line` is 1-based,
//! `column` is 0-based.

use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize, de};

/// Source position. `line` is 1-based, `column` is 0-based (`SonarQube`
/// text-range convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Pos {
    pub line: u32,
    pub column: u32,
}
#[derive(Deserialize)]
struct PosRepr {
    line: u32,
    column: u32,
}

fn valid_pos<E: de::Error>(raw: &PosRepr) -> Result<Pos, E> {
    if raw.line == 0 {
        return Err(E::custom("source positions must use a 1-based line"));
    }
    Ok(Pos {
        line: raw.line,
        column: raw.column,
    })
}

impl<'de> Deserialize<'de> for Pos {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        valid_pos(&PosRepr::deserialize(deserializer)?)
    }
}

/// Canonical `usize` → `u32` conversion for position offsets coming from
/// `usize`-based parser APIs; saturates at `u32::MAX`.
#[must_use]
pub fn u32_saturating(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Half-open source span; invariant `start <= end` lexicographic.
/// [`Pos`] orders lexicographically, so spans compare the same way. The sole
/// zero-based exception is [`Range::file_level`], used when `SonarQube` attaches
/// an issue to a file without a text range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Range {
    pub start: Pos,
    pub end: Pos,
}

impl Range {
    /// Sentinel for a `SonarQube` file-level issue with no primary text range.
    #[must_use]
    pub const fn file_level() -> Self {
        Self {
            start: Pos { line: 0, column: 0 },
            end: Pos { line: 0, column: 0 },
        }
    }

    #[must_use]
    pub const fn is_file_level(&self) -> bool {
        self.start.line == 0 && self.start.column == 0 && self.end.line == 0 && self.end.column == 0
    }
}
#[derive(Deserialize)]
struct RangeRepr {
    start: PosRepr,
    end: PosRepr,
}

impl<'de> Deserialize<'de> for Range {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RangeRepr::deserialize(deserializer)?;
        let is_file_level = raw.start.line == 0
            && raw.start.column == 0
            && raw.end.line == 0
            && raw.end.column == 0;
        let start = if is_file_level {
            Pos { line: 0, column: 0 }
        } else {
            valid_pos(&raw.start)?
        };
        let end = if is_file_level {
            Pos { line: 0, column: 0 }
        } else {
            valid_pos(&raw.end)?
        };
        if start > end {
            return Err(de::Error::custom("range start must not be after range end"));
        }
        Ok(Self { start, end })
    }
}

/// One replacement inside a single file: applying it overwrites `range` with
/// `replacement`; an empty `replacement` deletes the range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextEdit {
    pub range: Range,
    pub replacement: String,
}

impl TextEdit {
    /// Whether both edits rewrite overlapping source regions. An insertion
    /// at a replacement's start competes with that replacement; an insertion
    /// at its end is plain half-open adjacency and remains compatible. Two
    /// insertions at the same position also overlap.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        let shared_start = self.range.start.max(other.range.start);
        let shared_end = self.range.end.min(other.range.end);
        if shared_start < shared_end {
            return true;
        }
        (self.range.start == self.range.end
            && self.range.start >= other.range.start
            && self.range.start < other.range.end)
            || (other.range.start == other.range.end
                && other.range.start >= self.range.start
                && other.range.start < self.range.end)
            || (self.range.start == self.range.end
                && other.range.start == other.range.end
                && self.range.start == other.range.start)
    }
}

/// One machine-applicable remedy: a human-readable `message` plus the
/// [`TextEdit`]s realizing it.
///
/// Invariants for `edits`: sorted ascending by start, pairwise
/// non-overlapping, every range within the bounds of the fixed file.
/// [`Issue::with_fix`] enforces ordering and overlap on construction;
/// [`apply_fixes`] re-validates bounds and overlap before rewriting anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fix {
    pub message: String,
    pub edits: Vec<TextEdit>,
}
#[derive(Deserialize)]
struct FixRepr {
    message: String,
    edits: Vec<TextEdit>,
}

impl<'de> Deserialize<'de> for Fix {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = FixRepr::deserialize(deserializer)?;
        if raw.edits.is_empty() {
            return Err(de::Error::custom(
                "quick fix must contain at least one TextEdit",
            ));
        }
        for edit in &raw.edits {
            if edit.range.is_file_level() {
                return Err(de::Error::custom(
                    "quick fix edits cannot use a file-level range",
                ));
            }
        }
        for pair in raw.edits.windows(2) {
            if pair[0].range.start > pair[1].range.start {
                return Err(de::Error::custom(
                    "quick fix edits must be sorted by start position",
                ));
            }
            if pair[0].overlaps(&pair[1]) {
                return Err(de::Error::custom("quick fix edits must not overlap"));
            }
        }
        Ok(Self {
            message: raw.message,
            edits: raw.edits,
        })
    }
}

/// One secondary location in an execution/data-flow trace. `path=None`
/// refers to the finding's primary file; a path enables cross-file flows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowLocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    pub message: String,
    pub range: Range,
}

impl FlowLocation {
    /// Builds a location in the finding's primary file.
    #[must_use]
    pub fn in_primary_file(message: impl Into<String>, range: Range) -> Self {
        Self {
            path: None,
            message: message.into(),
            range,
        }
    }
}

/// Ordered locations describing one execution or data-flow path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssueFlow {
    pub locations: Vec<FlowLocation>,
}
#[derive(Deserialize)]
struct IssueFlowRepr {
    locations: Vec<FlowLocation>,
}

impl<'de> Deserialize<'de> for IssueFlow {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = IssueFlowRepr::deserialize(deserializer)?;
        if raw.locations.is_empty() {
            return Err(de::Error::custom("issue flow must contain a location"));
        }
        Ok(Self {
            locations: raw.locations,
        })
    }
}

/// One finding. `rule_key` resolves through either the frozen Sonar catalog
/// or the separate Hoonarqube-native catalog; severity/type are never
/// duplicated here. `fix` optionally carries a machine-applicable quick fix.
/// `flows` carries ordered supporting locations for path-sensitive rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub rule_key: String,
    pub message: String,
    pub range: Range,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<Fix>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flows: Vec<IssueFlow>,
}
#[derive(Deserialize)]
struct IssueRepr {
    rule_key: String,
    message: String,
    range: Range,
    #[serde(default)]
    fix: Option<Fix>,
    #[serde(default)]
    flows: Vec<IssueFlow>,
}

impl<'de> Deserialize<'de> for Issue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = IssueRepr::deserialize(deserializer)?;
        Ok(Self {
            rule_key: raw.rule_key,
            message: raw.message,
            range: raw.range,
            fix: raw.fix,
            flows: raw.flows,
        })
    }
}

/// Canonical `SonarQube` issue ordering: start position, then end position
/// lexicographic, then rule key, then message.
pub fn sort_issues(issues: &mut [Issue]) {
    issues.sort_by(|a, b| {
        (
            a.range.start.line,
            a.range.start.column,
            a.range.end.line,
            a.range.end.column,
            a.rule_key.as_str(),
            a.message.as_str(),
        )
            .cmp(&(
                b.range.start.line,
                b.range.start.column,
                b.range.end.line,
                b.range.end.column,
                b.rule_key.as_str(),
                b.message.as_str(),
            ))
    });
}

impl Issue {
    /// Builds a fix-less finding; attach a remedy separately via
    /// [`Issue::with_fix`].
    #[must_use]
    pub fn new(rule_key: impl Into<String>, message: impl Into<String>, range: Range) -> Self {
        Self {
            rule_key: rule_key.into(),
            message: message.into(),
            range,
            fix: None,
            flows: Vec::new(),
        }
    }

    /// Attaches a quick fix, sorting `edits` ascending by start position so
    /// the [`Fix`] invariants hold.
    ///
    /// # Panics
    /// Panics when any edit's range is inverted (`start` after `end`) or when
    /// two edits overlap — including two insertions at the same position —
    /// because overlapping edits cannot be applied deterministically.
    #[must_use]
    pub fn with_fix(mut self, message: impl Into<String>, mut edits: Vec<TextEdit>) -> Self {
        assert!(
            !edits.is_empty(),
            "quick fix must contain at least one TextEdit"
        );
        for edit in &edits {
            assert!(
                (edit.range.start.line, edit.range.start.column)
                    <= (edit.range.end.line, edit.range.end.column),
                "inverted TextEdit range {:?}",
                edit.range
            );
        }
        edits.sort_by_key(|edit| edit.range.start);
        for pair in edits.windows(2) {
            assert!(
                !pair[0].overlaps(&pair[1]),
                "overlapping TextEdits at {:?} / {:?}",
                pair[0].range,
                pair[1].range
            );
        }
        self.fix = Some(Fix {
            message: message.into(),
            edits,
        });
        self
    }

    /// Attaches one non-empty ordered execution/data-flow path.
    ///
    /// # Panics
    /// Panics when `locations` is empty because an empty flow has no evidence.
    #[must_use]
    pub fn with_flow(mut self, locations: Vec<FlowLocation>) -> Self {
        assert!(!locations.is_empty(), "issue flow must contain a location");
        self.flows.push(IssueFlow { locations });
        self
    }
}

/// Failure modes of [`apply_fixes`]; `index` fields refer to positions in
/// the input slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixApplyError {
    /// The edit's `start` lies lexicographically after its `end`.
    InvertedRange {
        /// Position of the offending edit in the input slice.
        index: usize,
    },
    /// The referenced line or character column does not exist in the source.
    OutOfBounds {
        /// Position of the offending edit in the input slice.
        index: usize,
        /// The endpoint that missed the source.
        pos: Pos,
    },
    /// Two edits rewrite overlapping regions (including competing insertions
    /// at the same position).
    Overlapping {
        /// Input-slice index of the earlier edit.
        first: usize,
        /// Input-slice index of the later edit.
        second: usize,
    },
}

impl std::fmt::Display for FixApplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvertedRange { index } => {
                write!(formatter, "text edit {index} ends before it starts")
            }
            Self::OutOfBounds { index, pos } => write!(
                formatter,
                "text edit {index} points outside the source at line {}, column {}",
                pos.line, pos.column
            ),
            Self::Overlapping { first, second } => {
                write!(formatter, "text edits {first} and {second} overlap")
            }
        }
    }
}

impl std::error::Error for FixApplyError {}

/// Resolves an IR position (1-based line, 0-based character column) to a
/// byte offset. A `\r\n` pair is one line terminator: neither byte contributes
/// to a character column. A column equal to the line's character count
/// addresses the insertion point right after the content (before the
/// terminator or EOF).
fn resolve_pos(
    line_starts: &[usize],
    ascii_lines: &[bool],
    source: &str,
    pos: Pos,
) -> Option<usize> {
    if pos.line == 0 {
        return None;
    }
    let line_index = usize::try_from(pos.line).ok()?.checked_sub(1)?;
    let start = *line_starts.get(line_index)?;
    let terminator_start = line_starts
        .get(line_index + 1)
        .map_or(source.len(), |next_start| next_start - 1);
    let end = if line_index + 1 < line_starts.len()
        && terminator_start > start
        && source.as_bytes().get(terminator_start - 1) == Some(&b'\r')
    {
        terminator_start - 1
    } else {
        terminator_start
    };
    let content = source.get(start..end)?;
    let target = usize::try_from(pos.column).ok()?;
    if ascii_lines.get(line_index) == Some(&true) {
        return (target <= content.len()).then_some(start + target);
    }
    let mut seen = 0_usize;
    for (char_offset, _) in content.char_indices() {
        if seen == target {
            return Some(start + char_offset);
        }
        seen += 1;
    }
    (seen == target).then_some(end)
}

/// Applies text edits to `source` and returns the rewritten text. This is
/// the single canonical edit engine; the CLI and every test reuse it.
///
/// Edits may arrive in any order: they are validated (bounds and pairwise
/// overlap, mirroring [`TextEdit::overlaps`]) and applied in descending
/// start order so earlier byte offsets stay stable; the input slice is left
/// untouched.
///
/// # Errors
/// Returns [`FixApplyError::InvertedRange`] for `start > end` edits,
/// [`FixApplyError::OutOfBounds`] when an endpoint misses the source, and
/// [`FixApplyError::Overlapping`] for conflicting edits (same-point
/// insertions and insertion-at-replacement-start conflict; plain adjacent
/// `end == start` edits do not).
pub fn apply_fixes(source: &str, edits: &[&TextEdit]) -> Result<String, FixApplyError> {
    let mut line_starts = vec![0_usize];
    for (offset, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            line_starts.push(offset + 1);
        }
    }
    let ascii_lines: Vec<bool> = line_starts
        .iter()
        .enumerate()
        .map(|(index, start)| {
            let end = line_starts
                .get(index + 1)
                .map_or(source.len(), |next| next - 1);
            source[*start..end].is_ascii()
        })
        .collect();

    let mut mapped: Vec<(usize, usize, usize)> = Vec::with_capacity(edits.len());
    for (index, edit) in edits.iter().enumerate() {
        let range = &edit.range;
        if (range.start.line, range.start.column) > (range.end.line, range.end.column) {
            return Err(FixApplyError::InvertedRange { index });
        }
        let Some(start_offset) = resolve_pos(&line_starts, &ascii_lines, source, range.start)
        else {
            return Err(FixApplyError::OutOfBounds {
                index,
                pos: range.start,
            });
        };
        let Some(end_offset) = resolve_pos(&line_starts, &ascii_lines, source, range.end) else {
            return Err(FixApplyError::OutOfBounds {
                index,
                pos: range.end,
            });
        };
        mapped.push((start_offset, end_offset, index));
    }

    mapped.sort_by_key(|&(start, end, _)| (start, end));
    for window in mapped.windows(2) {
        let (first_start, first_end, first_index) = window[0];
        let (second_start, _, second_index) = window[1];
        let competes =
            second_start < first_end || (first_start == first_end && first_start == second_start);
        if competes {
            return Err(FixApplyError::Overlapping {
                first: first_index,
                second: second_index,
            });
        }
    }

    // Construct the result in one forward pass. Repeated descending
    // `replace_range` calls shift the unchanged suffix once per edit and turn
    // a large batch of otherwise independent edits into quadratic work.
    let removed: usize = mapped.iter().map(|(start, end, _)| end - start).sum();
    let replacement: usize = mapped
        .iter()
        .map(|(_, _, index)| edits[*index].replacement.len())
        .sum();
    let capacity = source
        .len()
        .saturating_sub(removed)
        .saturating_add(replacement);
    let mut fixed = String::with_capacity(capacity);
    let mut cursor = 0_usize;
    for (start, end, index) in mapped {
        fixed.push_str(&source[cursor..start]);
        fixed.push_str(&edits[index].replacement);
        cursor = end;
    }
    fixed.push_str(&source[cursor..]);
    Ok(fixed)
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
    /// first column is 0, spans are half-open.
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
                    fix: None,
                    flows: Vec::new(),
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

    #[test]
    fn issue_flows_round_trip_and_empty_fields_stay_omitted() {
        let plain = Issue::new(
            "python:S1",
            "plain",
            Range {
                start: Pos { line: 1, column: 0 },
                end: Pos { line: 1, column: 1 },
            },
        );
        let plain_json = serde_json::to_value(&plain).expect("serialize plain issue");
        assert!(plain_json.get("flows").is_none());
        assert!(plain_json.get("fix").is_none());

        let traced = plain.clone().with_flow(vec![FlowLocation {
            path: Some(PathBuf::from("src/source.py")),
            message: "value originates here".to_string(),
            range: Range {
                start: Pos { line: 4, column: 2 },
                end: Pos { line: 4, column: 8 },
            },
        }]);
        let json = serde_json::to_string(&traced).expect("serialize flow");
        let parsed: Issue = serde_json::from_str(&json).expect("deserialize flow");
        assert_eq!(parsed, traced);
    }

    #[test]
    #[should_panic(expected = "issue flow must contain a location")]
    fn empty_issue_flow_is_rejected() {
        let _ = Issue::new("python:S1", "plain", Range::file_level()).with_flow(Vec::new());
    }

    /// Builds a `TextEdit` from `(line, column)` tuples for compact tests.
    fn edit(start: (u32, u32), end: (u32, u32), replacement: &str) -> TextEdit {
        TextEdit {
            range: Range {
                start: Pos {
                    line: start.0,
                    column: start.1,
                },
                end: Pos {
                    line: end.0,
                    column: end.1,
                },
            },
            replacement: replacement.to_string(),
        }
    }

    #[test]
    fn apply_fixes_replaces_on_plain_lf_source() {
        let source = "alpha\nbeta\n";
        let fixed = apply_fixes(source, &[&edit((1, 0), (1, 5), "ALPHA")]).expect("applies");
        assert_eq!(fixed, "ALPHA\nbeta\n");
    }

    #[test]
    fn apply_fixes_preserves_a_standalone_final_carriage_return_as_content() {
        for source in ["ab\r", "é😀\r"] {
            let insertion = edit((1, 3), (1, 3), "!");
            assert_eq!(
                apply_fixes(source, &[&insertion]).unwrap(),
                format!("{source}!")
            );
            let replacement = edit((1, 2), (1, 3), "!");
            assert_eq!(
                apply_fixes(source, &[&replacement]).unwrap(),
                format!("{}!", &source[..source.len() - 1])
            );
        }
    }

    #[test]
    fn apply_fixes_preserves_crlf_and_excludes_terminators_from_columns() {
        let source = "ab\r\ncd\r\n";
        // Line 1 content is "ab": columns 0..2 replace only the text.
        let fixed = apply_fixes(source, &[&edit((1, 0), (1, 2), "xy")]).expect("applies");
        assert_eq!(fixed, "xy\r\ncd\r\n");
        // Column 2 is the insertion point before CRLF; column 3 is invalid.
        let fixed = apply_fixes(source, &[&edit((1, 2), (1, 2), "!")]).expect("applies");
        assert_eq!(fixed, "ab!\r\ncd\r\n");
        assert!(matches!(
            apply_fixes(source, &[&edit((1, 3), (1, 3), "")]),
            Err(FixApplyError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn apply_fixes_columns_count_characters_not_bytes() {
        // 'á'(2 bytes) 'é'(2) '€'(3) 'x'(1): columns 1..3 remove é and €.
        let source = "áé€x\n";
        let fixed = apply_fixes(source, &[&edit((1, 1), (1, 3), "")]).expect("applies");
        assert_eq!(fixed, "áx\n");
    }

    #[test]
    fn apply_fixes_deletes_inserts_and_reaches_eof() {
        let deletion = apply_fixes("abcd\n", &[&edit((1, 1), (1, 3), "")]).expect("deletes");
        assert_eq!(deletion, "ad\n");

        let insertion = apply_fixes("ab\n", &[&edit((1, 1), (1, 1), "X")]).expect("inserts");
        assert_eq!(insertion, "aXb\n");

        // A file ending in a newline has an empty virtual last line at EOF.
        let eof = apply_fixes("ab\n", &[&edit((2, 0), (2, 0), "!")]).expect("eof insert");
        assert_eq!(eof, "ab\n!");
    }

    #[test]
    fn apply_fixes_allows_adjacent_edits_and_unordered_input() {
        let source = "abcdef\n";
        let edits = [edit((1, 3), (1, 6), "Y"), edit((1, 0), (1, 3), "X")];
        let fixed = apply_fixes(source, &edits.iter().collect::<Vec<_>>()).expect("applies");
        assert_eq!(fixed, "XY\n");
    }

    #[test]
    fn apply_fixes_handles_many_edits_in_one_forward_rewrite() {
        let source = "a".repeat(10_000);
        let edits: Vec<_> = (0..5_000)
            .map(|column| edit((1, column * 2), (1, column * 2 + 1), "bc"))
            .collect();
        let fixed = apply_fixes(&source, &edits.iter().collect::<Vec<_>>()).expect("applies");

        assert_eq!(fixed, "bca".repeat(5_000));
    }

    #[test]
    fn apply_fixes_rejects_competing_same_point_insertions() {
        let first = edit((1, 1), (1, 1), "X");
        let second = edit((1, 1), (1, 1), "Y");
        let error = apply_fixes("ab\n", &[&first, &second]).expect_err("conflicts");
        assert_eq!(
            error,
            FixApplyError::Overlapping {
                first: 0,
                second: 1
            }
        );
    }

    #[test]
    fn apply_fixes_rejects_insertion_at_replacement_start() {
        let insertion = edit((1, 1), (1, 1), "X");
        let replacement = edit((1, 1), (1, 2), "Y");
        assert!(insertion.overlaps(&replacement));
        assert!(replacement.overlaps(&insertion));
        assert!(matches!(
            apply_fixes("ab\n", &[&replacement, &insertion]),
            Err(FixApplyError::Overlapping { .. })
        ));

        let at_end = edit((1, 2), (1, 2), "!");
        assert!(!replacement.overlaps(&at_end));
        assert_eq!(
            apply_fixes("ab\n", &[&replacement, &at_end]).expect("adjacent edits apply"),
            "aY!\n"
        );
    }

    #[test]
    fn apply_fixes_reports_out_of_bounds_endpoints() {
        let beyond_line = edit((1, 5), (1, 6), "X");
        assert_eq!(
            apply_fixes("ab\n", &[&beyond_line]),
            Err(FixApplyError::OutOfBounds {
                index: 0,
                pos: Pos { line: 1, column: 5 }
            })
        );

        let unknown_line = edit((9, 0), (9, 1), "X");
        assert!(matches!(
            apply_fixes("ab\n", &[&unknown_line]),
            Err(FixApplyError::OutOfBounds { index: 0, .. })
        ));

        let zero_line = edit((0, 0), (0, 1), "X");
        assert!(matches!(
            apply_fixes("ab\n", &[&zero_line]),
            Err(FixApplyError::OutOfBounds { index: 0, .. })
        ));
    }

    #[test]
    fn issue_new_has_no_fix_and_with_fix_sorts_edits() {
        let range = Range {
            start: Pos { line: 1, column: 0 },
            end: Pos { line: 1, column: 4 },
        };
        let bare = Issue::new("python:S1721", "Remove the parentheses.", range.clone());
        assert!(bare.fix.is_none());

        let edits = vec![edit((1, 10), (1, 11), ""), edit((1, 6), (1, 7), " ")];
        let fixed = bare.with_fix("Remove redundant parentheses", edits);
        let fix = fixed.fix.expect("attached");
        assert_eq!(fix.message, "Remove redundant parentheses");
        assert!(fix.edits[0].range.start < fix.edits[1].range.start);
    }

    #[test]
    #[should_panic(expected = "overlapping TextEdits")]
    fn with_fix_panics_on_overlapping_edits() {
        let range = Range {
            start: Pos { line: 1, column: 0 },
            end: Pos { line: 1, column: 4 },
        };
        let _ = Issue::new("python:S1721", "message", range).with_fix(
            "fix",
            vec![edit((1, 0), (1, 5), "A"), edit((1, 3), (1, 7), "B")],
        );
    }

    #[test]
    #[should_panic(expected = "quick fix must contain at least one TextEdit")]
    fn with_fix_panics_on_empty_edits() {
        let range = Range {
            start: Pos { line: 1, column: 0 },
            end: Pos { line: 1, column: 4 },
        };
        let _ = Issue::new("python:S1721", "message", range).with_fix("fix", Vec::new());
    }

    #[test]
    #[should_panic(expected = "inverted TextEdit range")]
    fn with_fix_panics_on_inverted_range() {
        let range = Range {
            start: Pos { line: 1, column: 0 },
            end: Pos { line: 1, column: 4 },
        };
        let _ = Issue::new("python:S1721", "message", range)
            .with_fix("fix", vec![edit((1, 5), (1, 2), "A")]);
    }

    #[test]
    fn serde_rejects_invalid_public_ir_invariants() {
        assert!(serde_json::from_str::<Pos>(r#"{"line":0,"column":1}"#).is_err());
        assert!(
            serde_json::from_str::<Range>(
                r#"{"start":{"line":2,"column":0},"end":{"line":1,"column":0}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Range>(
                r#"{"start":{"line":0,"column":0},"end":{"line":1,"column":0}}"#
            )
            .is_err()
        );
        assert_eq!(
            serde_json::from_str::<Range>(
                r#"{"start":{"line":0,"column":0},"end":{"line":0,"column":0}}"#
            )
            .expect("file-level sentinel"),
            Range::file_level()
        );

        assert!(serde_json::from_str::<Fix>(r#"{"message":"fix","edits":[]}"#).is_err());
        let file_level_edit = r#"{"message":"fix","edits":[
            {"range":{"start":{"line":0,"column":0},"end":{"line":0,"column":0}},"replacement":"x"}
        ]}"#;
        assert!(serde_json::from_str::<Fix>(file_level_edit).is_err());
        let unsorted = r#"{"message":"fix","edits":[
            {"range":{"start":{"line":1,"column":2},"end":{"line":1,"column":3}},"replacement":"b"},
            {"range":{"start":{"line":1,"column":0},"end":{"line":1,"column":1}},"replacement":"a"}
        ]}"#;
        assert!(serde_json::from_str::<Fix>(unsorted).is_err());
        let overlapping = r#"{"message":"fix","edits":[
            {"range":{"start":{"line":1,"column":0},"end":{"line":1,"column":2}},"replacement":"x"},
            {"range":{"start":{"line":1,"column":1},"end":{"line":1,"column":3}},"replacement":"y"}
        ]}"#;
        assert!(serde_json::from_str::<Fix>(overlapping).is_err());
        assert!(serde_json::from_str::<IssueFlow>(r#"{"locations":[]}"#).is_err());
        assert!(serde_json::from_str::<Issue>(
            r#"{"rule_key":"x","message":"m","range":{"start":{"line":1,"column":0},"end":{"line":1,"column":1}},"flows":[{"locations":[]}]}"#
        )
        .is_err());
    }

    #[test]
    fn issue_json_omits_absent_fix_and_round_trips_present_one() {
        let range = Range {
            start: Pos { line: 1, column: 0 },
            end: Pos { line: 1, column: 4 },
        };
        let without = serde_json::to_string(&Issue::new("python:S1721", "m", range.clone()))
            .expect("serialize");
        assert!(!without.contains("\"fix\""));

        let with = Issue::new("python:S1721", "m", range)
            .with_fix("fix message", vec![edit((1, 4), (1, 4), "")]);
        let json = serde_json::to_string(&with).expect("serialize");
        assert!(json.contains("\"fix\""));
        let parsed: Issue = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, with);
    }
}
