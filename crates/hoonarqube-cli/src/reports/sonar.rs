//! `SonarQube` Generic Issue Import, including conversion to UTF-16 columns.
use hoonarqube_catalog::{Catalog, native_rule};
use hoonarqube_ir::assessment::{
    SourceLineStyle, line_content_end, line_style_for_path, line_terminator_width,
};

/// Builds the current `SonarQube` Generic Issue Import document. Every used rule
/// is defined once in the top-level `rules` array; findings reference it by the
/// repository-qualified `ruleId`. Catalog classification and impacts remain the
/// single metadata source. Native columns are converted at this export boundary
/// to Sonar's zero-based UTF-16 units; native JSON and SARIF retain their own
/// coordinate contracts.
pub(crate) fn document(
    catalog: &Catalog,
    reports: &[hoonarqube_ir::FileReport],
) -> Result<serde_json::Value, String> {
    let mut source_cache = SonarSourceCache::default();
    sonar_import_value_with_source_loader(
        catalog,
        reports,
        &mut |path| {
            hoonarqube_core::read_bounded_source(path)
                .map_err(|error| format!("cannot read Sonar source {}: {error}", path.display()))
        },
        &mut source_cache,
    )
}

#[derive(Default)]
struct SonarSourceCache {
    sources: std::collections::HashMap<std::path::PathBuf, SonarSource>,
}

struct SonarSource {
    text: String,
    line_starts: Vec<usize>,
    line_style: SourceLineStyle,
}

impl SonarSource {
    fn new(text: String, line_style: SourceLineStyle) -> Self {
        let bytes = text.as_bytes();
        let mut line_starts = vec![0];
        let mut offset = 0;
        while offset < bytes.len() {
            if let Some(width) = line_terminator_width(bytes, offset, line_style) {
                offset += width;
                line_starts.push(offset);
            } else {
                offset += 1;
            }
        }
        Self {
            text,
            line_starts,
            line_style,
        }
    }

    fn line(&self, line: u32) -> Result<&str, String> {
        if line == 0 {
            return Err("Sonar source positions use 1-based lines".to_owned());
        }
        let line_index =
            usize::try_from(line - 1).map_err(|_| "Sonar line is too large".to_owned())?;
        let start = *self
            .line_starts
            .get(line_index)
            .ok_or_else(|| format!("Sonar source has no line {line}"))?;
        let next = self
            .line_starts
            .get(line_index + 1)
            .copied()
            .unwrap_or(self.text.len());
        let end = line_content_end(self.text.as_bytes(), start, next, self.line_style);
        self.text
            .get(start..end)
            .ok_or_else(|| format!("Sonar source line {line} is not valid UTF-8"))
    }
}

impl SonarSourceCache {
    fn load<'a>(
        &'a mut self,
        path: &std::path::Path,
        loader: &mut dyn FnMut(&std::path::Path) -> Result<String, String>,
    ) -> Result<&'a SonarSource, String> {
        if !self.sources.contains_key(path) {
            let source = loader(path)?;
            self.sources.insert(
                path.to_path_buf(),
                SonarSource::new(source, line_style_for_path(path, None)),
            );
        }
        Ok(self
            .sources
            .get(path)
            .expect("source cache entry inserted above"))
    }
}

fn sonar_import_value_with_source_loader(
    catalog: &Catalog,
    reports: &[hoonarqube_ir::FileReport],
    source_loader: &mut dyn FnMut(&std::path::Path) -> Result<String, String>,
    source_cache: &mut SonarSourceCache,
) -> Result<serde_json::Value, String> {
    let mut rules = std::collections::BTreeMap::new();
    let mut findings = Vec::new();
    for report in reports {
        let file_path = report.path.to_str().ok_or_else(|| {
            format!(
                "primary report path is not valid UTF-8: {}",
                report.path.display()
            )
        })?;
        for issue in &report.issues {
            let rule_id = sonar_rule_id(&issue.rule_key);
            rules
                .entry(rule_id)
                .or_insert_with(|| sonar_import_rule(catalog, issue));
            findings.push((file_path, report.path.as_path(), issue));
        }
    }
    findings.sort_by(|(path_a, _, issue_a), (path_b, _, issue_b)| {
        (
            *path_a,
            issue_a.range.start.line,
            issue_a.range.start.column,
            issue_a.range.end.line,
            issue_a.range.end.column,
            issue_a.rule_key.as_str(),
            issue_a.message.as_str(),
        )
            .cmp(&(
                *path_b,
                issue_b.range.start.line,
                issue_b.range.start.column,
                issue_b.range.end.line,
                issue_b.range.end.column,
                issue_b.rule_key.as_str(),
                issue_b.message.as_str(),
            ))
    });
    let issues = findings
        .into_iter()
        .map(|(file_path, source_path, issue)| {
            sonar_import_issue(file_path, source_path, issue, source_loader, source_cache)
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Move the already-built values into the document. Passing them through
    // json! serializes them again, cloning every finding and location.
    Ok(serde_json::Value::Object(serde_json::Map::from_iter([
        (
            "rules".to_owned(),
            serde_json::Value::Array(rules.into_values().collect()),
        ),
        ("issues".to_owned(), serde_json::Value::Array(issues)),
    ])))
}

fn sonar_import_rule(catalog: &Catalog, issue: &hoonarqube_ir::Issue) -> serde_json::Value {
    let rule_id = sonar_rule_id(&issue.rule_key);
    if let Some(record) = catalog.rule(&issue.rule_key) {
        return serde_json::json!({
            "id": rule_id,
            "name": issue.rule_key,
            "description": format!("Hoonarqube finding for `{}`.", issue.rule_key),
            "engineId": "hoonarqube",
            "cleanCodeAttribute": record.clean_code_attribute.as_deref().unwrap_or("CONVENTIONAL"),
            "type": record.rule_type,
            "severity": record.severity,
            "impacts": record.impacts.iter().map(|impact| serde_json::json!({
                "softwareQuality": impact.software_quality,
                "severity": impact.severity,
            })).collect::<Vec<_>>(),
        });
    }
    if let Some(record) = native_rule(&issue.rule_key) {
        return serde_json::json!({
            "id": rule_id,
            "name": record.name,
            "description": format!("{} Origin: {} {} ({}).", record.description, record.origin_tool, record.origin_rule_id, record.origin_url),
            "engineId": "hoonarqube-native",
            "cleanCodeAttribute": record.clean_code_attribute,
            "type": record.rule_type,
            "severity": record.severity,
            "impacts": record.impacts.iter().map(|impact| serde_json::json!({
                "softwareQuality": impact.software_quality,
                "severity": impact.severity,
            })).collect::<Vec<_>>(),
        });
    }
    serde_json::json!({
        "id": rule_id,
        "name": issue.rule_key,
        "description": format!("Hoonarqube finding for `{}`.", issue.rule_key),
        "engineId": "hoonarqube",
        "cleanCodeAttribute": "CONVENTIONAL",
        "type": "CODE_SMELL",
        "severity": "INFO",
        "impacts": [{
            "softwareQuality": "MAINTAINABILITY",
            "severity": "MEDIUM",
        }],
    })
}

fn sonar_import_issue(
    file_path: &str,
    source_path: &std::path::Path,
    issue: &hoonarqube_ir::Issue,
    source_loader: &mut dyn FnMut(&std::path::Path) -> Result<String, String>,
    source_cache: &mut SonarSourceCache,
) -> Result<serde_json::Value, String> {
    sonar_validate_range(&issue.range, "primary location")?;
    let mut primary_location = serde_json::json!({
        "message": &issue.message,
        "filePath": file_path,
    });
    if !issue.range.is_file_level() {
        let source = source_cache.load(source_path, source_loader)?;
        primary_location["textRange"] = sonar_text_range(&issue.range, source)?;
    }
    let mut imported = serde_json::json!({
        "ruleId": sonar_rule_id(&issue.rule_key),
        "primaryLocation": primary_location,
    });
    let secondary_locations: Result<Vec<_>, String> = issue
        .flows
        .iter()
        .flat_map(|flow| &flow.locations)
        .filter(|location| location.path.is_some() || location.range != issue.range)
        .map(|location| {
            sonar_validate_range(&location.range, "secondary location")?;
            let secondary_file_path = match location.path.as_ref() {
                Some(path) => path.to_str().ok_or_else(|| {
                    format!("secondary flow path is not valid UTF-8: {}", path.display())
                })?,
                None => file_path,
            };
            let secondary_source_path = location.path.as_deref().unwrap_or(source_path);
            let mut value = serde_json::json!({
                "message": location.message,
                "filePath": secondary_file_path,
            });
            if !location.range.is_file_level() {
                let source = source_cache.load(secondary_source_path, source_loader)?;
                value["textRange"] = sonar_text_range(&location.range, source)?;
            }
            Ok(value)
        })
        .collect();
    let secondary_locations = secondary_locations?;
    if !secondary_locations.is_empty() {
        imported["secondaryLocations"] = serde_json::Value::Array(secondary_locations);
    }
    Ok(imported)
}
fn sonar_validate_range(range: &hoonarqube_ir::Range, context: &str) -> Result<(), String> {
    if !range.is_file_level()
        && (range.start.line == 0
            || range.end.line == 0
            || range.start.column == u32::MAX
            || range.end.column == u32::MAX
            || (range.start.line, range.start.column) > (range.end.line, range.end.column))
    {
        return Err(format!("invalid {context} range for Sonar output"));
    }
    Ok(())
}

fn sonar_text_range(
    range: &hoonarqube_ir::Range,
    source: &SonarSource,
) -> Result<serde_json::Value, String> {
    let start_column = sonar_utf16_column(source, range.start.line, range.start.column)?;
    let end_column = sonar_utf16_column(source, range.end.line, range.end.column)?;
    Ok(serde_json::json!({
        "startLine": range.start.line,
        "startColumn": start_column,
        "endLine": range.end.line,
        "endColumn": end_column,
    }))
}

fn sonar_utf16_column(source: &SonarSource, line: u32, column: u32) -> Result<u32, String> {
    let line_text = source.line(line)?;
    let target = usize::try_from(column).map_err(|_| "Sonar column is too large".to_owned())?;
    let mut scalar_count = 0_usize;
    let mut utf16_count = 0_usize;
    for character in line_text.chars() {
        if scalar_count == target {
            break;
        }
        utf16_count = utf16_count
            .checked_add(character.len_utf16())
            .ok_or_else(|| "Sonar UTF-16 column overflow".to_owned())?;
        scalar_count += 1;
    }
    if scalar_count != target {
        return Err(format!(
            "Sonar source line {line} has no Unicode scalar column {column}"
        ));
    }
    u32::try_from(utf16_count).map_err(|_| "Sonar UTF-16 column overflow".to_owned())
}

/// Keeps the repository-qualified catalog key as the Generic Issue Import rule
/// id. A single report can contain Python, JS/TS, C#, Go, and Rust; stripping the prefix
/// would collapse distinct rules such as `python:S112` and `csharpsquid:S112`.
fn sonar_rule_id(rule_key: &str) -> &str {
    rule_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analyze,
        test_support::{sample_report, temp_path},
    };
    use hoonarqube_catalog::embedded;
    use hoonarqube_ir::{FileReport, FlowLocation, Issue, Pos, Range};

    /// Existing schema tests use synthetic reports rather than files on disk.
    /// Give those tests deterministic ASCII source snapshots while production
    /// export remains strict about loading the analyzed source.
    fn sonar_import_value_for_test(
        catalog: &Catalog,
        reports: &[FileReport],
    ) -> Result<serde_json::Value, String> {
        let mut source_lines = std::collections::HashMap::<std::path::PathBuf, Vec<usize>>::new();
        let mut add_range = |path: &std::path::Path, range: &Range| {
            if range.is_file_level()
                || range.start.column == u32::MAX
                || range.end.column == u32::MAX
                || range.start.line == 0
                || range.end.line == 0
            {
                return;
            }
            let max_line = range.start.line.max(range.end.line) as usize;
            let lines = source_lines.entry(path.to_path_buf()).or_default();
            lines.resize(lines.len().max(max_line), 0);
            lines[range.start.line as usize - 1] =
                lines[range.start.line as usize - 1].max(range.start.column as usize);
            lines[range.end.line as usize - 1] =
                lines[range.end.line as usize - 1].max(range.end.column as usize);
        };
        for report in reports {
            for issue in &report.issues {
                add_range(&report.path, &issue.range);
                for location in issue.flows.iter().flat_map(|flow| &flow.locations) {
                    add_range(
                        location.path.as_deref().unwrap_or(&report.path),
                        &location.range,
                    );
                }
            }
        }
        let sources = source_lines
            .into_iter()
            .map(|(path, mut lines)| {
                if lines.is_empty() {
                    lines.push(0);
                }
                (
                    path,
                    lines
                        .into_iter()
                        .map(|length| "x".repeat(length))
                        .collect::<Vec<_>>()
                        .join("\n"),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        let mut source_cache = SonarSourceCache::default();
        sonar_import_value_with_source_loader(
            catalog,
            reports,
            &mut |path| {
                sources
                    .get(path)
                    .cloned()
                    .ok_or_else(|| format!("missing synthetic Sonar source {}", path.display()))
            },
            &mut source_cache,
        )
    }

    #[test]
    fn sonar_import_maps_findings_to_generic_schema() {
        let reports = vec![
            sample_report(
                "src/bad.js",
                "javascript",
                vec![Issue {
                    rule_key: "javascript:S1523".to_string(),
                    message: "Remove this usage of 'eval'.".to_string(),
                    range: Range {
                        start: Pos { line: 1, column: 0 },
                        end: Pos { line: 1, column: 4 },
                    },
                    fix: None,
                    alternatives: Vec::new(),
                    flows: Vec::new(),
                }],
            ),
            sample_report(
                "src/long.py",
                "python",
                vec![Issue {
                    rule_key: "python:LineLength".to_string(),
                    message: "This line exceeds the maximum allowed length of 120 characters."
                        .to_string(),
                    range: Range {
                        start: Pos { line: 3, column: 0 },
                        end: Pos {
                            line: 3,
                            column: 140,
                        },
                    },
                    fix: None,
                    alternatives: Vec::new(),
                    flows: Vec::new(),
                }],
            ),
        ];

        let value = sonar_import_value_for_test(embedded(), &reports).unwrap();
        let rules = value["rules"].as_array().expect("rules array");
        let issues = value["issues"].as_array().expect("issues array");
        assert_eq!(rules.len(), 2);
        assert_eq!(issues.len(), 2);

        let first_rule = &rules[0];
        assert_eq!(first_rule["id"], "javascript:S1523");
        assert_eq!(first_rule["engineId"], "hoonarqube");
        assert_eq!(first_rule["severity"], "CRITICAL");
        assert_eq!(first_rule["type"], "SECURITY_HOTSPOT");
        assert!(first_rule["cleanCodeAttribute"].is_string());
        assert!(first_rule["impacts"].is_array());

        let first = &issues[0];
        assert_eq!(first["ruleId"], "javascript:S1523");
        assert!(first.get("engineId").is_none());
        assert!(first.get("severity").is_none());
        assert!(first.get("type").is_none());
        assert_eq!(
            first["primaryLocation"]["message"],
            "Remove this usage of 'eval'."
        );
        assert_eq!(first["primaryLocation"]["filePath"], "src/bad.js");
        assert_eq!(first["primaryLocation"]["textRange"]["startLine"], 1);
        assert_eq!(first["primaryLocation"]["textRange"]["startColumn"], 0);
        assert_eq!(first["primaryLocation"]["textRange"]["endLine"], 1);
        assert_eq!(first["primaryLocation"]["textRange"]["endColumn"], 4);

        assert_eq!(issues[1]["ruleId"], "python:LineLength");
        assert_eq!(issues[1]["primaryLocation"]["filePath"], "src/long.py");

        // Generic-import optional fields are omitted, never emitted as null.
        assert!(!value.to_string().contains("null"));
    }

    #[test]
    fn sonar_import_of_clean_report_has_empty_issue_list() {
        let value = sonar_import_value_for_test(embedded(), &[]).unwrap();
        assert_eq!(value["rules"].as_array().map(Vec::len), Some(0));
        assert_eq!(value["issues"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn sonar_import_uses_native_metadata_and_flattens_flow_locations() {
        let source_range = Range {
            start: Pos { line: 2, column: 4 },
            end: Pos {
                line: 2,
                column: 24,
            },
        };
        let sink_range = Range {
            start: Pos { line: 5, column: 8 },
            end: Pos {
                line: 5,
                column: 14,
            },
        };
        let issue = Issue::new(
            "hoonarqube-go:G110",
            "Wrap this decompression reader with io.LimitReader before copying.",
            sink_range.clone(),
        )
        .with_flow(vec![
            FlowLocation::in_primary_file("Decompression reader created here.", source_range),
            FlowLocation::in_primary_file(
                "Zero-column secondary location.",
                Range {
                    start: Pos { line: 3, column: 0 },
                    end: Pos { line: 3, column: 1 },
                },
            ),
            FlowLocation::in_primary_file("Unbounded copy occurs here.", sink_range),
        ]);
        let value = sonar_import_value_for_test(
            embedded(),
            &[sample_report("src/archive.go", "go", vec![issue])],
        )
        .unwrap();
        let rule = &value["rules"][0];
        assert_eq!(rule["engineId"], "hoonarqube-native");
        assert_eq!(rule["name"], "Limit decompression output");
        assert_eq!(rule["severity"], "CRITICAL");
        assert_eq!(rule["type"], "VULNERABILITY");
        assert!(rule["description"].as_str().unwrap().contains("gosec G110"));

        let secondary = value["issues"][0]["secondaryLocations"]
            .as_array()
            .expect("flow source exported as secondary location");
        assert_eq!(secondary.len(), 2, "primary sink is not duplicated");
        assert_eq!(secondary[0]["filePath"], "src/archive.go");
        assert_eq!(secondary[0]["textRange"]["startLine"], 2);
        assert_eq!(secondary[0]["textRange"]["startColumn"], 4);
        assert_eq!(secondary[0]["textRange"]["endColumn"], 24);
        assert_eq!(secondary[1]["textRange"]["startColumn"], 0);
        assert_eq!(secondary[1]["textRange"]["endColumn"], 1);
    }

    #[test]
    fn sonar_columns_handle_unicode_paths_and_max_boundaries() {
        let issue = Issue::new(
            "python:S999999",
            "unicode finding",
            Range {
                start: Pos { line: 1, column: 1 },
                end: Pos { line: 1, column: 2 },
            },
        );
        let value = sonar_import_value_for_test(
            embedded(),
            &[sample_report("src/é.py", "python", vec![issue])],
        )
        .expect("Unicode Generic Issue output");
        let range = &value["issues"][0]["primaryLocation"]["textRange"];
        assert_eq!(range["startColumn"], 1);
        assert_eq!(range["endColumn"], 2);
        assert_eq!(
            value["issues"][0]["primaryLocation"]["filePath"],
            "src/é.py"
        );

        let boundary = Range {
            start: Pos {
                line: 1,
                column: u32::MAX,
            },
            end: Pos {
                line: 1,
                column: u32::MAX,
            },
        };
        let source = SonarSource::new("x".to_owned(), SourceLineStyle::Generic);
        let converted = sonar_text_range(&boundary, &source);
        assert!(converted.is_err());
        let error = sonar_import_value_for_test(
            embedded(),
            &[sample_report(
                "src/boundary.py",
                "python",
                vec![Issue::new("python:S999999", "overflow", boundary)],
            )],
        )
        .expect_err("maximum columns must be rejected");
        assert!(error.contains("invalid primary location range"));
    }

    #[test]
    fn sonar_columns_are_zero_based_utf16_for_six_source_variants() {
        let cases = [
            ("ascii-lf", "const value=1; value=2;\n", 15, 23, 15, 23),
            ("ascii-crlf", "const value=1; value=2;\r\n", 15, 23, 15, 23),
            (
                "ascii-no-newline",
                "const value=1; value=2;",
                15,
                23,
                15,
                23,
            ),
            (
                "unicode-bmp",
                "/*ü*/ const value=1; value=2;\n",
                21,
                29,
                21,
                29,
            ),
            (
                "unicode-astral",
                "/*😀*/ const value=1; value=2;\n",
                21,
                29,
                22,
                30,
            ),
            (
                "unicode-two-astral",
                "/*😀😀*/ const value=1; value=2;\n",
                22,
                30,
                24,
                32,
            ),
        ];
        let options = analyze::analyzer_options_bundle(embedded());
        for (label, source, native_start, native_end, expected_start, expected_end) in cases {
            let directory = temp_path(label);
            std::fs::create_dir_all(&directory).expect("create Sonar fixture directory");
            let path = directory.join("source.js");
            std::fs::write(&path, source).expect("write Sonar fixture");
            let report =
                hoonarqube_core::analyze(&path, source, &options).expect("JavaScript report");
            let native_issue = report
                .issues
                .iter()
                .find(|issue| issue.rule_key == "javascript:S122")
                .expect("S122 finding");
            assert_eq!(
                native_issue.range.start.column, native_start,
                "{label} native start"
            );
            assert_eq!(
                native_issue.range.end.column, native_end,
                "{label} native end"
            );
            let native = serde_json::to_value(&report).expect("native JSON report");
            let native_json_issue = native["issues"]
                .as_array()
                .expect("native issues")
                .iter()
                .find(|issue| issue["rule_key"] == "javascript:S122")
                .expect("native S122");
            assert_eq!(native_json_issue["range"]["start"]["column"], native_start);
            assert_eq!(native_json_issue["range"]["end"]["column"], native_end);
            let value = document(embedded(), &[report]).expect("Sonar output");
            let finding = value["issues"]
                .as_array()
                .expect("Sonar issues")
                .iter()
                .find(|issue| issue["ruleId"] == "javascript:S122")
                .expect("Sonar S122");
            let range = &finding["primaryLocation"]["textRange"];
            assert_eq!(range["startColumn"], expected_start, "{label} start");
            assert_eq!(range["endColumn"], expected_end, "{label} end");
            let _ = std::fs::remove_dir_all(directory);
        }
    }

    #[test]
    fn sonar_import_accepts_ecmascript_line_terminators_without_rewriting_source() {
        let options = analyze::analyzer_options_bundle(embedded());
        let directory = temp_path("ecmascript-line-terminators");
        std::fs::create_dir_all(&directory).expect("create Sonar fixture directory");
        for (label, separator) in [
            ("lf", "\n"),
            ("crlf", "\r\n"),
            ("cr", "\r"),
            ("line-separator", "\u{2028}"),
            ("paragraph-separator", "\u{2029}"),
        ] {
            let source = format!("let value = 1;{separator}debugger;{separator}");
            let path = directory.join(format!("{label}.js"));
            std::fs::write(&path, source.as_bytes()).expect("write Sonar fixture");
            let report =
                hoonarqube_core::analyze(&path, &source, &options).expect("JavaScript report");
            let native_issue = report
                .issues
                .iter()
                .find(|issue| issue.rule_key == "javascript:S1525")
                .expect("debugger finding");
            assert_eq!(
                native_issue.range.start.line, 2,
                "{label} native start line"
            );
            assert_eq!(native_issue.range.end.line, 2, "{label} native end line");

            let value = document(embedded(), &[report]).expect("Sonar output");
            let finding = value["issues"]
                .as_array()
                .expect("Sonar issues")
                .iter()
                .find(|issue| issue["ruleId"] == "javascript:S1525")
                .expect("Sonar debugger finding");
            let range = &finding["primaryLocation"]["textRange"];
            assert_eq!(range["startLine"], 2, "{label} Sonar start line");
            assert_eq!(range["endLine"], 2, "{label} Sonar end line");
            assert_eq!(range["startColumn"], 0, "{label} Sonar start column");
            assert_eq!(range["endColumn"], 9, "{label} Sonar end column");
            assert_eq!(
                std::fs::read(&path).expect("read source fixture"),
                source.as_bytes(),
                "{label} source bytes"
            );
        }
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn sonar_import_keeps_unicode_separators_generic_for_other_languages() {
        let issue = Issue::new(
            "python:S1",
            "finding",
            Range {
                start: Pos { line: 2, column: 0 },
                end: Pos { line: 2, column: 5 },
            },
        );
        let report = sample_report("sample.py", "python", vec![issue]);
        let source = "value = 1;\u{2028}value = 2;".to_owned();
        let mut source_cache = SonarSourceCache::default();
        let error = sonar_import_value_with_source_loader(
            embedded(),
            &[report],
            &mut |_| Ok(source.clone()),
            &mut source_cache,
        )
        .expect_err("non-ECMAScript line separators must not create Sonar lines");
        assert!(error.contains("Sonar source has no line 2"));
    }

    #[test]
    fn sonar_columns_convert_multiline_end_and_cross_file_secondary_ranges() {
        let directory = temp_path("multiline-secondary");
        std::fs::create_dir_all(&directory).expect("create Sonar fixture directory");
        let primary_path = directory.join("primary.js");
        let secondary_path = directory.join("secondary.js");
        std::fs::write(&primary_path, "header\n😀value\nfinish😀\n")
            .expect("write primary Sonar fixture");
        std::fs::write(&secondary_path, "é😀x\n").expect("write secondary Sonar fixture");
        let issue = Issue::new(
            "javascript:S999999",
            "Multiline position finding",
            Range {
                start: Pos { line: 2, column: 0 },
                end: Pos { line: 3, column: 7 },
            },
        )
        .with_flow(vec![FlowLocation {
            path: Some(secondary_path.clone()),
            message: "Cross-file secondary location.".to_owned(),
            range: Range {
                start: Pos { line: 1, column: 0 },
                end: Pos { line: 1, column: 3 },
            },
        }]);
        let report = sample_report(
            primary_path.to_str().expect("primary fixture path"),
            "javascript",
            vec![issue],
        );
        let value = document(embedded(), &[report]).expect("Sonar output");
        let primary = &value["issues"][0]["primaryLocation"]["textRange"];
        assert_eq!(primary["startLine"], 2);
        assert_eq!(primary["startColumn"], 0);
        assert_eq!(primary["endLine"], 3);
        assert_eq!(primary["endColumn"], 8);
        let secondary = &value["issues"][0]["secondaryLocations"][0]["textRange"];
        assert_eq!(secondary["startLine"], 1);
        assert_eq!(secondary["startColumn"], 0);
        assert_eq!(secondary["endLine"], 1);
        assert_eq!(secondary["endColumn"], 4);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn sonar_import_omits_text_range_for_file_level_issues() {
        let reports = vec![sample_report(
            "src/no-newline.py",
            "python",
            vec![Issue {
                rule_key: "python:S113".to_string(),
                message: "Add a new line at the end of this file \"no-newline.py\".".to_string(),
                range: Range::file_level(),
                fix: None,
                alternatives: Vec::new(),
                flows: Vec::new(),
            }],
        )];
        let value = sonar_import_value_for_test(embedded(), &reports).unwrap();
        let primary = &value["issues"][0]["primaryLocation"];
        assert_eq!(primary["filePath"], "src/no-newline.py");
        assert!(primary.get("textRange").is_none());
    }

    #[test]
    fn sonar_import_falls_back_to_info_for_unknown_rule_keys() {
        let reports = vec![sample_report(
            "src/unknown.py",
            "python",
            vec![Issue {
                rule_key: "python:S999999".to_string(),
                message: "not in the catalog".to_string(),
                range: Range {
                    start: Pos { line: 1, column: 0 },
                    end: Pos { line: 1, column: 1 },
                },
                fix: None,
                alternatives: Vec::new(),
                flows: Vec::new(),
            }],
        )];

        let value = sonar_import_value_for_test(embedded(), &reports).unwrap();
        let rule = &value["rules"][0];
        assert_eq!(rule["id"], "python:S999999");
        assert_eq!(rule["severity"], "INFO");
        assert_eq!(rule["type"], "CODE_SMELL");
        assert_eq!(rule["cleanCodeAttribute"], "CONVENTIONAL");
        assert_eq!(rule["impacts"][0]["softwareQuality"], "MAINTAINABILITY");
        assert_eq!(value["issues"][0]["ruleId"], "python:S999999");
    }

    #[test]
    fn sonar_import_keeps_same_numeric_key_distinct_across_languages() {
        let issue = |rule_key: &str| Issue {
            rule_key: rule_key.to_string(),
            message: "generic exception".to_string(),
            range: Range {
                start: Pos { line: 1, column: 0 },
                end: Pos { line: 1, column: 1 },
            },
            fix: None,
            alternatives: Vec::new(),
            flows: Vec::new(),
        };
        let reports = vec![
            sample_report("src/a.py", "python", vec![issue("python:S112")]),
            sample_report("src/a.cs", "csharp", vec![issue("csharpsquid:S112")]),
        ];

        let value = sonar_import_value_for_test(embedded(), &reports).unwrap();
        let ids = value["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .map(|rule| rule["id"].as_str().expect("id"))
            .collect::<Vec<_>>();
        assert_eq!(ids, ["csharpsquid:S112", "python:S112"]);
        assert_eq!(value["issues"][0]["ruleId"], "csharpsquid:S112");
        assert_eq!(value["issues"][1]["ruleId"], "python:S112");
    }

    #[test]
    fn sonar_import_orders_findings_independent_of_report_order() {
        let make_issue = |rule_key: &str, line: u32| {
            Issue::new(
                rule_key,
                "finding",
                Range {
                    start: Pos { line, column: 0 },
                    end: Pos { line, column: 1 },
                },
            )
        };
        let first = sample_report("zeta.py", "python", vec![make_issue("python:S112", 2)]);
        let second = sample_report("alpha.py", "python", vec![make_issue("python:S113", 1)]);

        let left = sonar_import_value_for_test(embedded(), &[first.clone(), second.clone()])
            .expect("Sonar output");
        let right =
            sonar_import_value_for_test(embedded(), &[second, first]).expect("Sonar output");

        assert_eq!(left["issues"], right["issues"]);
    }

    #[cfg(unix)]
    #[test]
    fn sonar_import_rejects_invalid_primary_path_encoding() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let mut report = sample_report("src/invalid.py", "python", Vec::new());
        report.path = std::path::PathBuf::from(OsString::from_vec(vec![
            b's', b'r', b'c', b'/', 0xff, b'.', b'p', b'y',
        ]));

        let error = sonar_import_value_for_test(embedded(), &[report]).expect_err("invalid path");
        assert!(error.contains("primary report path is not valid UTF-8"));
    }

    #[cfg(unix)]
    #[test]
    fn sonar_import_rejects_invalid_secondary_path_encoding() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let issue = Issue::new(
            "python:S2076",
            "Do not use this insecure path.",
            Range {
                start: Pos { line: 1, column: 0 },
                end: Pos { line: 1, column: 1 },
            },
        )
        .with_flow(vec![FlowLocation {
            path: Some(std::path::PathBuf::from(OsString::from_vec(vec![
                b's', b'r', b'c', b'/', 0xfe, b'.', b'p', b'y',
            ]))),
            message: "Secondary flow location.".to_string(),
            range: Range {
                start: Pos { line: 2, column: 0 },
                end: Pos { line: 2, column: 1 },
            },
        }]);
        let report = sample_report("src/valid.py", "python", vec![issue]);

        let error = sonar_import_value_for_test(embedded(), &[report]).expect_err("invalid path");
        assert!(error.contains("secondary flow path is not valid UTF-8"));
    }

    #[test]
    fn sonar_import_rejects_malformed_primary_and_flow_ranges() {
        let malformed_primary = Issue::new(
            "python:S999999",
            "reversed primary range",
            Range {
                start: Pos { line: 3, column: 0 },
                end: Pos { line: 2, column: 0 },
            },
        );
        let primary_error = sonar_import_value_for_test(
            embedded(),
            &[sample_report(
                "src/bad.py",
                "python",
                vec![malformed_primary],
            )],
        )
        .expect_err("reversed primary range");
        assert!(primary_error.contains("invalid primary location range for Sonar output"));

        let malformed_flow = Issue::new(
            "python:S999999",
            "malformed flow range",
            Range {
                start: Pos { line: 1, column: 0 },
                end: Pos { line: 1, column: 1 },
            },
        )
        .with_flow(vec![FlowLocation::in_primary_file(
            "invalid flow",
            Range {
                start: Pos { line: 0, column: 0 },
                end: Pos { line: 1, column: 1 },
            },
        )]);
        let flow_error = sonar_import_value_for_test(
            embedded(),
            &[sample_report("src/bad.py", "python", vec![malformed_flow])],
        )
        .expect_err("invalid flow range");
        assert!(flow_error.contains("invalid secondary location range for Sonar output"));
    }

    #[test]
    fn sonar_rule_id_preserves_repository_prefix() {
        assert_eq!(sonar_rule_id("typescript:S122"), "typescript:S122");
        assert_eq!(sonar_rule_id("python:LineLength"), "python:LineLength");
        assert_eq!(sonar_rule_id("S103"), "S103");
    }
}
