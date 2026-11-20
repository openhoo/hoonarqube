//! GitLab Code Quality paths, severities and stable finding fingerprints.
use hoonarqube_catalog::{Catalog, native_rule};
use hoonarqube_ir::Range;
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;

/// Returns the GitLab Code Quality severity spelling for one rule.
///
/// Sonar and native rules use the same five-level severity vocabulary. The
/// additional impact spellings are accepted for defensive handling of native
/// metadata, while unknown rule keys retain the issue instead of being
/// discarded.
fn gitlab_severity(catalog: &Catalog, rule_key: &str) -> &'static str {
    let severity = catalog
        .rule(rule_key)
        .map(|rule| rule.severity.as_str())
        .or_else(|| native_rule(rule_key).map(|rule| rule.severity))
        .unwrap_or("INFO");
    gitlab_severity_value(severity)
}

fn gitlab_severity_value(severity: &str) -> &'static str {
    match severity {
        "BLOCKER" => "blocker",
        "CRITICAL" | "HIGH" => "critical",
        "MAJOR" | "MEDIUM" => "major",
        "MINOR" | "LOW" => "minor",
        _ => "info",
    }
}

/// Normalizes a report path to GitLab's raw repository-relative path contract.
///
/// GitLab expects the path as it appears in the checkout, not a URI-escaped
/// reference. Lexical normalization removes `.` segments, rejects traversal
/// outside the checkout, and converts platform path components to `/`.
fn gitlab_path_error(context: &str, path: &std::path::Path, reason: &str) -> String {
    format!(
        "{context} is not a portable file path ({reason}): {}",
        path.display()
    )
}

fn gitlab_validate_raw_path(
    path_text: &str,
    path: &std::path::Path,
    context: &str,
) -> Result<(), String> {
    if path_text.chars().any(char::is_control) {
        return Err(gitlab_path_error(context, path, "control character"));
    }
    if cfg!(unix) && path_text.contains('\\') {
        return Err(gitlab_path_error(context, path, "backslash separator"));
    }
    Ok(())
}

fn gitlab_is_uri_scheme(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(
        characters.next(),
        Some(first) if first.is_ascii_alphabetic()
    ) && characters
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.'))
}

fn gitlab_is_uri_like_path(path_text: &str) -> bool {
    let mut candidate = path_text;
    while let Some(rest) = candidate.strip_prefix("./") {
        candidate = rest;
    }
    let Some(colon) = candidate.find(':') else {
        return false;
    };
    let scheme = &candidate[..colon];
    gitlab_is_uri_scheme(scheme) && candidate[colon + 1..].starts_with('/')
}

fn gitlab_is_drive_component(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn gitlab_validate_component(
    value: &str,
    is_first: bool,
    path: &std::path::Path,
    context: &str,
) -> Result<(), String> {
    if value.chars().any(char::is_control) {
        return Err(gitlab_path_error(context, path, "control character"));
    }
    if value.contains('\\') {
        return Err(gitlab_path_error(context, path, "backslash separator"));
    }
    if is_first && gitlab_is_drive_component(value) {
        return Err(gitlab_path_error(context, path, "drive prefix"));
    }
    Ok(())
}

fn gitlab_relative_path(
    path: &std::path::Path,
    checkout_root: &std::path::Path,
    context: &str,
) -> Result<String, String> {
    let path_text = path
        .to_str()
        .ok_or_else(|| format!("{context} is not valid UTF-8: {}", path.display()))?;
    gitlab_validate_raw_path(path_text, path, context)?;
    super::with_checkout_relative(path, checkout_root, context, |relative| {
        gitlab_encode_relative(relative, path, context)
    })
}

fn gitlab_encode_relative(
    relative: &std::path::Path,
    path: &std::path::Path,
    context: &str,
) -> Result<String, String> {
    let relative_text = relative
        .to_str()
        .ok_or_else(|| format!("{context} is not valid UTF-8: {}", path.display()))?;
    if gitlab_is_uri_like_path(relative_text) {
        return Err(gitlab_path_error(context, path, "URI-like prefix"));
    }
    let mut output = String::with_capacity(relative_text.len());
    for (index, component) in relative.components().enumerate() {
        let value = match component {
            std::path::Component::Normal(value) => value.to_str(),
            _ => None,
        }
        .ok_or_else(|| gitlab_path_error(context, path, "non-normal component"))?;
        gitlab_validate_component(value, index == 0, path, context)?;
        if index > 0 {
            output.push('/');
        }
        output.push_str(value);
    }
    if output.is_empty() {
        return Err(format!("{context} must name a file: {}", path.display()));
    }
    Ok(output)
}

/// Converts an IR range to GitLab's inclusive positive line interval.
///
/// GitLab has no file-level location sentinel. A file-level finding is
/// anchored at line 1, which is the conventional report location when the
/// analyzer has no more precise source range.
fn gitlab_lines(range: &Range, context: &str) -> Result<(u32, u32), String> {
    if range.is_file_level() {
        return Ok((1, 1));
    }
    if range.start.line == 0
        || range.end.line == 0
        || (range.start.line, range.start.column) > (range.end.line, range.end.column)
    {
        return Err(format!(
            "invalid {context} range for GitLab Code Quality output"
        ));
    }
    Ok((range.start.line, range.end.line))
}

fn gitlab_hash_field(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

fn gitlab_hash_range(hasher: &mut Sha256, range: &Range) {
    gitlab_hash_field(hasher, &range.start.line.to_be_bytes());
    gitlab_hash_field(hasher, &range.start.column.to_be_bytes());
    gitlab_hash_field(hasher, &range.end.line.to_be_bytes());
    gitlab_hash_field(hasher, &range.end.column.to_be_bytes());
}

/// Computes a stable content identity for one GitLab finding.
///
/// The version tag makes future identity changes explicit. Only the normalized
/// primary path, rule, message, and primary range participate in the identity;
/// flow and fix metadata are intentionally excluded from the fingerprint.
fn gitlab_fingerprint(file_path: &str, issue: &hoonarqube_ir::Issue) -> String {
    let mut hasher = Sha256::new();
    gitlab_hash_field(&mut hasher, b"hoonarqube-gitlab-codequality-v2");
    gitlab_hash_field(&mut hasher, file_path.as_bytes());
    gitlab_hash_field(&mut hasher, issue.rule_key.as_bytes());
    gitlab_hash_field(&mut hasher, issue.message.as_bytes());
    gitlab_hash_range(&mut hasher, &issue.range);
    let digest = hasher.finalize();
    let mut fingerprint = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut fingerprint, "{byte:02x}").expect("writing to String cannot fail");
    }
    fingerprint
}

struct GitlabFinding<'a> {
    file_path: String,
    issue: &'a hoonarqube_ir::Issue,
    severity: &'static str,
    fingerprint: String,
    start_line: u32,
    end_line: u32,
}

fn gitlab_finding_order(left: &GitlabFinding<'_>, right: &GitlabFinding<'_>) -> std::cmp::Ordering {
    (
        left.file_path.as_str(),
        left.start_line,
        left.end_line,
        left.issue.range.start.column,
        left.issue.range.end.column,
        left.issue.rule_key.as_str(),
        left.issue.message.as_str(),
        left.fingerprint.as_str(),
    )
        .cmp(&(
            right.file_path.as_str(),
            right.start_line,
            right.end_line,
            right.issue.range.start.column,
            right.issue.range.end.column,
            right.issue.rule_key.as_str(),
            right.issue.message.as_str(),
            right.fingerprint.as_str(),
        ))
}

fn gitlab_finding_value(finding: &GitlabFinding<'_>) -> serde_json::Value {
    serde_json::json!({
        "description": finding.issue.message,
        "check_name": finding.issue.rule_key,
        "fingerprint": finding.fingerprint,
        "severity": finding.severity,
        "location": {
            "path": finding.file_path,
            "lines": {
                "begin": finding.start_line,
                "end": finding.end_line,
            },
        },
    })
}

/// Builds GitLab Code Quality's one-array report from issue findings.
///
/// This format intentionally transports findings only. Project metrics and
/// completeness stay in the versioned JSON report, while `run_analyze`
/// preserves their status semantics for this issue-only output.
pub(crate) fn document(
    catalog: &Catalog,
    reports: &[hoonarqube_ir::FileReport],
) -> Result<serde_json::Value, String> {
    let checkout_root = std::env::current_dir()
        .map_err(|error| format!("cannot determine checkout root for GitLab output: {error}"))?;
    let mut findings = Vec::new();
    for report in reports {
        let file_path = gitlab_relative_path(&report.path, &checkout_root, "primary report path")?;
        for issue in &report.issues {
            let (start_line, end_line) = gitlab_lines(&issue.range, "primary location")?;
            findings.push(GitlabFinding {
                file_path: file_path.clone(),
                issue,
                severity: gitlab_severity(catalog, &issue.rule_key),
                fingerprint: gitlab_fingerprint(&file_path, issue),
                start_line,
                end_line,
            });
        }
    }
    findings.sort_by(gitlab_finding_order);
    Ok(serde_json::Value::Array(
        findings.iter().map(gitlab_finding_value).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::sample_report;
    use hoonarqube_catalog::embedded;
    use hoonarqube_ir::{FlowLocation, Issue, Pos, TextEdit};

    #[test]
    fn gitlab_codequality_maps_metadata_paths_and_fingerprints() {
        let issue = Issue::new(
            "hoonarqube-go:G110",
            "Limit decompression output.",
            Range {
                start: Pos { line: 2, column: 0 },
                end: Pos { line: 4, column: 5 },
            },
        );
        let value = document(
            embedded(),
            &[sample_report("./src/main.go", "go", vec![issue])],
        )
        .expect("GitLab Code Quality");
        let finding = &value[0];
        assert_eq!(finding["description"], "Limit decompression output.");
        assert_eq!(finding["check_name"], "hoonarqube-go:G110");
        assert_eq!(finding["severity"], "critical");
        assert_eq!(finding["location"]["path"], "src/main.go");
        assert_eq!(
            finding["location"]["lines"],
            serde_json::json!({ "begin": 2, "end": 4 })
        );
        let fingerprint = finding["fingerprint"].as_str().expect("fingerprint string");
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn gitlab_fingerprint_ignores_nested_flow_and_fix_paths() {
        fn finding(flow_path: &str, replacement: &str) -> Issue {
            Issue::new(
                "go/duplicate-condition",
                "quality finding",
                Range {
                    start: Pos { line: 2, column: 1 },
                    end: Pos { line: 2, column: 3 },
                },
            )
            .with_fix(
                "replace",
                vec![TextEdit {
                    range: Range {
                        start: Pos { line: 2, column: 1 },
                        end: Pos { line: 2, column: 3 },
                    },
                    replacement: replacement.to_string(),
                }],
            )
            .with_flow(vec![FlowLocation {
                path: Some(std::path::PathBuf::from(flow_path)),
                message: "flow location".to_string(),
                range: Range {
                    start: Pos { line: 8, column: 0 },
                    end: Pos { line: 8, column: 1 },
                },
            }])
        }

        let first = finding("/checkout-one/flow.go", "/checkout-one/fix.go");
        let second = finding("/checkout-two/flow.go", "/checkout-two/fix.go");
        assert_eq!(
            gitlab_fingerprint("src/main.go", &first),
            gitlab_fingerprint("src/main.go", &second)
        );
    }

    #[test]
    fn gitlab_severity_maps_catalog_native_and_unknown_rules() {
        assert_eq!(
            gitlab_severity(embedded(), "hoonarqube-go:G110"),
            "critical"
        );
        assert_eq!(
            gitlab_severity(embedded(), "hoonarqube-csharp:CA2022"),
            "major"
        );
        assert_eq!(gitlab_severity(embedded(), "unknown:rule"), "info");
        assert_eq!(gitlab_severity_value("BLOCKER"), "blocker");
        assert_eq!(gitlab_severity_value("LOW"), "minor");
    }

    #[cfg(unix)]
    #[test]
    fn gitlab_paths_keep_colon_filenames_and_reject_nonportable_forms() {
        let issue = Issue::new(
            "go/duplicate-condition",
            "quality finding",
            Range {
                start: Pos { line: 1, column: 0 },
                end: Pos { line: 1, column: 1 },
            },
        );
        let value = document(
            embedded(),
            &[
                sample_report("generated:main.go", "go", vec![issue.clone()]),
                sample_report("src/generated:files/main.go", "go", vec![issue]),
            ],
        )
        .expect("ordinary colon filenames");
        assert_eq!(value[0]["location"]["path"], "generated:main.go");
        assert_eq!(value[1]["location"]["path"], "src/generated:files/main.go");

        for path in [
            "C:/src/main.go",
            "file:///src/main.go",
            "src\\main.go",
            "src/\nmain.go",
        ] {
            let error = document(embedded(), &[sample_report(path, "go", Vec::new())])
                .expect_err("non-portable path");
            assert!(error.contains("portable file path"), "{path:?}: {error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn gitlab_relative_path_is_checkout_root_independent() {
        let first = gitlab_relative_path(
            std::path::Path::new("/checkout-one/src/main.go"),
            std::path::Path::new("/checkout-one"),
            "test path",
        )
        .expect("first checkout");
        let second = gitlab_relative_path(
            std::path::Path::new("/checkout-two/src/main.go"),
            std::path::Path::new("/checkout-two"),
            "test path",
        )
        .expect("second checkout");
        assert_eq!(first, "src/main.go");
        assert_eq!(first, second);
    }

    #[test]
    fn gitlab_codequality_is_empty_and_anchors_file_level_findings() {
        let clean = document(embedded(), &[]).expect("clean GitLab report");
        assert_eq!(clean, serde_json::json!([]));

        let value = document(
            embedded(),
            &[sample_report(
                "src/no-newline.py",
                "python",
                vec![Issue::new(
                    "python:S113",
                    "Add a final newline.",
                    Range::file_level(),
                )],
            )],
        )
        .expect("file-level GitLab report");
        assert_eq!(
            value[0]["location"]["lines"],
            serde_json::json!({
                "begin": 1,
                "end": 1,
            })
        );
    }

    #[test]
    fn gitlab_codequality_order_and_fingerprints_are_deterministic() {
        let make_issue = |rule_key: &str, line: u32| {
            Issue::new(
                rule_key,
                "quality finding",
                Range {
                    start: Pos { line, column: 1 },
                    end: Pos { line, column: 3 },
                },
            )
        };
        let first = sample_report(
            "z.go",
            "go",
            vec![make_issue("go/mistyped-exponentiation", 3)],
        );
        let second = sample_report("a.go", "go", vec![make_issue("go/duplicate-condition", 2)]);
        let left = document(embedded(), &[first.clone(), second.clone()]).expect("GitLab report");
        let right = document(embedded(), &[second, first]).expect("GitLab report");
        assert_eq!(
            serde_json::to_string(&left).expect("serialize"),
            serde_json::to_string(&right).expect("serialize")
        );
        assert_eq!(left[0]["location"]["path"], "a.go");
        assert_eq!(left[0]["fingerprint"], right[0]["fingerprint"]);
    }

    #[test]
    fn gitlab_codequality_rejects_outside_paths_and_malformed_ranges() {
        let outside = sample_report(
            "/tmp/outside.go",
            "go",
            vec![Issue::new(
                "go/duplicate-condition",
                "outside",
                Range {
                    start: Pos { line: 1, column: 0 },
                    end: Pos { line: 1, column: 1 },
                },
            )],
        );
        let outside_error = document(embedded(), &[outside]).expect_err("outside path");
        assert!(outside_error.contains("outside checkout root"));

        let malformed = sample_report(
            "src/bad.go",
            "go",
            vec![Issue::new(
                "go/duplicate-condition",
                "malformed",
                Range {
                    start: Pos { line: 0, column: 0 },
                    end: Pos { line: 1, column: 1 },
                },
            )],
        );
        let range_error = document(embedded(), &[malformed]).expect_err("malformed range");
        assert!(range_error.contains("invalid primary location range"));
    }

    #[cfg(unix)]
    #[test]
    fn gitlab_codequality_rejects_non_utf8_paths() {
        use std::os::unix::ffi::OsStringExt as _;

        let mut report = sample_report("valid.go", "go", Vec::new());
        report.path = std::path::PathBuf::from(std::ffi::OsString::from_vec(vec![
            b'b', 0xff, b'.', b'g', b'o',
        ]));
        let error = document(embedded(), &[report]).expect_err("invalid path");
        assert!(error.contains("primary report path is not valid UTF-8"));
    }
}
