//! SARIF 2.1.0 for the isolated GitHub Code Quality profile.
use hoonarqube_ir::Range;

fn sarif_level(severity: hoonarqube_catalog::github_quality::Severity) -> &'static str {
    use hoonarqube_catalog::github_quality::Severity;

    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info | Severity::Recommendation => "note",
    }
}

fn sarif_rule(
    definition: &hoonarqube_catalog::github_quality::QueryDefinition,
) -> serde_json::Value {
    serde_json::json!({
        "id": definition.id,
        "name": definition.title,
        "shortDescription": {
            "text": definition.title,
        },
        "helpUri": definition.help_url,
        "properties": {
            "category": definition.category,
            "severity": definition.severity,
            "help": definition.help_url,
        },
    })
}

fn sarif_region(range: &hoonarqube_ir::Range) -> serde_json::Value {
    serde_json::json!({
        "startLine": range.start.line,
        "startColumn": range.start.column.saturating_add(1),
        "endLine": range.end.line,
        "endColumn": range.end.column.saturating_add(1),
    })
}

fn sarif_location(file_path: &str, message: Option<&str>, range: &Range) -> serde_json::Value {
    let mut location = serde_json::json!({
        "physicalLocation": {
            "artifactLocation": {
                "uri": file_path,
            },
        },
    });
    if !range.is_file_level() {
        location["physicalLocation"]["region"] = sarif_region(range);
    }
    if let Some(message) = message {
        location["message"] = serde_json::json!({ "text": message });
    }
    location
}

/// Renders a GitHub Code Quality result message.
///
/// Language engines keep `$@` slots in their message templates for the names
/// carried by the finding's ordered flow locations (an overloaded method, a
/// local variable, ...). SARIF consumers only see rendered text, so each slot
/// is substituted with its flow-location name in order; a slot without a
/// matching flow location stays literal instead of silently disappearing.
fn sarif_message_text(issue: &hoonarqube_ir::Issue) -> std::borrow::Cow<'_, str> {
    if !issue.message.contains("$@") {
        return std::borrow::Cow::Borrowed(issue.message.as_str());
    }
    let mut names = issue
        .flows
        .iter()
        .flat_map(|flow| &flow.locations)
        .map(|location| location.message.as_str());
    let mut rendered = String::with_capacity(issue.message.len());
    for (index, part) in issue.message.split("$@").enumerate() {
        if index > 0 {
            rendered.push_str(names.next().unwrap_or("$@"));
        }
        rendered.push_str(part);
    }
    std::borrow::Cow::Owned(rendered)
}

fn sarif_validate_range(range: &Range, context: &str) -> Result<(), String> {
    if !range.is_file_level()
        && (range.start.line == 0
            || range.end.line == 0
            || range.start.column == u32::MAX
            || range.end.column == u32::MAX
            || (range.start.line, range.start.column) > (range.end.line, range.end.column))
    {
        return Err(format!("invalid {context} range for SARIF output"));
    }
    Ok(())
}

fn sarif_uri_byte_allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

fn sarif_percent_encode_path(path: &std::path::Path) -> Result<String, String> {
    let mut encoded = String::new();
    for (index, component) in path.components().enumerate() {
        let value = match component {
            std::path::Component::Normal(value) => value.to_str(),
            _ => None,
        }
        .ok_or_else(|| format!("SARIF artifact path is not valid UTF-8: {}", path.display()))?;
        if index != 0 {
            encoded.push('/');
        }
        for byte in value.as_bytes() {
            // RFC 3986 forbids ':' in the first segment of a relative-path
            // reference: otherwise a file name can be parsed as a URI scheme.
            if sarif_uri_byte_allowed(*byte) && !(index == 0 && *byte == b':') {
                encoded.push(char::from(*byte));
            } else {
                use std::fmt::Write as _;
                write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
            }
        }
    }
    if encoded.is_empty() {
        return Err("SARIF artifact path must not be empty".to_owned());
    }
    Ok(encoded)
}

fn sarif_artifact_uri(
    path: &std::path::Path,
    checkout_root: &std::path::Path,
    context: &str,
) -> Result<String, String> {
    if path.to_str().is_none() {
        return Err(format!("{context} is not valid UTF-8: {}", path.display()));
    }
    super::with_checkout_relative(path, checkout_root, context, sarif_percent_encode_path)
}

fn sarif_related_locations(
    file_path: &str,
    checkout_root: &std::path::Path,
    issue: &hoonarqube_ir::Issue,
) -> Result<Vec<serde_json::Value>, String> {
    issue
        .flows
        .iter()
        .flat_map(|flow| &flow.locations)
        .filter(|location| location.path.is_some() || location.range != issue.range)
        .enumerate()
        .map(|(id, location)| {
            let location_path = match location.path.as_ref() {
                Some(path) => sarif_artifact_uri(path, checkout_root, "related flow path")?,
                None => file_path.to_owned(),
            };
            let mut value =
                sarif_location(&location_path, Some(&location.message), &location.range);
            value["id"] = serde_json::json!(id);
            Ok(value)
        })
        .collect()
}

fn sarif_code_flows(
    file_path: &str,
    checkout_root: &std::path::Path,
    issue: &hoonarqube_ir::Issue,
) -> Result<Vec<serde_json::Value>, String> {
    issue
        .flows
        .iter()
        .filter(|flow| !flow.locations.is_empty())
        .map(|flow| {
            let locations: Result<Vec<_>, String> = flow
                .locations
                .iter()
                .map(|location| {
                    let location_path = match location.path.as_ref() {
                        Some(path) => sarif_artifact_uri(path, checkout_root, "related flow path")?,
                        None => file_path.to_owned(),
                    };
                    Ok(serde_json::json!({
                        "location": sarif_location(
                            &location_path,
                            Some(&location.message),
                            &location.range,
                        ),
                    }))
                })
                .collect();
            Ok(serde_json::json!({
                "threadFlows": [{
                    "locations": locations?,
                }],
            }))
        })
        .collect()
}

fn sarif_report_family(
    language: &str,
) -> Option<hoonarqube_catalog::github_quality::LanguageFamily> {
    use hoonarqube_catalog::github_quality::LanguageFamily;
    match language {
        "csharp" | "csharpsquid" => Some(LanguageFamily::CSharp),
        "go" => Some(LanguageFamily::Go),
        "java" => Some(LanguageFamily::Java),
        "javascript" | "typescript" => Some(LanguageFamily::JavaScriptTypeScript),
        "python" => Some(LanguageFamily::Python),
        "ruby" => Some(LanguageFamily::Ruby),
        _ => None,
    }
}

fn sarif_results(
    definitions: &std::collections::BTreeMap<
        String,
        &'static hoonarqube_catalog::github_quality::QueryDefinition,
    >,
    checkout_root: &std::path::Path,
    findings: Vec<(String, &hoonarqube_ir::Issue, String)>,
) -> Result<Vec<serde_json::Value>, String> {
    let rule_indices: std::collections::BTreeMap<_, _> = definitions
        .keys()
        .enumerate()
        .map(|(index, rule_id)| (rule_id.as_str(), index))
        .collect();

    let mut results = Vec::with_capacity(findings.len());
    for (file_path, issue, _) in findings {
        let definition = definitions
            .get(issue.rule_key.as_str())
            .expect("validated GitHub query");
        let mut result = serde_json::json!({
            "ruleId": issue.rule_key,
            "ruleIndex": rule_indices[issue.rule_key.as_str()],
            "level": sarif_level(definition.severity),
            "message": {
                "text": sarif_message_text(issue),
            },
            "locations": [
                sarif_location(&file_path, None, &issue.range),
            ],
        });
        let related = sarif_related_locations(&file_path, checkout_root, issue)?;
        if !related.is_empty() {
            result["relatedLocations"] = serde_json::Value::Array(related);
        }
        let code_flows = sarif_code_flows(&file_path, checkout_root, issue)?;
        if !code_flows.is_empty() {
            result["codeFlows"] = serde_json::Value::Array(code_flows);
        }
        results.push(result);
    }
    Ok(results)
}

/// Builds a deterministic SARIF 2.1.0 document from GitHub Code Quality
/// findings. The report contract carries zero-based columns, while SARIF
/// regions use one-based columns. Every rule is resolved through the official
/// GitHub query catalog; no fallback metadata is permitted.
pub(crate) fn document(reports: &[hoonarqube_ir::FileReport]) -> Result<serde_json::Value, String> {
    let checkout_root = std::env::current_dir()
        .map_err(|error| format!("cannot determine checkout root for SARIF: {error}"))?;
    let (definitions, findings) = sarif_collect_findings(reports, &checkout_root)?;
    let rules: Vec<_> = definitions
        .values()
        .map(|definition| sarif_rule(definition))
        .collect();
    let results = sarif_results(&definitions, &checkout_root, findings)?;

    let mut document = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "columnKind": "unicodeCodePoints",
            "tool": {
                "driver": {
                    "name": "Hoonarqube",
                    "informationUri": "https://github.com/openhoo/hoonarqube",
                    "rules": [],
                },
            },
            "results": [],
        }],
    });
    document["runs"][0]["tool"]["driver"]["rules"] = serde_json::Value::Array(rules);
    document["runs"][0]["results"] = serde_json::Value::Array(results);
    Ok(document)
}

type SarifDefinitions = std::collections::BTreeMap<
    String,
    &'static hoonarqube_catalog::github_quality::QueryDefinition,
>;

type SarifFinding<'a> = (String, &'a hoonarqube_ir::Issue, String);

fn sarif_collect_findings<'a>(
    reports: &'a [hoonarqube_ir::FileReport],
    checkout_root: &std::path::Path,
) -> Result<(SarifDefinitions, Vec<SarifFinding<'a>>), String> {
    let mut definitions = std::collections::BTreeMap::new();
    let mut findings = Vec::new();

    for report in reports {
        sarif_collect_report(report, checkout_root, &mut definitions, &mut findings)?;
    }

    findings.sort_by(|(path_a, issue_a, key_a), (path_b, issue_b, key_b)| {
        (
            path_a.as_str(),
            issue_a.range.start.line,
            issue_a.range.start.column,
            issue_a.range.end.line,
            issue_a.range.end.column,
            issue_a.rule_key.as_str(),
            issue_a.message.as_str(),
            key_a.as_str(),
        )
            .cmp(&(
                path_b.as_str(),
                issue_b.range.start.line,
                issue_b.range.start.column,
                issue_b.range.end.line,
                issue_b.range.end.column,
                issue_b.rule_key.as_str(),
                issue_b.message.as_str(),
                key_b.as_str(),
            ))
    });

    Ok((definitions, findings))
}

fn sarif_collect_report<'a>(
    report: &'a hoonarqube_ir::FileReport,
    checkout_root: &std::path::Path,
    definitions: &mut std::collections::BTreeMap<
        String,
        &'static hoonarqube_catalog::github_quality::QueryDefinition,
    >,
    findings: &mut Vec<(String, &'a hoonarqube_ir::Issue, String)>,
) -> Result<(), String> {
    let report_family = sarif_report_family(&report.language);
    let file_path = sarif_artifact_uri(&report.path, checkout_root, "primary report path")?;
    for issue in &report.issues {
        sarif_collect_issue(
            report,
            report_family,
            checkout_root,
            &file_path,
            issue,
            definitions,
            findings,
        )?;
    }
    Ok(())
}

fn sarif_collect_issue<'a>(
    report: &'a hoonarqube_ir::FileReport,
    report_family: Option<hoonarqube_catalog::github_quality::LanguageFamily>,
    checkout_root: &std::path::Path,
    file_path: &str,
    issue: &'a hoonarqube_ir::Issue,
    definitions: &mut std::collections::BTreeMap<
        String,
        &'static hoonarqube_catalog::github_quality::QueryDefinition,
    >,
    findings: &mut Vec<(String, &'a hoonarqube_ir::Issue, String)>,
) -> Result<(), String> {
    let report_family = report_family.ok_or_else(|| {
        format!(
            "report language {:?} has no GitHub Code Quality family",
            report.language
        )
    })?;
    let definition = hoonarqube_catalog::github_quality::query(&issue.rule_key)
        .ok_or_else(|| format!("unknown GitHub Code Quality query id: {}", issue.rule_key))?;
    if definition.language != report_family {
        return Err(format!(
            "GitHub Code Quality query {} belongs to {}, not report language {}",
            issue.rule_key,
            definition.language.as_str(),
            report.language
        ));
    }
    sarif_validate_range(&issue.range, "primary location")?;
    sarif_validate_flow_locations(checkout_root, issue)?;
    definitions.insert(issue.rule_key.clone(), definition);
    let canonical_issue = serde_json::to_string(issue).map_err(|error| {
        format!(
            "cannot canonicalize SARIF finding {}: {error}",
            issue.rule_key
        )
    })?;
    findings.push((file_path.to_owned(), issue, canonical_issue));
    Ok(())
}

fn sarif_validate_flow_locations(
    checkout_root: &std::path::Path,
    issue: &hoonarqube_ir::Issue,
) -> Result<(), String> {
    for flow in &issue.flows {
        for location in &flow.locations {
            sarif_validate_range(&location.range, "related location")?;
            if let Some(path) = location.path.as_ref() {
                sarif_artifact_uri(path, checkout_root, "related flow path")?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyze, test_support::sample_report};
    use hoonarqube_catalog::RuleProfile;
    use hoonarqube_ir::{FlowLocation, Issue, Pos};

    #[test]
    fn sarif_maps_github_metadata_levels_and_columns() {
        let issue = Issue::new(
            "go/duplicate-condition",
            "Duplicate condition.",
            Range {
                start: Pos { line: 2, column: 0 },
                end: Pos { line: 2, column: 4 },
            },
        );
        let value = document(&[sample_report("src/main.go", "go", vec![issue])]).expect("SARIF");
        let run = &value["runs"][0];
        let rule = &run["tool"]["driver"]["rules"][0];
        assert_eq!(rule["id"], "go/duplicate-condition");
        assert_eq!(rule["name"], "Duplicate 'if' condition");
        assert_eq!(rule["properties"]["category"], "Reliability");
        assert_eq!(rule["properties"]["severity"], "Error");
        assert_eq!(rule["properties"]["help"], rule["helpUri"]);
        assert_eq!(run["results"][0]["level"], "error");
        assert_eq!(
            run["results"][0]["locations"][0]["physicalLocation"]["region"],
            serde_json::json!({
                "startLine": 2,
                "startColumn": 1,
                "endLine": 2,
                "endColumn": 5,
            })
        );
        assert_eq!(
            run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/main.go"
        );
        assert!(run["results"][0]["partialFingerprints"].is_null());
    }

    #[test]
    fn sarif_exports_flows_as_related_locations_and_code_flows() {
        let source_range = Range {
            start: Pos { line: 1, column: 2 },
            end: Pos { line: 1, column: 8 },
        };
        let sink_range = Range {
            start: Pos { line: 4, column: 1 },
            end: Pos { line: 4, column: 7 },
        };
        let issue = Issue::new(
            "go/duplicate-condition",
            "Duplicate condition.",
            sink_range.clone(),
        )
        .with_flow(vec![
            FlowLocation::in_primary_file("Condition source.", source_range),
            FlowLocation::in_primary_file("Condition sink.", sink_range),
        ]);
        let value = document(&[sample_report("main.go", "go", vec![issue])]).expect("SARIF");
        let result = &value["runs"][0]["results"][0];
        assert_eq!(result["relatedLocations"].as_array().map(Vec::len), Some(1));
        assert_eq!(result["relatedLocations"][0]["id"], 0);
        assert_eq!(
            result["relatedLocations"][0]["message"]["text"],
            "Condition source."
        );
        assert_eq!(result["codeFlows"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            result["codeFlows"][0]["threadFlows"][0]["locations"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            result["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]["physicalLocation"]
                ["region"]["startColumn"],
            3
        );
    }

    #[test]
    fn sarif_substitutes_placeholder_names_in_engine_message_templates() {
        // Pinned java and ruby engine message templates carrying `$@` slots
        // (issue #372): each slot renders with its ordered flow-location
        // name instead of the literal placeholder.
        fn span(line: u32, start_column: u32, end_column: u32) -> Range {
            Range {
                start: Pos {
                    line,
                    column: start_column,
                },
                end: Pos {
                    line,
                    column: end_column,
                },
            }
        }
        let java_confusing_signature = Issue::new(
            "java/confusing-method-signature",
            "Method Gson.toJson(..) could be confused with overloaded method $@, since dispatch depends on static types.",
            Range {
                start: Pos {
                    line: 707,
                    column: 2,
                },
                end: Pos {
                    line: 711,
                    column: 3,
                },
            },
        )
        .with_flow(vec![FlowLocation::in_primary_file("toJson", span(721, 11, 17))]);
        let java_misleading_indentation = Issue::new(
            "java/misleading-indentation",
            "Indentation suggests that $@ belongs to $@, but this is not the case; consider adding braces or adjusting indentation.",
            span(3, 0, 4),
        )
        .with_flow(vec![
            FlowLocation::in_primary_file("the next statement", span(4, 0, 4)),
            FlowLocation::in_primary_file("the control structure", span(2, 0, 1)),
        ]);
        let ruby_useless_assignment = Issue::new(
            "rb/useless-assignment-to-local",
            "This assignment to $@ is useless, since its value is never read.",
            span(1, 2, 7),
        )
        // The flow range equals the primary range, so the name-bearing
        // location is filtered out of relatedLocations yet must still feed
        // message substitution.
        .with_flow(vec![FlowLocation::in_primary_file("value", span(1, 2, 7))]);
        let ruby_uninitialized = Issue::new(
            "rb/uninitialized-local-variable",
            "Local variable $@ may be used before it is initialized.",
            span(4, 2, 9),
        )
        .with_flow(vec![FlowLocation::in_primary_file(
            "fn_task",
            span(6, 2, 9),
        )]);
        let value = document(&[
            sample_report(
                "src/Main.java",
                "java",
                vec![java_confusing_signature, java_misleading_indentation],
            ),
            sample_report(
                "lib/app.rb",
                "ruby",
                vec![ruby_useless_assignment, ruby_uninitialized],
            ),
        ])
        .expect("SARIF");
        let rendered = |rule: &str| {
            value["runs"][0]["results"]
                .as_array()
                .expect("results")
                .iter()
                .find(|result| result["ruleId"] == rule)
                .unwrap_or_else(|| panic!("missing result for {rule}"))["message"]["text"]
                .as_str()
                .expect("message text")
                .to_owned()
        };
        assert_eq!(
            rendered("java/confusing-method-signature"),
            "Method Gson.toJson(..) could be confused with overloaded method toJson, since dispatch depends on static types.",
        );
        assert_eq!(
            rendered("java/misleading-indentation"),
            "Indentation suggests that the next statement belongs to the control structure, but this is not the case; consider adding braces or adjusting indentation.",
        );
        assert_eq!(
            rendered("rb/useless-assignment-to-local"),
            "This assignment to value is useless, since its value is never read.",
        );
        assert_eq!(
            rendered("rb/uninitialized-local-variable"),
            "Local variable fn_task may be used before it is initialized.",
        );
    }

    #[test]
    fn sarif_clean_output_has_no_rules_or_results() {
        let value = document(&[]).expect("clean SARIF");
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(
            value["$schema"],
            "https://json.schemastore.org/sarif-2.1.0.json"
        );
        assert_eq!(
            value["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .map(Vec::len),
            Some(0)
        );
        assert_eq!(
            value["runs"][0]["results"].as_array().map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn sarif_declares_character_columns_for_non_bmp_source() {
        let source = "const marker = '😀'; const value = 1; value = 2;\n";
        let report = hoonarqube_core::analyze(
            std::path::Path::new("unicode.js"),
            source,
            &analyze::AnalyzerOptionsBundle {
                profile: RuleProfile::GithubCodeQuality,
                ..analyze::AnalyzerOptionsBundle::default()
            },
        )
        .expect("JavaScript report");
        let value = document(&[report]).expect("SARIF");
        let run = &value["runs"][0];
        let finding = run["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|result| result["ruleId"] == "js/assignment-to-constant")
            .expect("constant reassignment");
        let expected = source[..source.rfind("value = 2").unwrap()].chars().count() + 1;
        assert_eq!(
            finding["locations"][0]["physicalLocation"]["region"]["startColumn"],
            expected
        );
        assert_eq!(run["columnKind"], "unicodeCodePoints");
    }

    #[cfg(unix)]
    #[test]
    fn sarif_colons_cannot_turn_relative_artifacts_into_uri_schemes() {
        let root = std::env::current_dir().unwrap();
        for (path, expected) in [
            ("generated:main.go", "generated%3Amain.go"),
            ("generated:files/main.go", "generated%3Afiles/main.go"),
            ("src/generated:main.go", "src/generated:main.go"),
        ] {
            assert_eq!(
                sarif_artifact_uri(std::path::Path::new(path), &root, "test").unwrap(),
                expected,
            );
        }
    }

    #[test]
    fn sarif_order_is_deterministic_without_coordinate_fingerprints() {
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
        let left = document(&[first.clone(), second.clone()]).expect("SARIF");
        let right = document(&[second, first]).expect("SARIF");
        assert_eq!(
            serde_json::to_string(&left).expect("serialize"),
            serde_json::to_string(&right).expect("serialize")
        );
        assert_eq!(
            left["runs"][0]["tool"]["driver"]["rules"][0]["id"],
            "go/duplicate-condition"
        );
        assert!(left["runs"][0]["results"][0]["partialFingerprints"].is_null());
    }

    #[test]
    fn sarif_rejects_unknown_github_query_ids() {
        let issue = Issue::new(
            "go/not-a-real-query",
            "unknown",
            Range {
                start: Pos { line: 1, column: 0 },
                end: Pos { line: 1, column: 1 },
            },
        );
        let error =
            document(&[sample_report("unknown.go", "go", vec![issue])]).expect_err("unknown query");
        assert!(error.contains("unknown GitHub Code Quality query id"));
    }

    #[cfg(unix)]
    #[test]
    fn sarif_rejects_invalid_primary_and_related_path_encoding() {
        use std::os::unix::ffi::OsStringExt as _;

        let mut primary = sample_report("valid.go", "go", Vec::new());
        primary.path = std::path::PathBuf::from(std::ffi::OsString::from_vec(vec![
            b'v', b'a', b'l', b'i', b'd', b'/', 0xff, b'.', b'g', b'o',
        ]));
        let error = document(&[primary]).expect_err("invalid primary path");
        assert!(error.contains("primary report path is not valid UTF-8"));

        let issue = Issue::new(
            "go/duplicate-condition",
            "finding",
            Range {
                start: Pos { line: 1, column: 0 },
                end: Pos { line: 1, column: 1 },
            },
        )
        .with_flow(vec![FlowLocation {
            path: Some(std::path::PathBuf::from(std::ffi::OsString::from_vec(
                vec![b'f', b'/', 0xfe, b'.', b'g', b'o'],
            ))),
            message: "related".to_string(),
            range: Range {
                start: Pos { line: 2, column: 0 },
                end: Pos { line: 2, column: 1 },
            },
        }]);
        let error = document(&[sample_report("valid.go", "go", vec![issue])])
            .expect_err("invalid related path");
        assert!(error.contains("related flow path is not valid UTF-8"));
    }

    #[test]
    fn sarif_percent_encodes_unicode_artifact_paths() {
        let issue = Issue::new(
            "go/duplicate-condition",
            "finding",
            Range {
                start: Pos { line: 1, column: 0 },
                end: Pos { line: 1, column: 1 },
            },
        );
        let value = document(&[sample_report("dir/é space.go", "go", vec![issue])]).expect("SARIF");

        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "dir/%C3%A9%20space.go"
        );
    }

    #[test]
    fn sarif_percent_encodes_special_artifact_path_bytes() {
        let issue = Issue::new(
            "go/duplicate-condition",
            "finding",
            Range {
                start: Pos { line: 1, column: 0 },
                end: Pos { line: 1, column: 1 },
            },
        );
        let value = document(&[sample_report("dir/a b#?.go", "go", vec![issue])]).expect("SARIF");
        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "dir/a%20b%23%3F.go"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sarif_rejects_absolute_paths_outside_checkout_root() {
        let mut report = sample_report("/tmp/outside.go", "go", Vec::new());
        report.path = std::path::PathBuf::from("/tmp/outside.go");
        let error = document(&[report]).expect_err("outside path");
        assert!(error.contains("outside checkout root"));
    }

    #[test]
    fn sarif_rejects_rule_family_mismatch() {
        let issue = Issue::new(
            "py/explicit-call-to-delete",
            "wrong family",
            Range {
                start: Pos { line: 1, column: 0 },
                end: Pos { line: 1, column: 1 },
            },
        );
        let error =
            document(&[sample_report("wrong.go", "go", vec![issue])]).expect_err("family mismatch");
        assert!(error.contains("belongs to Python"));
    }

    #[test]
    fn sarif_rejects_unrepresentable_columns() {
        let issue = Issue::new(
            "go/duplicate-condition",
            "finding",
            Range {
                start: Pos {
                    line: 1,
                    column: u32::MAX,
                },
                end: Pos {
                    line: 1,
                    column: u32::MAX,
                },
            },
        );
        let error = document(&[sample_report("overflow.go", "go", vec![issue])])
            .expect_err("column overflow");
        assert!(error.contains("invalid primary location range"));
    }
}
