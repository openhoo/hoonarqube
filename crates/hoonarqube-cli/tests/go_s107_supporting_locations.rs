//! Full CLI S107 documents from independently qualified actual source controls.
//! Qualification: 73f163049214ce13e7b1a114ad34c31ceca421a5029a0ef0083b30d80e818ec4.
//! Literal/variadic/astral and custom-reference Max2/native Max7 residuals remain.
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);
impl Fixture {
    fn new(sources: &[(&str, &str)]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("hoonarqube-s107-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("source")).unwrap();
        for (path, source) in sources {
            let destination = root.join("source").join(path);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::write(destination, source).unwrap();
        }
        Self(root)
    }

    fn document(
        &self,
        label: &str,
        profile: &str,
        format: &str,
        exit: i32,
        stderr: &str,
    ) -> Vec<u8> {
        let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(self.0.join("source"))
            .args([
                "analyze",
                ".",
                "--profile",
                profile,
                "--format",
                format,
                "--cache-dir",
            ])
            .arg(self.0.join("cache").join(format))
            .output()
            .unwrap();
        if let Some(capture) = std::env::var_os("HOONARQUBE_REGRESSION_CAPTURE") {
            let capture = PathBuf::from(capture);
            std::fs::create_dir_all(&capture).unwrap();
            let prefix = format!("s107-{label}-{format}");
            std::fs::write(capture.join(format!("{prefix}.stdout")), &output.stdout).unwrap();
            std::fs::write(capture.join(format!("{prefix}.stderr")), &output.stderr).unwrap();
            for (path, bytes) in self.cache_snapshot(format) {
                let destination = capture.join(format!("{prefix}-cache")).join(
                    path.strip_prefix(self.0.join("cache").join(format))
                        .unwrap(),
                );
                std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
                std::fs::write(destination, bytes).unwrap();
            }
        }
        assert_eq!(
            output.status.code(),
            Some(exit),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stderr, stderr.as_bytes());
        output.stdout
    }

    fn cache_snapshot(&self, format: &str) -> Vec<(PathBuf, Vec<u8>)> {
        fn collect(root: &Path, output: &mut Vec<(PathBuf, Vec<u8>)>) {
            if !root.exists() {
                return;
            }
            for entry in std::fs::read_dir(root).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    collect(&path, output);
                } else {
                    output.push((path.clone(), std::fs::read(path).unwrap()));
                }
            }
        }
        let mut output = Vec::new();
        collect(&self.0.join("cache").join(format), &mut output);
        output.sort();
        output
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn complete(scope: &str, format: &str) {
    let (sources, expected) = match (scope, format) {
        ("default", "json") => (DEFAULT_SOURCES, EXPECTED_DEFAULT_NATIVE),
        ("default", "sonar") => (DEFAULT_SOURCES, EXPECTED_DEFAULT_GENERIC),
        ("custom", "json") => (CUSTOM_SOURCES, EXPECTED_CUSTOM_NATIVE),
        ("custom", "sonar") => (CUSTOM_SOURCES, EXPECTED_CUSTOM_GENERIC),
        _ => unreachable!(),
    };
    let fixture = Fixture::new(sources);
    let cold = fixture.document(&format!("{scope}-cold"), "sonar-parity", format, 0, "");
    assert_eq!(cold, expected.as_bytes());
    let cache = fixture.cache_snapshot(format);
    assert_eq!(cache.len(), sources.len());
    let warm = fixture.document(&format!("{scope}-warm"), "sonar-parity", format, 0, "");
    assert_eq!(warm, cold);
    assert_eq!(fixture.cache_snapshot(format), cache);
    for (path, source) in sources {
        assert_eq!(
            std::fs::read(fixture.0.join("source").join(path)).unwrap(),
            source.as_bytes()
        );
    }
}

fn original(format: &str) {
    let fixture = Fixture::new(ORIGINAL_SOURCES);
    let bytes = fixture.document("original", "strict", format, 0, "");
    let actual: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let expected: serde_json::Value = serde_json::from_str(if format == "json" {
        EXPECTED_ORIGINAL_NATIVE_ISSUES
    } else {
        EXPECTED_ORIGINAL_GENERIC_ISSUES
    })
    .unwrap();
    if format == "json" {
        assert_eq!(actual["project"]["complete"], true);
        assert_eq!(actual["files"][0]["issues"], expected);
        assert_eq!(actual["files"][1]["issues"], serde_json::json!([]));
    } else {
        assert_eq!(actual["issues"], expected);
    }
}

fn malformed(format: &str) {
    let fixture = Fixture::new(MALFORMED_SOURCES);
    let expected = if format == "json" {
        EXPECTED_MALFORMED_NATIVE
    } else {
        EXPECTED_MALFORMED_GENERIC
    };
    assert_eq!(
        fixture.document("malformed", "strict", format, 2, EXPECTED_MALFORMED_STDERR),
        expected.as_bytes()
    );
    for (path, source) in MALFORMED_SOURCES {
        assert_eq!(
            std::fs::read(fixture.0.join("source").join(path)).unwrap(),
            source.as_bytes()
        );
    }
}

#[test]
fn s107_original_native_exact_issue() {
    original("json");
}
#[test]
fn s107_original_generic_exact_issue() {
    original("sonar");
}
#[test]
fn s107_default_native_full_document_cold_and_warm() {
    complete("default", "json");
}
#[test]
fn s107_default_generic_full_document_cold_and_warm() {
    complete("default", "sonar");
}
#[test]
fn s107_custom_sources_native_max7_full_document_cold_and_warm() {
    complete("custom", "json");
}
#[test]
fn s107_custom_sources_generic_max7_full_document_cold_and_warm() {
    complete("custom", "sonar");
}
#[test]
fn s107_malformed_native_full_document_remains_incomplete_exit2() {
    malformed("json");
}
#[test]
fn s107_malformed_generic_full_document_remains_incomplete_exit2() {
    malformed("sonar");
}

const DEFAULT_SOURCES: &[(&str, &str)] = &[
    (
        "01-separated-eight.go",
        "package probe\nfunc separatedEight(a int,b int,c int,d int,e int,f int,g int,h int) { println(a,b,c,d,e,f,g,h) }\n",
    ),
    (
        "02-separated-nine.go",
        "package probe\nfunc separatedNine(a int,b int,c int,d int,e int,f int,g int,h int,i int) { println(a,b,c,d,e,f,g,h,i) }\n",
    ),
    (
        "03-grouped-nine.go",
        "package probe\nfunc groupedNine(a,b,c,d,e,f,g,h,i int) { println(a,b,c,d,e,f,g,h,i) }\n",
    ),
    (
        "04-mixed-group.go",
        "package probe\nfunc mixedGroups(a,b,c,d,e,f int,g,h,i string) { println(a,b,c,d,e,f,g,h,i) }\n",
    ),
    (
        "05-method-boundary.go",
        "package probe\ntype Receiver struct{}\nfunc (r Receiver) methodSeven(a,b,c,d,e,f,g int) { println(a,b,c,d,e,f,g) }\nfunc (r Receiver) methodEight(a,b,c,d,e,f,g,h int) { println(a,b,c,d,e,f,g,h) }\n",
    ),
    (
        "06-literal.go",
        "package probe\nvar literal = func(a,b,c,d,e,f,g,h int) { println(a,b,c,d,e,f,g,h) }\n",
    ),
    (
        "07-variadic.go",
        "package probe\nfunc variadic(a,b,c,d,e,f,g int,h ...int) { println(a,b,c,d,e,f,g,h) }\n",
    ),
    (
        "08-negative-and-position.go",
        "package probe\r\nfunc boundarySeven(a,b,c,d,e,f,g int) { println(a,b,c,d,e,f,g) }\r\n/* 😀 */ func positionEight(\r\n a,b,c,d,e,f,g,\r\n h int,\r\n) { println(a,b,c,d,e,f,g,h) }\r\n",
    ),
];
const CUSTOM_SOURCES: &[(&str, &str)] = &[
    (
        "01-custom-grouped.go",
        "package probe\nfunc customGrouped(a,b,c int) { println(a,b,c) }\n",
    ),
    (
        "02-custom-separated.go",
        "package probe\nfunc customSeparated(a int,b int,c int) { println(a,b,c) }\n",
    ),
];
const ORIGINAL_SOURCES: &[(&str, &str)] = &[
    (
        "s107_bad.go",
        "// Hoonarqube oracle fixture: go:S107 bad\npackage oracle\nfunc many(a,b,c,d,e,f,g,h int) { println(a,b,c,d,e,f,g,h) }\n",
    ),
    (
        "s107_good.go",
        "// Hoonarqube oracle fixture: go:S107 good\npackage oracle\n\n// Each function does a part of what the original setCoordinates function was doing, so confusion risks are lower\nfunc setOrigin(x int, y int, z int) {\n   // ...\n}\n\nfunc setSize(width int, height int, depth int) {\n   // ...\n}\n",
    ),
];
const EXPECTED_DEFAULT_NATIVE: &str = r###"{"schema_version":1,"files":[{"path":"./01-separated-eight.go","language":"go","issues":[{"rule_key":"go:S107","message":"This function has 8 parameters, which is greater than the 7 authorized.","range":{"start":{"line":2,"column":5},"end":{"line":2,"column":19}},"flows":[{"locations":[{"message":"","range":{"start":{"line":2,"column":62},"end":{"line":2,"column":67}}}]}]}],"metrics":{"lines":3,"code_lines":2,"comment_lines":0}},{"path":"./02-separated-nine.go","language":"go","issues":[{"rule_key":"go:S107","message":"This function has 9 parameters, which is greater than the 7 authorized.","range":{"start":{"line":2,"column":5},"end":{"line":2,"column":18}},"flows":[{"locations":[{"message":"","range":{"start":{"line":2,"column":61},"end":{"line":2,"column":66}}}]},{"locations":[{"message":"","range":{"start":{"line":2,"column":67},"end":{"line":2,"column":72}}}]}]}],"metrics":{"lines":3,"code_lines":2,"comment_lines":0}},{"path":"./03-grouped-nine.go","language":"go","issues":[{"rule_key":"go:S107","message":"This function has 9 parameters, which is greater than the 7 authorized.","range":{"start":{"line":2,"column":5},"end":{"line":2,"column":16}},"flows":[{"locations":[{"message":"","range":{"start":{"line":2,"column":31},"end":{"line":2,"column":32}}}]},{"locations":[{"message":"","range":{"start":{"line":2,"column":33},"end":{"line":2,"column":38}}}]}]}],"metrics":{"lines":3,"code_lines":2,"comment_lines":0}},{"path":"./04-mixed-group.go","language":"go","issues":[{"rule_key":"go:S107","message":"This function has 9 parameters, which is greater than the 7 authorized.","range":{"start":{"line":2,"column":5},"end":{"line":2,"column":16}},"flows":[{"locations":[{"message":"","range":{"start":{"line":2,"column":35},"end":{"line":2,"column":36}}}]},{"locations":[{"message":"","range":{"start":{"line":2,"column":37},"end":{"line":2,"column":45}}}]}]}],"metrics":{"lines":3,"code_lines":2,"comment_lines":0}},{"path":"./05-method-boundary.go","language":"go","issues":[{"rule_key":"go:S107","message":"This function has 8 parameters, which is greater than the 7 authorized.","range":{"start":{"line":4,"column":18},"end":{"line":4,"column":29}},"flows":[{"locations":[{"message":"","range":{"start":{"line":4,"column":44},"end":{"line":4,"column":49}}}]}]}],"metrics":{"lines":5,"code_lines":4,"comment_lines":0}},{"path":"./06-literal.go","language":"go","issues":[{"rule_key":"go:S107","message":"This function has 8 parameters, which is greater than the 7 authorized.","range":{"start":{"line":2,"column":18},"end":{"line":2,"column":39}},"flows":[{"locations":[{"message":"","range":{"start":{"line":2,"column":33},"end":{"line":2,"column":38}}}]}]}],"metrics":{"lines":3,"code_lines":2,"comment_lines":0}},{"path":"./07-variadic.go","language":"go","issues":[],"metrics":{"lines":3,"code_lines":2,"comment_lines":0}},{"path":"./08-negative-and-position.go","language":"go","issues":[{"rule_key":"go:S107","message":"This function has 8 parameters, which is greater than the 7 authorized.","range":{"start":{"line":3,"column":13},"end":{"line":3,"column":26}},"flows":[{"locations":[{"message":"","range":{"start":{"line":5,"column":1},"end":{"line":5,"column":6}}}]}]}],"metrics":{"lines":7,"code_lines":6,"comment_lines":1}}],"project":{"metrics":{"files":8,"lines":30,"code_lines":22,"comment_lines":1},"files":[{"path":"./01-separated-eight.go","classification":"source","status":"complete","metrics":{"lines":3,"code_lines":2,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./02-separated-nine.go","classification":"source","status":"complete","metrics":{"lines":3,"code_lines":2,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./03-grouped-nine.go","classification":"source","status":"complete","metrics":{"lines":3,"code_lines":2,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./04-mixed-group.go","classification":"source","status":"complete","metrics":{"lines":3,"code_lines":2,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./05-method-boundary.go","classification":"source","status":"complete","metrics":{"lines":5,"code_lines":4,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./06-literal.go","classification":"source","status":"complete","metrics":{"lines":3,"code_lines":2,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./07-variadic.go","classification":"source","status":"complete","metrics":{"lines":3,"code_lines":2,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./08-negative-and-position.go","classification":"source","status":"complete","metrics":{"lines":7,"code_lines":6,"comment_lines":1},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null}],"duplications":[],"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"complete":true,"warnings":[],"roots":["."]},"parity":{"reference":{"sonarqube_version":"2025.4.4.119049","profile":"sonar-parity","captured_at_utc":"2026-08-22T14:45:03.705491626Z","capture_sha256":"f423f0d8b8001af94dbf28bb8e3af368702447a9318b1200650cb3f9b3a332f0"},"active_rules":[{"key":"go:S100","parameters":[{"key":"formatForTests","default_value":"^(_|[a-zA-Z0-9_]+)$","parameter_type":"STRING"},{"key":"format","default_value":"^(_|[a-zA-Z0-9]+)$","parameter_type":"STRING"}],"fidelity":"community-base"},{"key":"go:S103","parameters":[{"key":"maximumLineLength","default_value":"120","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S104","parameters":[{"key":"Max","default_value":"750","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S1067","parameters":[{"key":"max","default_value":"3","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S107","parameters":[{"key":"Max","default_value":"7","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S108","parameters":[],"fidelity":"community-base"},{"key":"go:S1110","parameters":[],"fidelity":"community-base"},{"key":"go:S1125","parameters":[],"fidelity":"community-base"},{"key":"go:S1134","parameters":[],"fidelity":"community-base"},{"key":"go:S1135","parameters":[],"fidelity":"community-base"},{"key":"go:S1145","parameters":[],"fidelity":"community-base"},{"key":"go:S1151","parameters":[{"key":"max","default_value":"6","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S117","parameters":[{"key":"format","default_value":"^(_|[a-zA-Z0-9]+)$","parameter_type":"STRING"}],"fidelity":"community-base"},{"key":"go:S1186","parameters":[],"fidelity":"community-base"},{"key":"go:S1192","parameters":[{"key":"threshold","default_value":"3","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S122","parameters":[],"fidelity":"community-base"},{"key":"go:S126","parameters":[],"fidelity":"community-base"},{"key":"go:S131","parameters":[],"fidelity":"community-base"},{"key":"go:S1314","parameters":[],"fidelity":"community-base"},{"key":"go:S134","parameters":[{"key":"max","default_value":"4","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S138","parameters":[{"key":"max","default_value":"120","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S1451","parameters":[{"key":"headerFormat","parameter_type":"TEXT"},{"key":"isRegularExpression","default_value":"false","parameter_type":"BOOLEAN"}],"fidelity":"community-base"},{"key":"go:S1479","parameters":[{"key":"maximum","default_value":"30","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S1656","parameters":[],"fidelity":"community-base"},{"key":"go:S1763","parameters":[],"fidelity":"community-base"},{"key":"go:S1764","parameters":[],"fidelity":"community-base"},{"key":"go:S1821","parameters":[],"fidelity":"community-base"},{"key":"go:S1862","parameters":[],"fidelity":"community-base"},{"key":"go:S1871","parameters":[],"fidelity":"community-base"},{"key":"go:S1940","parameters":[],"fidelity":"community-base"},{"key":"go:S2260","parameters":[],"fidelity":"community-base"},{"key":"go:S2757","parameters":[],"fidelity":"community-base"},{"key":"go:S3776","parameters":[{"key":"threshold","default_value":"15","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S3923","parameters":[],"fidelity":"community-base"},{"key":"go:S4144","parameters":[],"fidelity":"community-base"},{"key":"go:S4663","parameters":[],"fidelity":"community-base"}],"scope":{"roots":["."],"test_include":[],"exclude":[],"generated_include":[],"vendor_include":[],"duplication_exclude":[],"file_counts":{"excluded":0,"generated":0,"source":8,"test":0,"vendor":0}},"semantic_context":{"typescript":"not_applicable","csharp":"not_applicable"},"completeness":"complete_native_analysis","rule_set_violations":[]}}
"###;
const EXPECTED_DEFAULT_GENERIC: &str = r###"{"issues":[{"primaryLocation":{"filePath":"./01-separated-eight.go","message":"This function has 8 parameters, which is greater than the 7 authorized.","textRange":{"endColumn":19,"endLine":2,"startColumn":5,"startLine":2}},"ruleId":"go:S107","secondaryLocations":[{"filePath":"./01-separated-eight.go","message":"","textRange":{"endColumn":67,"endLine":2,"startColumn":62,"startLine":2}}]},{"primaryLocation":{"filePath":"./02-separated-nine.go","message":"This function has 9 parameters, which is greater than the 7 authorized.","textRange":{"endColumn":18,"endLine":2,"startColumn":5,"startLine":2}},"ruleId":"go:S107","secondaryLocations":[{"filePath":"./02-separated-nine.go","message":"","textRange":{"endColumn":66,"endLine":2,"startColumn":61,"startLine":2}},{"filePath":"./02-separated-nine.go","message":"","textRange":{"endColumn":72,"endLine":2,"startColumn":67,"startLine":2}}]},{"primaryLocation":{"filePath":"./03-grouped-nine.go","message":"This function has 9 parameters, which is greater than the 7 authorized.","textRange":{"endColumn":16,"endLine":2,"startColumn":5,"startLine":2}},"ruleId":"go:S107","secondaryLocations":[{"filePath":"./03-grouped-nine.go","message":"","textRange":{"endColumn":32,"endLine":2,"startColumn":31,"startLine":2}},{"filePath":"./03-grouped-nine.go","message":"","textRange":{"endColumn":38,"endLine":2,"startColumn":33,"startLine":2}}]},{"primaryLocation":{"filePath":"./04-mixed-group.go","message":"This function has 9 parameters, which is greater than the 7 authorized.","textRange":{"endColumn":16,"endLine":2,"startColumn":5,"startLine":2}},"ruleId":"go:S107","secondaryLocations":[{"filePath":"./04-mixed-group.go","message":"","textRange":{"endColumn":36,"endLine":2,"startColumn":35,"startLine":2}},{"filePath":"./04-mixed-group.go","message":"","textRange":{"endColumn":45,"endLine":2,"startColumn":37,"startLine":2}}]},{"primaryLocation":{"filePath":"./05-method-boundary.go","message":"This function has 8 parameters, which is greater than the 7 authorized.","textRange":{"endColumn":29,"endLine":4,"startColumn":18,"startLine":4}},"ruleId":"go:S107","secondaryLocations":[{"filePath":"./05-method-boundary.go","message":"","textRange":{"endColumn":49,"endLine":4,"startColumn":44,"startLine":4}}]},{"primaryLocation":{"filePath":"./06-literal.go","message":"This function has 8 parameters, which is greater than the 7 authorized.","textRange":{"endColumn":39,"endLine":2,"startColumn":18,"startLine":2}},"ruleId":"go:S107","secondaryLocations":[{"filePath":"./06-literal.go","message":"","textRange":{"endColumn":38,"endLine":2,"startColumn":33,"startLine":2}}]},{"primaryLocation":{"filePath":"./08-negative-and-position.go","message":"This function has 8 parameters, which is greater than the 7 authorized.","textRange":{"endColumn":27,"endLine":3,"startColumn":14,"startLine":3}},"ruleId":"go:S107","secondaryLocations":[{"filePath":"./08-negative-and-position.go","message":"","textRange":{"endColumn":6,"endLine":5,"startColumn":1,"startLine":5}}]}],"parity":{"active_rules":[{"fidelity":"community-base","key":"go:S100","parameters":[{"default_value":"^(_|[a-zA-Z0-9_]+)$","key":"formatForTests","parameter_type":"STRING"},{"default_value":"^(_|[a-zA-Z0-9]+)$","key":"format","parameter_type":"STRING"}]},{"fidelity":"community-base","key":"go:S103","parameters":[{"default_value":"120","key":"maximumLineLength","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S104","parameters":[{"default_value":"750","key":"Max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S1067","parameters":[{"default_value":"3","key":"max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S107","parameters":[{"default_value":"7","key":"Max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S108","parameters":[]},{"fidelity":"community-base","key":"go:S1110","parameters":[]},{"fidelity":"community-base","key":"go:S1125","parameters":[]},{"fidelity":"community-base","key":"go:S1134","parameters":[]},{"fidelity":"community-base","key":"go:S1135","parameters":[]},{"fidelity":"community-base","key":"go:S1145","parameters":[]},{"fidelity":"community-base","key":"go:S1151","parameters":[{"default_value":"6","key":"max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S117","parameters":[{"default_value":"^(_|[a-zA-Z0-9]+)$","key":"format","parameter_type":"STRING"}]},{"fidelity":"community-base","key":"go:S1186","parameters":[]},{"fidelity":"community-base","key":"go:S1192","parameters":[{"default_value":"3","key":"threshold","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S122","parameters":[]},{"fidelity":"community-base","key":"go:S126","parameters":[]},{"fidelity":"community-base","key":"go:S131","parameters":[]},{"fidelity":"community-base","key":"go:S1314","parameters":[]},{"fidelity":"community-base","key":"go:S134","parameters":[{"default_value":"4","key":"max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S138","parameters":[{"default_value":"120","key":"max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S1451","parameters":[{"key":"headerFormat","parameter_type":"TEXT"},{"default_value":"false","key":"isRegularExpression","parameter_type":"BOOLEAN"}]},{"fidelity":"community-base","key":"go:S1479","parameters":[{"default_value":"30","key":"maximum","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S1656","parameters":[]},{"fidelity":"community-base","key":"go:S1763","parameters":[]},{"fidelity":"community-base","key":"go:S1764","parameters":[]},{"fidelity":"community-base","key":"go:S1821","parameters":[]},{"fidelity":"community-base","key":"go:S1862","parameters":[]},{"fidelity":"community-base","key":"go:S1871","parameters":[]},{"fidelity":"community-base","key":"go:S1940","parameters":[]},{"fidelity":"community-base","key":"go:S2260","parameters":[]},{"fidelity":"community-base","key":"go:S2757","parameters":[]},{"fidelity":"community-base","key":"go:S3776","parameters":[{"default_value":"15","key":"threshold","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S3923","parameters":[]},{"fidelity":"community-base","key":"go:S4144","parameters":[]},{"fidelity":"community-base","key":"go:S4663","parameters":[]}],"completeness":"complete_native_analysis","reference":{"capture_sha256":"f423f0d8b8001af94dbf28bb8e3af368702447a9318b1200650cb3f9b3a332f0","captured_at_utc":"2026-08-22T14:45:03.705491626Z","profile":"sonar-parity","sonarqube_version":"2025.4.4.119049"},"rule_set_violations":[],"scope":{"duplication_exclude":[],"exclude":[],"file_counts":{"excluded":0,"generated":0,"source":8,"test":0,"vendor":0},"generated_include":[],"roots":["."],"test_include":[],"vendor_include":[]},"semantic_context":{"csharp":"not_applicable","typescript":"not_applicable"}},"rules":[{"cleanCodeAttribute":"FOCUSED","description":"Hoonarqube finding for `go:S107`.","engineId":"hoonarqube","id":"go:S107","impacts":[{"severity":"MEDIUM","softwareQuality":"MAINTAINABILITY"}],"name":"go:S107","severity":"MAJOR","type":"CODE_SMELL"}]}
"###;
const EXPECTED_CUSTOM_NATIVE: &str = r###"{"schema_version":1,"files":[{"path":"./01-custom-grouped.go","language":"go","issues":[],"metrics":{"lines":3,"code_lines":2,"comment_lines":0}},{"path":"./02-custom-separated.go","language":"go","issues":[],"metrics":{"lines":3,"code_lines":2,"comment_lines":0}}],"project":{"metrics":{"files":2,"lines":6,"code_lines":4,"comment_lines":0},"files":[{"path":"./01-custom-grouped.go","classification":"source","status":"complete","metrics":{"lines":3,"code_lines":2,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./02-custom-separated.go","classification":"source","status":"complete","metrics":{"lines":3,"code_lines":2,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null}],"duplications":[],"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"complete":true,"warnings":[],"roots":["."]},"parity":{"reference":{"sonarqube_version":"2025.4.4.119049","profile":"sonar-parity","captured_at_utc":"2026-08-22T14:45:03.705491626Z","capture_sha256":"f423f0d8b8001af94dbf28bb8e3af368702447a9318b1200650cb3f9b3a332f0"},"active_rules":[{"key":"go:S100","parameters":[{"key":"formatForTests","default_value":"^(_|[a-zA-Z0-9_]+)$","parameter_type":"STRING"},{"key":"format","default_value":"^(_|[a-zA-Z0-9]+)$","parameter_type":"STRING"}],"fidelity":"community-base"},{"key":"go:S103","parameters":[{"key":"maximumLineLength","default_value":"120","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S104","parameters":[{"key":"Max","default_value":"750","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S1067","parameters":[{"key":"max","default_value":"3","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S107","parameters":[{"key":"Max","default_value":"7","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S108","parameters":[],"fidelity":"community-base"},{"key":"go:S1110","parameters":[],"fidelity":"community-base"},{"key":"go:S1125","parameters":[],"fidelity":"community-base"},{"key":"go:S1134","parameters":[],"fidelity":"community-base"},{"key":"go:S1135","parameters":[],"fidelity":"community-base"},{"key":"go:S1145","parameters":[],"fidelity":"community-base"},{"key":"go:S1151","parameters":[{"key":"max","default_value":"6","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S117","parameters":[{"key":"format","default_value":"^(_|[a-zA-Z0-9]+)$","parameter_type":"STRING"}],"fidelity":"community-base"},{"key":"go:S1186","parameters":[],"fidelity":"community-base"},{"key":"go:S1192","parameters":[{"key":"threshold","default_value":"3","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S122","parameters":[],"fidelity":"community-base"},{"key":"go:S126","parameters":[],"fidelity":"community-base"},{"key":"go:S131","parameters":[],"fidelity":"community-base"},{"key":"go:S1314","parameters":[],"fidelity":"community-base"},{"key":"go:S134","parameters":[{"key":"max","default_value":"4","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S138","parameters":[{"key":"max","default_value":"120","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S1451","parameters":[{"key":"headerFormat","parameter_type":"TEXT"},{"key":"isRegularExpression","default_value":"false","parameter_type":"BOOLEAN"}],"fidelity":"community-base"},{"key":"go:S1479","parameters":[{"key":"maximum","default_value":"30","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S1656","parameters":[],"fidelity":"community-base"},{"key":"go:S1763","parameters":[],"fidelity":"community-base"},{"key":"go:S1764","parameters":[],"fidelity":"community-base"},{"key":"go:S1821","parameters":[],"fidelity":"community-base"},{"key":"go:S1862","parameters":[],"fidelity":"community-base"},{"key":"go:S1871","parameters":[],"fidelity":"community-base"},{"key":"go:S1940","parameters":[],"fidelity":"community-base"},{"key":"go:S2260","parameters":[],"fidelity":"community-base"},{"key":"go:S2757","parameters":[],"fidelity":"community-base"},{"key":"go:S3776","parameters":[{"key":"threshold","default_value":"15","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S3923","parameters":[],"fidelity":"community-base"},{"key":"go:S4144","parameters":[],"fidelity":"community-base"},{"key":"go:S4663","parameters":[],"fidelity":"community-base"}],"scope":{"roots":["."],"test_include":[],"exclude":[],"generated_include":[],"vendor_include":[],"duplication_exclude":[],"file_counts":{"excluded":0,"generated":0,"source":2,"test":0,"vendor":0}},"semantic_context":{"typescript":"not_applicable","csharp":"not_applicable"},"completeness":"complete_native_analysis","rule_set_violations":[]}}
"###;
const EXPECTED_CUSTOM_GENERIC: &str = r###"{"issues":[],"parity":{"active_rules":[{"fidelity":"community-base","key":"go:S100","parameters":[{"default_value":"^(_|[a-zA-Z0-9_]+)$","key":"formatForTests","parameter_type":"STRING"},{"default_value":"^(_|[a-zA-Z0-9]+)$","key":"format","parameter_type":"STRING"}]},{"fidelity":"community-base","key":"go:S103","parameters":[{"default_value":"120","key":"maximumLineLength","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S104","parameters":[{"default_value":"750","key":"Max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S1067","parameters":[{"default_value":"3","key":"max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S107","parameters":[{"default_value":"7","key":"Max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S108","parameters":[]},{"fidelity":"community-base","key":"go:S1110","parameters":[]},{"fidelity":"community-base","key":"go:S1125","parameters":[]},{"fidelity":"community-base","key":"go:S1134","parameters":[]},{"fidelity":"community-base","key":"go:S1135","parameters":[]},{"fidelity":"community-base","key":"go:S1145","parameters":[]},{"fidelity":"community-base","key":"go:S1151","parameters":[{"default_value":"6","key":"max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S117","parameters":[{"default_value":"^(_|[a-zA-Z0-9]+)$","key":"format","parameter_type":"STRING"}]},{"fidelity":"community-base","key":"go:S1186","parameters":[]},{"fidelity":"community-base","key":"go:S1192","parameters":[{"default_value":"3","key":"threshold","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S122","parameters":[]},{"fidelity":"community-base","key":"go:S126","parameters":[]},{"fidelity":"community-base","key":"go:S131","parameters":[]},{"fidelity":"community-base","key":"go:S1314","parameters":[]},{"fidelity":"community-base","key":"go:S134","parameters":[{"default_value":"4","key":"max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S138","parameters":[{"default_value":"120","key":"max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S1451","parameters":[{"key":"headerFormat","parameter_type":"TEXT"},{"default_value":"false","key":"isRegularExpression","parameter_type":"BOOLEAN"}]},{"fidelity":"community-base","key":"go:S1479","parameters":[{"default_value":"30","key":"maximum","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S1656","parameters":[]},{"fidelity":"community-base","key":"go:S1763","parameters":[]},{"fidelity":"community-base","key":"go:S1764","parameters":[]},{"fidelity":"community-base","key":"go:S1821","parameters":[]},{"fidelity":"community-base","key":"go:S1862","parameters":[]},{"fidelity":"community-base","key":"go:S1871","parameters":[]},{"fidelity":"community-base","key":"go:S1940","parameters":[]},{"fidelity":"community-base","key":"go:S2260","parameters":[]},{"fidelity":"community-base","key":"go:S2757","parameters":[]},{"fidelity":"community-base","key":"go:S3776","parameters":[{"default_value":"15","key":"threshold","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S3923","parameters":[]},{"fidelity":"community-base","key":"go:S4144","parameters":[]},{"fidelity":"community-base","key":"go:S4663","parameters":[]}],"completeness":"complete_native_analysis","reference":{"capture_sha256":"f423f0d8b8001af94dbf28bb8e3af368702447a9318b1200650cb3f9b3a332f0","captured_at_utc":"2026-08-22T14:45:03.705491626Z","profile":"sonar-parity","sonarqube_version":"2025.4.4.119049"},"rule_set_violations":[],"scope":{"duplication_exclude":[],"exclude":[],"file_counts":{"excluded":0,"generated":0,"source":2,"test":0,"vendor":0},"generated_include":[],"roots":["."],"test_include":[],"vendor_include":[]},"semantic_context":{"csharp":"not_applicable","typescript":"not_applicable"}},"rules":[]}
"###;
const EXPECTED_MALFORMED_NATIVE: &str = r###"{"schema_version":1,"files":[{"path":"./09-malformed-missing-close/case.go","language":"go","issues":[{"rule_key":"go:S2260","message":"A parsing error occurred in this file.","range":{"start":{"line":5,"column":19},"end":{"line":5,"column":19}}}],"metrics":{"lines":7,"code_lines":4,"comment_lines":1}}],"project":{"metrics":{"files":0,"lines":0,"code_lines":0,"comment_lines":0},"files":[{"path":"./09-malformed-missing-close/case.go","classification":"source","status":"failed","metrics":null,"duplication":null,"reason":"syntax tree contains recovered or missing nodes"}],"duplications":[],"duplication":null,"complete":false,"warnings":["./09-malformed-missing-close/case.go: syntax tree contains recovered or missing nodes","cannot analyze ./09-malformed-missing-close/case.go: syntax tree contains recovered or missing nodes","duplication analysis skipped because one or more eligible source files failed","incomplete source facts for ./09-malformed-missing-close/case.go: syntax tree contains recovered or missing nodes"],"roots":["."]}}
"###;
const EXPECTED_MALFORMED_GENERIC: &str = r###"{"issues":[{"primaryLocation":{"filePath":"./09-malformed-missing-close/case.go","message":"A parsing error occurred in this file.","textRange":{"endColumn":19,"endLine":5,"startColumn":19,"startLine":5}},"ruleId":"go:S2260"}],"rules":[{"cleanCodeAttribute":"CONVENTIONAL","description":"Hoonarqube finding for `go:S2260`.","engineId":"hoonarqube","id":"go:S2260","impacts":[{"severity":"MEDIUM","softwareQuality":"MAINTAINABILITY"}],"name":"go:S2260","severity":"MAJOR","type":"CODE_SMELL"}]}
"###;
const MALFORMED_SOURCES: &[(&str, &str)] = &[(
    "09-malformed-missing-close/case.go",
    "// Licensed\npackage p\n\nfunc f(x int) int {\n    return ((x + 1)\n}\n",
)];
const EXPECTED_MALFORMED_STDERR: &str = "./09-malformed-missing-close/case.go: syntax tree contains recovered or missing nodes\ncannot analyze ./09-malformed-missing-close/case.go: syntax tree contains recovered or missing nodes\nduplication analysis skipped because one or more eligible source files failed\nincomplete source facts for ./09-malformed-missing-close/case.go: syntax tree contains recovered or missing nodes\n";
const EXPECTED_ORIGINAL_NATIVE_ISSUES: &str = r###"[{"rule_key":"go:S1451","message":"Add or update the header of this file.","range":{"start":{"line":0,"column":0},"end":{"line":0,"column":0}}},{"rule_key":"go:S107","message":"This function has 8 parameters, which is greater than the 7 authorized.","range":{"start":{"line":3,"column":5},"end":{"line":3,"column":9}},"flows":[{"locations":[{"message":"","range":{"start":{"line":3,"column":24},"end":{"line":3,"column":29}}}]}]}]"###;
const EXPECTED_ORIGINAL_GENERIC_ISSUES: &str = r###"[{"primaryLocation":{"filePath":"./s107_bad.go","message":"Add or update the header of this file."},"ruleId":"go:S1451"},{"primaryLocation":{"filePath":"./s107_bad.go","message":"This function has 8 parameters, which is greater than the 7 authorized.","textRange":{"endColumn":9,"endLine":3,"startColumn":5,"startLine":3}},"ruleId":"go:S107","secondaryLocations":[{"filePath":"./s107_bad.go","message":"","textRange":{"endColumn":29,"endLine":3,"startColumn":24,"startLine":3}}]}]"###;
