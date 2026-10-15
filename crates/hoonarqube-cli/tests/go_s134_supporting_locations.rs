//! Frozen complete-report S134 CLI regressions, measured before implementation.
//! Native scalar columns and Generic UTF16 columns are separately asserted.
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("hoonarqube-s134-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        std::fs::create_dir(path.join("source")).unwrap();
        for (name, source) in SOURCES {
            let destination = path.join("source").join(name);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::write(destination, source).unwrap();
        }
        Self(path)
    }

    fn document(&self, format: &str) -> serde_json::Value {
        let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(self.0.join("source"))
            .args([
                "analyze",
                ".",
                "--profile",
                "sonar-parity",
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
            std::fs::write(
                capture.join(format!("s134-boundary-{format}.stdout")),
                &output.stdout,
            )
            .unwrap();
            std::fs::write(
                capture.join(format!("s134-boundary-{format}.stderr")),
                &output.stderr,
            )
            .unwrap();
        }
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn s134_boundary_native_complete_document() {
    let fixture = Fixture::new();
    let expected: serde_json::Value = serde_json::from_str(EXPECTED_NATIVE).unwrap();
    assert_eq!(fixture.document("json"), expected);
}

#[test]
fn s134_boundary_generic_complete_document() {
    let fixture = Fixture::new();
    let expected: serde_json::Value = serde_json::from_str(EXPECTED_GENERIC).unwrap();
    assert_eq!(fixture.document("sonar"), expected);
}

const SOURCES: &[(&str, &str)] = &[
    (
        "01-mixed-ancestors/case.go",
        r###"package mixed

func MixedAncestors(value any, limit int, enabled bool) {
	if enabled {
		for index := 0; index < limit; index++ {
			switch index % 2 {
			case 0:
				switch typed := value.(type) {
				case int:
					if typed > index {
						println(typed)
					}
				default:
					println(index)
				}
			default:
				println(limit)
			}
		}
	}
}
"###,
    ),
    (
        "02-for-primary/case.go",
        r###"package forprimary

func ForPrimary(values []int, seed int, enabled bool) {
	if enabled {
		switch seed % 2 {
		case 0:
			for _, value := range values {
				if value > seed {
					for repeat := 0; repeat < value; repeat++ {
						println(repeat)
					}
				}
			}
		default:
			println(seed)
		}
	}
}
"###,
    ),
    (
        "03-expression-switch-primary/case.go",
        r###"package expressionprimary

func ExpressionSwitchPrimary(flags [4]bool, value int) {
	if flags[0] {
		if flags[1] {
			if flags[2] {
				if flags[3] {
					switch value % 2 {
					case 0:
						println(value)
					default:
						println(-value)
					}
				}
			}
		}
	}
}
"###,
    ),
    (
        "04-type-switch-primary/case.go",
        r###"package typeprimary

func TypeSwitchPrimary(flags [4]bool, value any) {
	if flags[0] {
		if flags[1] {
			if flags[2] {
				if flags[3] {
					switch typed := value.(type) {
					case int:
						println(typed)
					default:
						println("other")
					}
				}
			}
		}
	}
}
"###,
    ),
    (
        "05-effective-else-if/case.go",
        r###"package effectiveelseif

func EffectiveElseIf(mode int, flags [4]bool) {
	if flags[0] {
		for index := 0; index < 2; index++ {
			if mode == 0 {
				println(index)
			} else if mode == 1 {
				if flags[1] {
					println(mode)
				} else if flags[2] {
					if flags[3] {
						println(index)
					}
				}
			} else {
				println(mode)
			}
		}
	}
}
"###,
    ),
    (
        "06-transparent-literal/case.go",
        r###"package transparentliteral

func TransparentLiteral(flags [4]bool, limit int) {
	if flags[0] {
		for index := 0; index < limit; index++ {
			func() {
				if flags[1] {
					if flags[2] {
						if flags[3] {
							println(index)
						}
					}
				}
			}()
		}
	}
}
"###,
    ),
    (
        "07-named-sibling-isolation/case.go",
        r###"package isolation

func FirstDeep(flags [5]bool) {
	if flags[0] {
		if flags[1] {
			if flags[2] {
				if flags[3] {
					if flags[4] {
						println("deep")
					}
				}
			}
		}
	}
}

func NextSibling(flags [4]bool) {
	if flags[0] {
		if flags[1] {
			if flags[2] {
				if flags[3] {
					println("sibling")
				}
			}
		}
	}
}

type Guard struct {
	Enabled bool
}

func (guard Guard) NextMethod(flags [3]bool) {
	if guard.Enabled {
		if flags[0] {
			if flags[1] {
				if flags[2] {
					println("method")
				}
			}
		}
	}
}
"###,
    ),
    (
        "08-threshold-and-deeper/case.go",
        r###"package threshold

func FourLevels(flags [4]bool) {
	if flags[0] {
		if flags[1] {
			if flags[2] {
				if flags[3] {
					println("four")
				}
			}
		}
	}
}

func FiveLevels(flags [5]bool) {
	if flags[0] {
		if flags[1] {
			if flags[2] {
				if flags[3] {
					if flags[4] {
						println("five")
					}
				}
			}
		}
	}
}

func SevenLevels(flags [7]bool) {
	if flags[0] {
		if flags[1] {
			if flags[2] {
				if flags[3] {
					if flags[4] {
						if flags[5] {
							if flags[6] {
								println("seven")
							}
						}
					}
				}
			}
		}
	}
}
"###,
    ),
    (
        "09-unicode-crlf/case.go",
        "package unicodecrlf\r\n\r\nfunc UnicodeCRLF(value int) {\r\n\t_ = \"🦉é\"; if value > 0 { if value > 1 { if value > 2 { if value > 3 { if value > 4 { println(value) } } } } }\r\n}\r\n",
    ),
    (
        "10-native-options-shallow/case.go",
        r###"package nativeoptions

func NativeOptionsShallow(enabled bool, value int) {
	if enabled {
		if value > 0 {
			println(value)
		}
	}
}
"###,
    ),
];

const EXPECTED_NATIVE: &str = r###"{"schema_version":1,"files":[{"path":"./01-mixed-ancestors/case.go","language":"go","issues":[{"rule_key":"go:S1151","message":"Reduce this case clause number of lines from 9 to at most 6, for example by extracting code into methods.","range":{"start":{"line":7,"column":3},"end":{"line":7,"column":10}}},{"rule_key":"go:S1821","message":"Refactor the code to eliminate this nested \"switch\".","range":{"start":{"line":8,"column":4},"end":{"line":8,"column":10}}},{"rule_key":"go:S134","message":"Refactor this code to not nest more than 4 control flow statements.","range":{"start":{"line":10,"column":5},"end":{"line":10,"column":7}},"flows":[{"locations":[{"message":"Nesting depth 1","range":{"start":{"line":4,"column":1},"end":{"line":4,"column":3}}}]},{"locations":[{"message":"Nesting depth 2","range":{"start":{"line":5,"column":2},"end":{"line":5,"column":5}}}]},{"locations":[{"message":"Nesting depth 3","range":{"start":{"line":6,"column":3},"end":{"line":6,"column":9}}}]},{"locations":[{"message":"Nesting depth 4","range":{"start":{"line":8,"column":4},"end":{"line":8,"column":10}}}]}]}],"metrics":{"lines":22,"code_lines":20,"comment_lines":0}},{"path":"./02-for-primary/case.go","language":"go","issues":[{"rule_key":"go:S1151","message":"Reduce this case clause number of lines from 8 to at most 6, for example by extracting code into methods.","range":{"start":{"line":6,"column":2},"end":{"line":6,"column":9}}},{"rule_key":"go:S134","message":"Refactor this code to not nest more than 4 control flow statements.","range":{"start":{"line":9,"column":5},"end":{"line":9,"column":8}},"flows":[{"locations":[{"message":"Nesting depth 1","range":{"start":{"line":4,"column":1},"end":{"line":4,"column":3}}}]},{"locations":[{"message":"Nesting depth 2","range":{"start":{"line":5,"column":2},"end":{"line":5,"column":8}}}]},{"locations":[{"message":"Nesting depth 3","range":{"start":{"line":7,"column":3},"end":{"line":7,"column":6}}}]},{"locations":[{"message":"Nesting depth 4","range":{"start":{"line":8,"column":4},"end":{"line":8,"column":6}}}]}]}],"metrics":{"lines":19,"code_lines":17,"comment_lines":0}},{"path":"./03-expression-switch-primary/case.go","language":"go","issues":[{"rule_key":"go:S134","message":"Refactor this code to not nest more than 4 control flow statements.","range":{"start":{"line":8,"column":5},"end":{"line":8,"column":7}},"flows":[{"locations":[{"message":"Nesting depth 1","range":{"start":{"line":4,"column":1},"end":{"line":4,"column":3}}}]},{"locations":[{"message":"Nesting depth 2","range":{"start":{"line":5,"column":2},"end":{"line":5,"column":4}}}]},{"locations":[{"message":"Nesting depth 3","range":{"start":{"line":6,"column":3},"end":{"line":6,"column":5}}}]},{"locations":[{"message":"Nesting depth 4","range":{"start":{"line":7,"column":4},"end":{"line":7,"column":6}}}]}]}],"metrics":{"lines":19,"code_lines":17,"comment_lines":0}},{"path":"./04-type-switch-primary/case.go","language":"go","issues":[{"rule_key":"go:S134","message":"Refactor this code to not nest more than 4 control flow statements.","range":{"start":{"line":8,"column":5},"end":{"line":8,"column":7}},"flows":[{"locations":[{"message":"Nesting depth 1","range":{"start":{"line":4,"column":1},"end":{"line":4,"column":3}}}]},{"locations":[{"message":"Nesting depth 2","range":{"start":{"line":5,"column":2},"end":{"line":5,"column":4}}}]},{"locations":[{"message":"Nesting depth 3","range":{"start":{"line":6,"column":3},"end":{"line":6,"column":5}}}]},{"locations":[{"message":"Nesting depth 4","range":{"start":{"line":7,"column":4},"end":{"line":7,"column":6}}}]}]}],"metrics":{"lines":19,"code_lines":17,"comment_lines":0}},{"path":"./05-effective-else-if/case.go","language":"go","issues":[{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 18 to the 15 allowed.","range":{"start":{"line":3,"column":5},"end":{"line":3,"column":20}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":4,"column":1},"end":{"line":4,"column":3}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":5,"column":2},"end":{"line":5,"column":5}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":6,"column":3},"end":{"line":6,"column":5}}}]},{"locations":[{"message":"+1","range":{"start":{"line":8,"column":5},"end":{"line":8,"column":9}}}]},{"locations":[{"message":"+1","range":{"start":{"line":16,"column":5},"end":{"line":16,"column":9}}}]},{"locations":[{"message":"+4 (incl 3 for nesting)","range":{"start":{"line":9,"column":4},"end":{"line":9,"column":6}}}]},{"locations":[{"message":"+1","range":{"start":{"line":11,"column":6},"end":{"line":11,"column":10}}}]},{"locations":[{"message":"+5 (incl 4 for nesting)","range":{"start":{"line":12,"column":5},"end":{"line":12,"column":7}}}]}]},{"rule_key":"go:S134","message":"Refactor this code to not nest more than 4 control flow statements.","range":{"start":{"line":12,"column":5},"end":{"line":12,"column":7}},"flows":[{"locations":[{"message":"Nesting depth 1","range":{"start":{"line":4,"column":1},"end":{"line":4,"column":3}}}]},{"locations":[{"message":"Nesting depth 2","range":{"start":{"line":5,"column":2},"end":{"line":5,"column":5}}}]},{"locations":[{"message":"Nesting depth 3","range":{"start":{"line":6,"column":3},"end":{"line":6,"column":5}}}]},{"locations":[{"message":"Nesting depth 4","range":{"start":{"line":9,"column":4},"end":{"line":9,"column":6}}}]}]}],"metrics":{"lines":22,"code_lines":20,"comment_lines":0}},{"path":"./06-transparent-literal/case.go","language":"go","issues":[{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 18 to the 15 allowed.","range":{"start":{"line":3,"column":5},"end":{"line":3,"column":23}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":4,"column":1},"end":{"line":4,"column":3}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":5,"column":2},"end":{"line":5,"column":5}}}]},{"locations":[{"message":"+4 (incl 3 for nesting)","range":{"start":{"line":7,"column":4},"end":{"line":7,"column":6}}}]},{"locations":[{"message":"+5 (incl 4 for nesting)","range":{"start":{"line":8,"column":5},"end":{"line":8,"column":7}}}]},{"locations":[{"message":"+6 (incl 5 for nesting)","range":{"start":{"line":9,"column":6},"end":{"line":9,"column":8}}}]}]},{"rule_key":"go:S134","message":"Refactor this code to not nest more than 4 control flow statements.","range":{"start":{"line":9,"column":6},"end":{"line":9,"column":8}},"flows":[{"locations":[{"message":"Nesting depth 1","range":{"start":{"line":4,"column":1},"end":{"line":4,"column":3}}}]},{"locations":[{"message":"Nesting depth 2","range":{"start":{"line":5,"column":2},"end":{"line":5,"column":5}}}]},{"locations":[{"message":"Nesting depth 3","range":{"start":{"line":7,"column":4},"end":{"line":7,"column":6}}}]},{"locations":[{"message":"Nesting depth 4","range":{"start":{"line":8,"column":5},"end":{"line":8,"column":7}}}]}]}],"metrics":{"lines":18,"code_lines":16,"comment_lines":0}},{"path":"./07-named-sibling-isolation/case.go","language":"go","issues":[{"rule_key":"go:S134","message":"Refactor this code to not nest more than 4 control flow statements.","range":{"start":{"line":8,"column":5},"end":{"line":8,"column":7}},"flows":[{"locations":[{"message":"Nesting depth 1","range":{"start":{"line":4,"column":1},"end":{"line":4,"column":3}}}]},{"locations":[{"message":"Nesting depth 2","range":{"start":{"line":5,"column":2},"end":{"line":5,"column":4}}}]},{"locations":[{"message":"Nesting depth 3","range":{"start":{"line":6,"column":3},"end":{"line":6,"column":5}}}]},{"locations":[{"message":"Nesting depth 4","range":{"start":{"line":7,"column":4},"end":{"line":7,"column":6}}}]}]}],"metrics":{"lines":44,"code_lines":39,"comment_lines":0}},{"path":"./08-threshold-and-deeper/case.go","language":"go","issues":[{"rule_key":"go:S134","message":"Refactor this code to not nest more than 4 control flow statements.","range":{"start":{"line":20,"column":5},"end":{"line":20,"column":7}},"flows":[{"locations":[{"message":"Nesting depth 1","range":{"start":{"line":16,"column":1},"end":{"line":16,"column":3}}}]},{"locations":[{"message":"Nesting depth 2","range":{"start":{"line":17,"column":2},"end":{"line":17,"column":4}}}]},{"locations":[{"message":"Nesting depth 3","range":{"start":{"line":18,"column":3},"end":{"line":18,"column":5}}}]},{"locations":[{"message":"Nesting depth 4","range":{"start":{"line":19,"column":4},"end":{"line":19,"column":6}}}]}]},{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 28 to the 15 allowed.","range":{"start":{"line":29,"column":5},"end":{"line":29,"column":16}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":30,"column":1},"end":{"line":30,"column":3}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":31,"column":2},"end":{"line":31,"column":4}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":32,"column":3},"end":{"line":32,"column":5}}}]},{"locations":[{"message":"+4 (incl 3 for nesting)","range":{"start":{"line":33,"column":4},"end":{"line":33,"column":6}}}]},{"locations":[{"message":"+5 (incl 4 for nesting)","range":{"start":{"line":34,"column":5},"end":{"line":34,"column":7}}}]},{"locations":[{"message":"+6 (incl 5 for nesting)","range":{"start":{"line":35,"column":6},"end":{"line":35,"column":8}}}]},{"locations":[{"message":"+7 (incl 6 for nesting)","range":{"start":{"line":36,"column":7},"end":{"line":36,"column":9}}}]}]},{"rule_key":"go:S134","message":"Refactor this code to not nest more than 4 control flow statements.","range":{"start":{"line":34,"column":5},"end":{"line":34,"column":7}},"flows":[{"locations":[{"message":"Nesting depth 1","range":{"start":{"line":30,"column":1},"end":{"line":30,"column":3}}}]},{"locations":[{"message":"Nesting depth 2","range":{"start":{"line":31,"column":2},"end":{"line":31,"column":4}}}]},{"locations":[{"message":"Nesting depth 3","range":{"start":{"line":32,"column":3},"end":{"line":32,"column":5}}}]},{"locations":[{"message":"Nesting depth 4","range":{"start":{"line":33,"column":4},"end":{"line":33,"column":6}}}]}]}],"metrics":{"lines":46,"code_lines":42,"comment_lines":0}},{"path":"./09-unicode-crlf/case.go","language":"go","issues":[{"rule_key":"go:S122","message":"Reformat the code to have only one statement per line.","range":{"start":{"line":4,"column":11},"end":{"line":4,"column":110}}},{"rule_key":"go:S134","message":"Refactor this code to not nest more than 4 control flow statements.","range":{"start":{"line":4,"column":71},"end":{"line":4,"column":73}},"flows":[{"locations":[{"message":"Nesting depth 1","range":{"start":{"line":4,"column":11},"end":{"line":4,"column":13}}}]},{"locations":[{"message":"Nesting depth 2","range":{"start":{"line":4,"column":26},"end":{"line":4,"column":28}}}]},{"locations":[{"message":"Nesting depth 3","range":{"start":{"line":4,"column":41},"end":{"line":4,"column":43}}}]},{"locations":[{"message":"Nesting depth 4","range":{"start":{"line":4,"column":56},"end":{"line":4,"column":58}}}]}]}],"metrics":{"lines":6,"code_lines":4,"comment_lines":0}},{"path":"./10-native-options-shallow/case.go","language":"go","issues":[],"metrics":{"lines":10,"code_lines":8,"comment_lines":0}}],"project":{"metrics":{"files":10,"lines":225,"code_lines":200,"comment_lines":0},"files":[{"path":"./01-mixed-ancestors/case.go","classification":"source","status":"complete","metrics":{"lines":22,"code_lines":20,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./02-for-primary/case.go","classification":"source","status":"complete","metrics":{"lines":19,"code_lines":17,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./03-expression-switch-primary/case.go","classification":"source","status":"complete","metrics":{"lines":19,"code_lines":17,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./04-type-switch-primary/case.go","classification":"source","status":"complete","metrics":{"lines":19,"code_lines":17,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./05-effective-else-if/case.go","classification":"source","status":"complete","metrics":{"lines":22,"code_lines":20,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./06-transparent-literal/case.go","classification":"source","status":"complete","metrics":{"lines":18,"code_lines":16,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./07-named-sibling-isolation/case.go","classification":"source","status":"complete","metrics":{"lines":44,"code_lines":39,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./08-threshold-and-deeper/case.go","classification":"source","status":"complete","metrics":{"lines":46,"code_lines":42,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./09-unicode-crlf/case.go","classification":"source","status":"complete","metrics":{"lines":6,"code_lines":4,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./10-native-options-shallow/case.go","classification":"source","status":"complete","metrics":{"lines":10,"code_lines":8,"comment_lines":0},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null}],"duplications":[],"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"complete":true,"warnings":[],"roots":["."]},"parity":{"reference":{"sonarqube_version":"2025.4.4.119049","profile":"sonar-parity","captured_at_utc":"2026-08-22T14:45:03.705491626Z","capture_sha256":"f423f0d8b8001af94dbf28bb8e3af368702447a9318b1200650cb3f9b3a332f0"},"active_rules":[{"key":"go:S100","parameters":[{"key":"formatForTests","default_value":"^(_|[a-zA-Z0-9_]+)$","parameter_type":"STRING"},{"key":"format","default_value":"^(_|[a-zA-Z0-9]+)$","parameter_type":"STRING"}],"fidelity":"community-base"},{"key":"go:S103","parameters":[{"key":"maximumLineLength","default_value":"120","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S104","parameters":[{"key":"Max","default_value":"750","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S1067","parameters":[{"key":"max","default_value":"3","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S107","parameters":[{"key":"Max","default_value":"7","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S108","parameters":[],"fidelity":"community-base"},{"key":"go:S1110","parameters":[],"fidelity":"community-base"},{"key":"go:S1125","parameters":[],"fidelity":"community-base"},{"key":"go:S1134","parameters":[],"fidelity":"community-base"},{"key":"go:S1135","parameters":[],"fidelity":"community-base"},{"key":"go:S1145","parameters":[],"fidelity":"community-base"},{"key":"go:S1151","parameters":[{"key":"max","default_value":"6","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S117","parameters":[{"key":"format","default_value":"^(_|[a-zA-Z0-9]+)$","parameter_type":"STRING"}],"fidelity":"community-base"},{"key":"go:S1186","parameters":[],"fidelity":"community-base"},{"key":"go:S1192","parameters":[{"key":"threshold","default_value":"3","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S122","parameters":[],"fidelity":"community-base"},{"key":"go:S126","parameters":[],"fidelity":"community-base"},{"key":"go:S131","parameters":[],"fidelity":"community-base"},{"key":"go:S1314","parameters":[],"fidelity":"community-base"},{"key":"go:S134","parameters":[{"key":"max","default_value":"4","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S138","parameters":[{"key":"max","default_value":"120","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S1451","parameters":[{"key":"headerFormat","parameter_type":"TEXT"},{"key":"isRegularExpression","default_value":"false","parameter_type":"BOOLEAN"}],"fidelity":"community-base"},{"key":"go:S1479","parameters":[{"key":"maximum","default_value":"30","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S1656","parameters":[],"fidelity":"community-base"},{"key":"go:S1763","parameters":[],"fidelity":"community-base"},{"key":"go:S1764","parameters":[],"fidelity":"community-base"},{"key":"go:S1821","parameters":[],"fidelity":"community-base"},{"key":"go:S1862","parameters":[],"fidelity":"community-base"},{"key":"go:S1871","parameters":[],"fidelity":"community-base"},{"key":"go:S1940","parameters":[],"fidelity":"community-base"},{"key":"go:S2260","parameters":[],"fidelity":"community-base"},{"key":"go:S2757","parameters":[],"fidelity":"community-base"},{"key":"go:S3776","parameters":[{"key":"threshold","default_value":"15","parameter_type":"INTEGER"}],"fidelity":"community-base"},{"key":"go:S3923","parameters":[],"fidelity":"community-base"},{"key":"go:S4144","parameters":[],"fidelity":"community-base"},{"key":"go:S4663","parameters":[],"fidelity":"community-base"}],"scope":{"roots":["."],"test_include":[],"exclude":[],"generated_include":[],"vendor_include":[],"duplication_exclude":[],"file_counts":{"excluded":0,"generated":0,"source":10,"test":0,"vendor":0}},"semantic_context":{"typescript":"not_applicable","csharp":"not_applicable"},"completeness":"complete_native_analysis","rule_set_violations":[]}}"###;
const EXPECTED_GENERIC: &str = r###"{"issues":[{"primaryLocation":{"filePath":"./01-mixed-ancestors/case.go","message":"Reduce this case clause number of lines from 9 to at most 6, for example by extracting code into methods.","textRange":{"endColumn":10,"endLine":7,"startColumn":3,"startLine":7}},"ruleId":"go:S1151"},{"primaryLocation":{"filePath":"./01-mixed-ancestors/case.go","message":"Refactor the code to eliminate this nested \"switch\".","textRange":{"endColumn":10,"endLine":8,"startColumn":4,"startLine":8}},"ruleId":"go:S1821"},{"primaryLocation":{"filePath":"./01-mixed-ancestors/case.go","message":"Refactor this code to not nest more than 4 control flow statements.","textRange":{"endColumn":7,"endLine":10,"startColumn":5,"startLine":10}},"ruleId":"go:S134","secondaryLocations":[{"filePath":"./01-mixed-ancestors/case.go","message":"Nesting depth 1","textRange":{"startLine":4,"startColumn":1,"endLine":4,"endColumn":3}},{"filePath":"./01-mixed-ancestors/case.go","message":"Nesting depth 2","textRange":{"startLine":5,"startColumn":2,"endLine":5,"endColumn":5}},{"filePath":"./01-mixed-ancestors/case.go","message":"Nesting depth 3","textRange":{"startLine":6,"startColumn":3,"endLine":6,"endColumn":9}},{"filePath":"./01-mixed-ancestors/case.go","message":"Nesting depth 4","textRange":{"startLine":8,"startColumn":4,"endLine":8,"endColumn":10}}]},{"primaryLocation":{"filePath":"./02-for-primary/case.go","message":"Reduce this case clause number of lines from 8 to at most 6, for example by extracting code into methods.","textRange":{"endColumn":9,"endLine":6,"startColumn":2,"startLine":6}},"ruleId":"go:S1151"},{"primaryLocation":{"filePath":"./02-for-primary/case.go","message":"Refactor this code to not nest more than 4 control flow statements.","textRange":{"endColumn":8,"endLine":9,"startColumn":5,"startLine":9}},"ruleId":"go:S134","secondaryLocations":[{"filePath":"./02-for-primary/case.go","message":"Nesting depth 1","textRange":{"startLine":4,"startColumn":1,"endLine":4,"endColumn":3}},{"filePath":"./02-for-primary/case.go","message":"Nesting depth 2","textRange":{"startLine":5,"startColumn":2,"endLine":5,"endColumn":8}},{"filePath":"./02-for-primary/case.go","message":"Nesting depth 3","textRange":{"startLine":7,"startColumn":3,"endLine":7,"endColumn":6}},{"filePath":"./02-for-primary/case.go","message":"Nesting depth 4","textRange":{"startLine":8,"startColumn":4,"endLine":8,"endColumn":6}}]},{"primaryLocation":{"filePath":"./03-expression-switch-primary/case.go","message":"Refactor this code to not nest more than 4 control flow statements.","textRange":{"endColumn":7,"endLine":8,"startColumn":5,"startLine":8}},"ruleId":"go:S134","secondaryLocations":[{"filePath":"./03-expression-switch-primary/case.go","message":"Nesting depth 1","textRange":{"startLine":4,"startColumn":1,"endLine":4,"endColumn":3}},{"filePath":"./03-expression-switch-primary/case.go","message":"Nesting depth 2","textRange":{"startLine":5,"startColumn":2,"endLine":5,"endColumn":4}},{"filePath":"./03-expression-switch-primary/case.go","message":"Nesting depth 3","textRange":{"startLine":6,"startColumn":3,"endLine":6,"endColumn":5}},{"filePath":"./03-expression-switch-primary/case.go","message":"Nesting depth 4","textRange":{"startLine":7,"startColumn":4,"endLine":7,"endColumn":6}}]},{"primaryLocation":{"filePath":"./04-type-switch-primary/case.go","message":"Refactor this code to not nest more than 4 control flow statements.","textRange":{"endColumn":7,"endLine":8,"startColumn":5,"startLine":8}},"ruleId":"go:S134","secondaryLocations":[{"filePath":"./04-type-switch-primary/case.go","message":"Nesting depth 1","textRange":{"startLine":4,"startColumn":1,"endLine":4,"endColumn":3}},{"filePath":"./04-type-switch-primary/case.go","message":"Nesting depth 2","textRange":{"startLine":5,"startColumn":2,"endLine":5,"endColumn":4}},{"filePath":"./04-type-switch-primary/case.go","message":"Nesting depth 3","textRange":{"startLine":6,"startColumn":3,"endLine":6,"endColumn":5}},{"filePath":"./04-type-switch-primary/case.go","message":"Nesting depth 4","textRange":{"startLine":7,"startColumn":4,"endLine":7,"endColumn":6}}]},{"primaryLocation":{"filePath":"./05-effective-else-if/case.go","message":"Refactor this method to reduce its Cognitive Complexity from 18 to the 15 allowed.","textRange":{"endColumn":20,"endLine":3,"startColumn":5,"startLine":3}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"./05-effective-else-if/case.go","message":"+1","textRange":{"endColumn":3,"endLine":4,"startColumn":1,"startLine":4}},{"filePath":"./05-effective-else-if/case.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":5,"endLine":5,"startColumn":2,"startLine":5}},{"filePath":"./05-effective-else-if/case.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":5,"endLine":6,"startColumn":3,"startLine":6}},{"filePath":"./05-effective-else-if/case.go","message":"+1","textRange":{"endColumn":9,"endLine":8,"startColumn":5,"startLine":8}},{"filePath":"./05-effective-else-if/case.go","message":"+1","textRange":{"endColumn":9,"endLine":16,"startColumn":5,"startLine":16}},{"filePath":"./05-effective-else-if/case.go","message":"+4 (incl 3 for nesting)","textRange":{"endColumn":6,"endLine":9,"startColumn":4,"startLine":9}},{"filePath":"./05-effective-else-if/case.go","message":"+1","textRange":{"endColumn":10,"endLine":11,"startColumn":6,"startLine":11}},{"filePath":"./05-effective-else-if/case.go","message":"+5 (incl 4 for nesting)","textRange":{"endColumn":7,"endLine":12,"startColumn":5,"startLine":12}}]},{"primaryLocation":{"filePath":"./05-effective-else-if/case.go","message":"Refactor this code to not nest more than 4 control flow statements.","textRange":{"endColumn":7,"endLine":12,"startColumn":5,"startLine":12}},"ruleId":"go:S134","secondaryLocations":[{"filePath":"./05-effective-else-if/case.go","message":"Nesting depth 1","textRange":{"startLine":4,"startColumn":1,"endLine":4,"endColumn":3}},{"filePath":"./05-effective-else-if/case.go","message":"Nesting depth 2","textRange":{"startLine":5,"startColumn":2,"endLine":5,"endColumn":5}},{"filePath":"./05-effective-else-if/case.go","message":"Nesting depth 3","textRange":{"startLine":6,"startColumn":3,"endLine":6,"endColumn":5}},{"filePath":"./05-effective-else-if/case.go","message":"Nesting depth 4","textRange":{"startLine":9,"startColumn":4,"endLine":9,"endColumn":6}}]},{"primaryLocation":{"filePath":"./06-transparent-literal/case.go","message":"Refactor this method to reduce its Cognitive Complexity from 18 to the 15 allowed.","textRange":{"endColumn":23,"endLine":3,"startColumn":5,"startLine":3}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"./06-transparent-literal/case.go","message":"+1","textRange":{"endColumn":3,"endLine":4,"startColumn":1,"startLine":4}},{"filePath":"./06-transparent-literal/case.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":5,"endLine":5,"startColumn":2,"startLine":5}},{"filePath":"./06-transparent-literal/case.go","message":"+4 (incl 3 for nesting)","textRange":{"endColumn":6,"endLine":7,"startColumn":4,"startLine":7}},{"filePath":"./06-transparent-literal/case.go","message":"+5 (incl 4 for nesting)","textRange":{"endColumn":7,"endLine":8,"startColumn":5,"startLine":8}},{"filePath":"./06-transparent-literal/case.go","message":"+6 (incl 5 for nesting)","textRange":{"endColumn":8,"endLine":9,"startColumn":6,"startLine":9}}]},{"primaryLocation":{"filePath":"./06-transparent-literal/case.go","message":"Refactor this code to not nest more than 4 control flow statements.","textRange":{"endColumn":8,"endLine":9,"startColumn":6,"startLine":9}},"ruleId":"go:S134","secondaryLocations":[{"filePath":"./06-transparent-literal/case.go","message":"Nesting depth 1","textRange":{"startLine":4,"startColumn":1,"endLine":4,"endColumn":3}},{"filePath":"./06-transparent-literal/case.go","message":"Nesting depth 2","textRange":{"startLine":5,"startColumn":2,"endLine":5,"endColumn":5}},{"filePath":"./06-transparent-literal/case.go","message":"Nesting depth 3","textRange":{"startLine":7,"startColumn":4,"endLine":7,"endColumn":6}},{"filePath":"./06-transparent-literal/case.go","message":"Nesting depth 4","textRange":{"startLine":8,"startColumn":5,"endLine":8,"endColumn":7}}]},{"primaryLocation":{"filePath":"./07-named-sibling-isolation/case.go","message":"Refactor this code to not nest more than 4 control flow statements.","textRange":{"endColumn":7,"endLine":8,"startColumn":5,"startLine":8}},"ruleId":"go:S134","secondaryLocations":[{"filePath":"./07-named-sibling-isolation/case.go","message":"Nesting depth 1","textRange":{"startLine":4,"startColumn":1,"endLine":4,"endColumn":3}},{"filePath":"./07-named-sibling-isolation/case.go","message":"Nesting depth 2","textRange":{"startLine":5,"startColumn":2,"endLine":5,"endColumn":4}},{"filePath":"./07-named-sibling-isolation/case.go","message":"Nesting depth 3","textRange":{"startLine":6,"startColumn":3,"endLine":6,"endColumn":5}},{"filePath":"./07-named-sibling-isolation/case.go","message":"Nesting depth 4","textRange":{"startLine":7,"startColumn":4,"endLine":7,"endColumn":6}}]},{"primaryLocation":{"filePath":"./08-threshold-and-deeper/case.go","message":"Refactor this code to not nest more than 4 control flow statements.","textRange":{"endColumn":7,"endLine":20,"startColumn":5,"startLine":20}},"ruleId":"go:S134","secondaryLocations":[{"filePath":"./08-threshold-and-deeper/case.go","message":"Nesting depth 1","textRange":{"startLine":16,"startColumn":1,"endLine":16,"endColumn":3}},{"filePath":"./08-threshold-and-deeper/case.go","message":"Nesting depth 2","textRange":{"startLine":17,"startColumn":2,"endLine":17,"endColumn":4}},{"filePath":"./08-threshold-and-deeper/case.go","message":"Nesting depth 3","textRange":{"startLine":18,"startColumn":3,"endLine":18,"endColumn":5}},{"filePath":"./08-threshold-and-deeper/case.go","message":"Nesting depth 4","textRange":{"startLine":19,"startColumn":4,"endLine":19,"endColumn":6}}]},{"primaryLocation":{"filePath":"./08-threshold-and-deeper/case.go","message":"Refactor this method to reduce its Cognitive Complexity from 28 to the 15 allowed.","textRange":{"endColumn":16,"endLine":29,"startColumn":5,"startLine":29}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"./08-threshold-and-deeper/case.go","message":"+1","textRange":{"endColumn":3,"endLine":30,"startColumn":1,"startLine":30}},{"filePath":"./08-threshold-and-deeper/case.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":31,"startColumn":2,"startLine":31}},{"filePath":"./08-threshold-and-deeper/case.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":5,"endLine":32,"startColumn":3,"startLine":32}},{"filePath":"./08-threshold-and-deeper/case.go","message":"+4 (incl 3 for nesting)","textRange":{"endColumn":6,"endLine":33,"startColumn":4,"startLine":33}},{"filePath":"./08-threshold-and-deeper/case.go","message":"+5 (incl 4 for nesting)","textRange":{"endColumn":7,"endLine":34,"startColumn":5,"startLine":34}},{"filePath":"./08-threshold-and-deeper/case.go","message":"+6 (incl 5 for nesting)","textRange":{"endColumn":8,"endLine":35,"startColumn":6,"startLine":35}},{"filePath":"./08-threshold-and-deeper/case.go","message":"+7 (incl 6 for nesting)","textRange":{"endColumn":9,"endLine":36,"startColumn":7,"startLine":36}}]},{"primaryLocation":{"filePath":"./08-threshold-and-deeper/case.go","message":"Refactor this code to not nest more than 4 control flow statements.","textRange":{"endColumn":7,"endLine":34,"startColumn":5,"startLine":34}},"ruleId":"go:S134","secondaryLocations":[{"filePath":"./08-threshold-and-deeper/case.go","message":"Nesting depth 1","textRange":{"startLine":30,"startColumn":1,"endLine":30,"endColumn":3}},{"filePath":"./08-threshold-and-deeper/case.go","message":"Nesting depth 2","textRange":{"startLine":31,"startColumn":2,"endLine":31,"endColumn":4}},{"filePath":"./08-threshold-and-deeper/case.go","message":"Nesting depth 3","textRange":{"startLine":32,"startColumn":3,"endLine":32,"endColumn":5}},{"filePath":"./08-threshold-and-deeper/case.go","message":"Nesting depth 4","textRange":{"startLine":33,"startColumn":4,"endLine":33,"endColumn":6}}]},{"primaryLocation":{"filePath":"./09-unicode-crlf/case.go","message":"Reformat the code to have only one statement per line.","textRange":{"endColumn":111,"endLine":4,"startColumn":12,"startLine":4}},"ruleId":"go:S122"},{"primaryLocation":{"filePath":"./09-unicode-crlf/case.go","message":"Refactor this code to not nest more than 4 control flow statements.","textRange":{"endColumn":74,"endLine":4,"startColumn":72,"startLine":4}},"ruleId":"go:S134","secondaryLocations":[{"filePath":"./09-unicode-crlf/case.go","message":"Nesting depth 1","textRange":{"startLine":4,"startColumn":12,"endLine":4,"endColumn":14}},{"filePath":"./09-unicode-crlf/case.go","message":"Nesting depth 2","textRange":{"startLine":4,"startColumn":27,"endLine":4,"endColumn":29}},{"filePath":"./09-unicode-crlf/case.go","message":"Nesting depth 3","textRange":{"startLine":4,"startColumn":42,"endLine":4,"endColumn":44}},{"filePath":"./09-unicode-crlf/case.go","message":"Nesting depth 4","textRange":{"startLine":4,"startColumn":57,"endLine":4,"endColumn":59}}]}],"parity":{"active_rules":[{"fidelity":"community-base","key":"go:S100","parameters":[{"default_value":"^(_|[a-zA-Z0-9_]+)$","key":"formatForTests","parameter_type":"STRING"},{"default_value":"^(_|[a-zA-Z0-9]+)$","key":"format","parameter_type":"STRING"}]},{"fidelity":"community-base","key":"go:S103","parameters":[{"default_value":"120","key":"maximumLineLength","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S104","parameters":[{"default_value":"750","key":"Max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S1067","parameters":[{"default_value":"3","key":"max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S107","parameters":[{"default_value":"7","key":"Max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S108","parameters":[]},{"fidelity":"community-base","key":"go:S1110","parameters":[]},{"fidelity":"community-base","key":"go:S1125","parameters":[]},{"fidelity":"community-base","key":"go:S1134","parameters":[]},{"fidelity":"community-base","key":"go:S1135","parameters":[]},{"fidelity":"community-base","key":"go:S1145","parameters":[]},{"fidelity":"community-base","key":"go:S1151","parameters":[{"default_value":"6","key":"max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S117","parameters":[{"default_value":"^(_|[a-zA-Z0-9]+)$","key":"format","parameter_type":"STRING"}]},{"fidelity":"community-base","key":"go:S1186","parameters":[]},{"fidelity":"community-base","key":"go:S1192","parameters":[{"default_value":"3","key":"threshold","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S122","parameters":[]},{"fidelity":"community-base","key":"go:S126","parameters":[]},{"fidelity":"community-base","key":"go:S131","parameters":[]},{"fidelity":"community-base","key":"go:S1314","parameters":[]},{"fidelity":"community-base","key":"go:S134","parameters":[{"default_value":"4","key":"max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S138","parameters":[{"default_value":"120","key":"max","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S1451","parameters":[{"key":"headerFormat","parameter_type":"TEXT"},{"default_value":"false","key":"isRegularExpression","parameter_type":"BOOLEAN"}]},{"fidelity":"community-base","key":"go:S1479","parameters":[{"default_value":"30","key":"maximum","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S1656","parameters":[]},{"fidelity":"community-base","key":"go:S1763","parameters":[]},{"fidelity":"community-base","key":"go:S1764","parameters":[]},{"fidelity":"community-base","key":"go:S1821","parameters":[]},{"fidelity":"community-base","key":"go:S1862","parameters":[]},{"fidelity":"community-base","key":"go:S1871","parameters":[]},{"fidelity":"community-base","key":"go:S1940","parameters":[]},{"fidelity":"community-base","key":"go:S2260","parameters":[]},{"fidelity":"community-base","key":"go:S2757","parameters":[]},{"fidelity":"community-base","key":"go:S3776","parameters":[{"default_value":"15","key":"threshold","parameter_type":"INTEGER"}]},{"fidelity":"community-base","key":"go:S3923","parameters":[]},{"fidelity":"community-base","key":"go:S4144","parameters":[]},{"fidelity":"community-base","key":"go:S4663","parameters":[]}],"completeness":"complete_native_analysis","reference":{"capture_sha256":"f423f0d8b8001af94dbf28bb8e3af368702447a9318b1200650cb3f9b3a332f0","captured_at_utc":"2026-08-22T14:45:03.705491626Z","profile":"sonar-parity","sonarqube_version":"2025.4.4.119049"},"rule_set_violations":[],"scope":{"duplication_exclude":[],"exclude":[],"file_counts":{"excluded":0,"generated":0,"source":10,"test":0,"vendor":0},"generated_include":[],"roots":["."],"test_include":[],"vendor_include":[]},"semantic_context":{"csharp":"not_applicable","typescript":"not_applicable"}},"rules":[{"cleanCodeAttribute":"FOCUSED","description":"Hoonarqube finding for `go:S1151`.","engineId":"hoonarqube","id":"go:S1151","impacts":[{"severity":"MEDIUM","softwareQuality":"MAINTAINABILITY"}],"name":"go:S1151","severity":"MAJOR","type":"CODE_SMELL"},{"cleanCodeAttribute":"FORMATTED","description":"Hoonarqube finding for `go:S122`.","engineId":"hoonarqube","id":"go:S122","impacts":[{"severity":"MEDIUM","softwareQuality":"MAINTAINABILITY"}],"name":"go:S122","severity":"MAJOR","type":"CODE_SMELL"},{"cleanCodeAttribute":"FOCUSED","description":"Hoonarqube finding for `go:S134`.","engineId":"hoonarqube","id":"go:S134","impacts":[{"severity":"HIGH","softwareQuality":"MAINTAINABILITY"}],"name":"go:S134","severity":"CRITICAL","type":"CODE_SMELL"},{"cleanCodeAttribute":"FOCUSED","description":"Hoonarqube finding for `go:S1821`.","engineId":"hoonarqube","id":"go:S1821","impacts":[{"severity":"HIGH","softwareQuality":"MAINTAINABILITY"}],"name":"go:S1821","severity":"CRITICAL","type":"CODE_SMELL"},{"cleanCodeAttribute":"FOCUSED","description":"Hoonarqube finding for `go:S3776`.","engineId":"hoonarqube","id":"go:S3776","impacts":[{"severity":"HIGH","softwareQuality":"MAINTAINABILITY"}],"name":"go:S3776","severity":"CRITICAL","type":"CODE_SMELL"}]}"###;
