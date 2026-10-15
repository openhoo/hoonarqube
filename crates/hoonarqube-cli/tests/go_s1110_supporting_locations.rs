//! Public CLI S1110 regressions against independently qualified actual controls.
//! Source proposal8cb0f133f42ab609beaf7ef880a180ba593fed5e6902546af81d4ebf1a19c747;
//! root qualificationf300e4df8672f10eae67570e1492dda8f21a96f5c67e66bbd2ce00e82d04aa22.
//! Generic retains existing UTF16 conversion; raw Unicode reference residual remains explicit.
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);
impl Fixture {
    fn new(sources: &[(&str, &str)]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("hoonarqube-s1110-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("source")).unwrap();
        for (path, source) in sources {
            let destination = root.join("source").join(path);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::write(destination, source).unwrap();
        }
        Self(root)
    }

    fn document(&self, label: &str, format: &str, exit: i32, stderr: &str) -> serde_json::Value {
        let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(self.0.join("source"))
            .args([
                "analyze",
                ".",
                "--profile",
                "strict",
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
                capture.join(format!("s1110-{label}-{format}.stdout")),
                &output.stdout,
            )
            .unwrap();
            std::fs::write(
                capture.join(format!("s1110-{label}-{format}.stderr")),
                &output.stderr,
            )
            .unwrap();
        }
        assert_eq!(
            output.status.code(),
            Some(exit),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stderr, stderr.as_bytes());
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn cache_snapshot(&self, format: &str) -> Vec<(PathBuf, Vec<u8>)> {
        fn collect(root: &std::path::Path, output: &mut Vec<(PathBuf, Vec<u8>)>) {
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

fn original(format: &str) {
    let fixture = Fixture::new(&SOURCES[..2]);
    let actual = fixture.document("original", format, 0, "");
    let expected: serde_json::Value = serde_json::from_str(if format == "json" {
        EXPECTED_NATIVE
    } else {
        EXPECTED_GENERIC
    })
    .unwrap();
    if format == "json" {
        assert_eq!(actual["project"]["complete"], true);
        assert_eq!(
            actual["files"],
            serde_json::Value::Array(expected["files"].as_array().unwrap()[..2].to_vec())
        );
    } else {
        let expected_issues: Vec<_> = expected["issues"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|issue| {
                issue["primaryLocation"]["filePath"]
                    .as_str()
                    .unwrap()
                    .starts_with("./01-original-bad/")
            })
            .cloned()
            .collect();
        assert_eq!(actual["issues"], serde_json::Value::Array(expected_issues));
        assert_eq!(actual["rules"], expected["rules"]);
    }
}

fn supplemental(format: &str) {
    let fixture = Fixture::new(&SOURCES[..8]);
    let expected: serde_json::Value = serde_json::from_str(if format == "json" {
        EXPECTED_NATIVE
    } else {
        EXPECTED_GENERIC
    })
    .unwrap();
    assert_eq!(
        fixture.document("supplemental-cold", format, 0, ""),
        expected
    );
    let cold = fixture.cache_snapshot(format);
    assert_eq!(cold.len(), 8);
    assert_eq!(
        fixture.document("supplemental-warm", format, 0, ""),
        expected
    );
    assert_eq!(fixture.cache_snapshot(format), cold);
    for (path, source) in &SOURCES[..8] {
        assert_eq!(
            std::fs::read(fixture.0.join("source").join(path)).unwrap(),
            source.as_bytes()
        );
    }
}

fn malformed(format: &str) {
    let fixture = Fixture::new(&SOURCES[8..]);
    let expected: serde_json::Value = serde_json::from_str(if format == "json" {
        EXPECTED_MALFORMED_NATIVE
    } else {
        EXPECTED_MALFORMED_GENERIC
    })
    .unwrap();
    assert_eq!(
        fixture.document("malformed", format, 2, EXPECTED_MALFORMED_STDERR),
        expected
    );
    assert_eq!(
        std::fs::read(fixture.0.join("source").join(SOURCES[8].0)).unwrap(),
        SOURCES[8].1.as_bytes()
    );
}

#[test]
fn s1110_original_native_exact_objects() {
    original("json");
}
#[test]
fn s1110_original_generic_exact_objects() {
    original("sonar");
}
#[test]
fn s1110_supplemental_native_complete_cold_and_warm() {
    supplemental("json");
}
#[test]
fn s1110_supplemental_generic_complete_cold_and_warm() {
    supplemental("sonar");
}
#[test]
fn s1110_malformed_native_remains_incomplete_exit2() {
    malformed("json");
}
#[test]
fn s1110_malformed_generic_remains_exit2() {
    malformed("sonar");
}

const SOURCES: &[(&str, &str)] = &[
    (
        "01-original-bad/case.go",
        "// Hoonarqube oracle fixture: go:S1110 bad\npackage oracle\n\nfunc foo(a bool, y int) int {\n  x := ((y / 2 + 1)) // Noncompliant\n\n  if a && ((x+y > 0)) {  // Noncompliant\n    return ((x + 1))  // Noncompliant\n  }\n}\n",
    ),
    (
        "02-original-good/case.go",
        "// Hoonarqube oracle fixture: go:S1110 good\npackage oracle\n\nfunc foo(a bool, y int) int {\n  x := (y / 2 + 1)\n\n  if a && (x+y > 0) {\n    return (x + 1)\n  }\n}\n",
    ),
    (
        "03-multiline/case.go",
        "// Licensed\npackage p\n\nfunc f(x int) int {\n    return ((\n        x + 1))\n}\n",
    ),
    (
        "04-astral-crlf/case.go",
        "// Licensed\r\npackage p\r\n\r\nfunc f(x int) int {\r\n    return len(\"😀\") + ((x + 1))\r\n}\r\n",
    ),
    (
        "05-triple-nesting/case.go",
        "// Licensed\npackage p\n\nfunc f(x int) int {\n    return (((x + 1)))\n}\n",
    ),
    (
        "06-independent-pairs/case.go",
        "// Licensed\npackage p\n\nfunc f(x int) int {\n    return ((x + 1)) + ((x + 2))\n}\n",
    ),
    (
        "07-comment-closing-decoys/case.go",
        "// Licensed\npackage p\n\nfunc f(x int) int {\n    return ((x + 1) /* ) )) marker only */)\n}\n",
    ),
    (
        "08-literal-and-comment-clean/case.go",
        "// Licensed\npackage p\n\nfunc f() string {\n    // ((comment)) ) (\n    return \"((literal)) ) (\"\n}\n",
    ),
    (
        "09-malformed-missing-close/case.go",
        "// Licensed\npackage p\n\nfunc f(x int) int {\n    return ((x + 1)\n}\n",
    ),
];

const EXPECTED_NATIVE: &str = r###"{
  "schema_version": 1,
  "files": [
    {
      "path": "./01-original-bad/case.go",
      "language": "go",
      "issues": [
        {
          "rule_key": "go:S1110",
          "message": "Remove these useless parentheses.",
          "range": {
            "start": {
              "line": 5,
              "column": 8
            },
            "end": {
              "line": 5,
              "column": 9
            }
          },
          "flows": [
            {
              "locations": [
                {
                  "message": "",
                  "range": {
                    "start": {
                      "line": 5,
                      "column": 18
                    },
                    "end": {
                      "line": 5,
                      "column": 19
                    }
                  }
                }
              ]
            }
          ]
        },
        {
          "rule_key": "go:S1110",
          "message": "Remove these useless parentheses.",
          "range": {
            "start": {
              "line": 7,
              "column": 11
            },
            "end": {
              "line": 7,
              "column": 12
            }
          },
          "flows": [
            {
              "locations": [
                {
                  "message": "",
                  "range": {
                    "start": {
                      "line": 7,
                      "column": 19
                    },
                    "end": {
                      "line": 7,
                      "column": 20
                    }
                  }
                }
              ]
            }
          ]
        },
        {
          "rule_key": "go:S1110",
          "message": "Remove these useless parentheses.",
          "range": {
            "start": {
              "line": 8,
              "column": 12
            },
            "end": {
              "line": 8,
              "column": 13
            }
          },
          "flows": [
            {
              "locations": [
                {
                  "message": "",
                  "range": {
                    "start": {
                      "line": 8,
                      "column": 18
                    },
                    "end": {
                      "line": 8,
                      "column": 19
                    }
                  }
                }
              ]
            }
          ]
        }
      ],
      "metrics": {
        "lines": 11,
        "code_lines": 7,
        "comment_lines": 4
      }
    },
    {
      "path": "./02-original-good/case.go",
      "language": "go",
      "issues": [],
      "metrics": {
        "lines": 11,
        "code_lines": 7,
        "comment_lines": 1
      }
    },
    {
      "path": "./03-multiline/case.go",
      "language": "go",
      "issues": [
        {
          "rule_key": "go:S1110",
          "message": "Remove these useless parentheses.",
          "range": {
            "start": {
              "line": 5,
              "column": 12
            },
            "end": {
              "line": 5,
              "column": 13
            }
          },
          "flows": [
            {
              "locations": [
                {
                  "message": "",
                  "range": {
                    "start": {
                      "line": 6,
                      "column": 13
                    },
                    "end": {
                      "line": 6,
                      "column": 14
                    }
                  }
                }
              ]
            }
          ]
        }
      ],
      "metrics": {
        "lines": 8,
        "code_lines": 5,
        "comment_lines": 1
      }
    },
    {
      "path": "./04-astral-crlf/case.go",
      "language": "go",
      "issues": [
        {
          "rule_key": "go:S1110",
          "message": "Remove these useless parentheses.",
          "range": {
            "start": {
              "line": 5,
              "column": 23
            },
            "end": {
              "line": 5,
              "column": 24
            }
          },
          "flows": [
            {
              "locations": [
                {
                  "message": "",
                  "range": {
                    "start": {
                      "line": 5,
                      "column": 29
                    },
                    "end": {
                      "line": 5,
                      "column": 30
                    }
                  }
                }
              ]
            }
          ]
        }
      ],
      "metrics": {
        "lines": 7,
        "code_lines": 4,
        "comment_lines": 1
      }
    },
    {
      "path": "./05-triple-nesting/case.go",
      "language": "go",
      "issues": [
        {
          "rule_key": "go:S1110",
          "message": "Remove these useless parentheses.",
          "range": {
            "start": {
              "line": 5,
              "column": 12
            },
            "end": {
              "line": 5,
              "column": 13
            }
          },
          "flows": [
            {
              "locations": [
                {
                  "message": "",
                  "range": {
                    "start": {
                      "line": 5,
                      "column": 20
                    },
                    "end": {
                      "line": 5,
                      "column": 21
                    }
                  }
                }
              ]
            }
          ]
        },
        {
          "rule_key": "go:S1110",
          "message": "Remove these useless parentheses.",
          "range": {
            "start": {
              "line": 5,
              "column": 13
            },
            "end": {
              "line": 5,
              "column": 14
            }
          },
          "flows": [
            {
              "locations": [
                {
                  "message": "",
                  "range": {
                    "start": {
                      "line": 5,
                      "column": 19
                    },
                    "end": {
                      "line": 5,
                      "column": 20
                    }
                  }
                }
              ]
            }
          ]
        }
      ],
      "metrics": {
        "lines": 7,
        "code_lines": 4,
        "comment_lines": 1
      }
    },
    {
      "path": "./06-independent-pairs/case.go",
      "language": "go",
      "issues": [
        {
          "rule_key": "go:S1110",
          "message": "Remove these useless parentheses.",
          "range": {
            "start": {
              "line": 5,
              "column": 12
            },
            "end": {
              "line": 5,
              "column": 13
            }
          },
          "flows": [
            {
              "locations": [
                {
                  "message": "",
                  "range": {
                    "start": {
                      "line": 5,
                      "column": 18
                    },
                    "end": {
                      "line": 5,
                      "column": 19
                    }
                  }
                }
              ]
            }
          ]
        },
        {
          "rule_key": "go:S1110",
          "message": "Remove these useless parentheses.",
          "range": {
            "start": {
              "line": 5,
              "column": 24
            },
            "end": {
              "line": 5,
              "column": 25
            }
          },
          "flows": [
            {
              "locations": [
                {
                  "message": "",
                  "range": {
                    "start": {
                      "line": 5,
                      "column": 30
                    },
                    "end": {
                      "line": 5,
                      "column": 31
                    }
                  }
                }
              ]
            }
          ]
        }
      ],
      "metrics": {
        "lines": 7,
        "code_lines": 4,
        "comment_lines": 1
      }
    },
    {
      "path": "./07-comment-closing-decoys/case.go",
      "language": "go",
      "issues": [
        {
          "rule_key": "go:S1110",
          "message": "Remove these useless parentheses.",
          "range": {
            "start": {
              "line": 5,
              "column": 12
            },
            "end": {
              "line": 5,
              "column": 13
            }
          },
          "flows": [
            {
              "locations": [
                {
                  "message": "",
                  "range": {
                    "start": {
                      "line": 5,
                      "column": 18
                    },
                    "end": {
                      "line": 5,
                      "column": 19
                    }
                  }
                }
              ]
            }
          ]
        }
      ],
      "metrics": {
        "lines": 7,
        "code_lines": 4,
        "comment_lines": 2
      }
    },
    {
      "path": "./08-literal-and-comment-clean/case.go",
      "language": "go",
      "issues": [],
      "metrics": {
        "lines": 8,
        "code_lines": 4,
        "comment_lines": 2
      }
    }
  ],
  "project": {
    "metrics": {
      "files": 8,
      "lines": 66,
      "code_lines": 39,
      "comment_lines": 13
    },
    "files": [
      {
        "path": "./01-original-bad/case.go",
        "classification": "source",
        "status": "complete",
        "metrics": {
          "lines": 11,
          "code_lines": 7,
          "comment_lines": 4
        },
        "duplication": {
          "duplicated_lines": 0,
          "duplicated_blocks": 0,
          "duplicated_files": 0,
          "duplicated_lines_density": 0.0
        },
        "reason": null
      },
      {
        "path": "./02-original-good/case.go",
        "classification": "source",
        "status": "complete",
        "metrics": {
          "lines": 11,
          "code_lines": 7,
          "comment_lines": 1
        },
        "duplication": {
          "duplicated_lines": 0,
          "duplicated_blocks": 0,
          "duplicated_files": 0,
          "duplicated_lines_density": 0.0
        },
        "reason": null
      },
      {
        "path": "./03-multiline/case.go",
        "classification": "source",
        "status": "complete",
        "metrics": {
          "lines": 8,
          "code_lines": 5,
          "comment_lines": 1
        },
        "duplication": {
          "duplicated_lines": 0,
          "duplicated_blocks": 0,
          "duplicated_files": 0,
          "duplicated_lines_density": 0.0
        },
        "reason": null
      },
      {
        "path": "./04-astral-crlf/case.go",
        "classification": "source",
        "status": "complete",
        "metrics": {
          "lines": 7,
          "code_lines": 4,
          "comment_lines": 1
        },
        "duplication": {
          "duplicated_lines": 0,
          "duplicated_blocks": 0,
          "duplicated_files": 0,
          "duplicated_lines_density": 0.0
        },
        "reason": null
      },
      {
        "path": "./05-triple-nesting/case.go",
        "classification": "source",
        "status": "complete",
        "metrics": {
          "lines": 7,
          "code_lines": 4,
          "comment_lines": 1
        },
        "duplication": {
          "duplicated_lines": 0,
          "duplicated_blocks": 0,
          "duplicated_files": 0,
          "duplicated_lines_density": 0.0
        },
        "reason": null
      },
      {
        "path": "./06-independent-pairs/case.go",
        "classification": "source",
        "status": "complete",
        "metrics": {
          "lines": 7,
          "code_lines": 4,
          "comment_lines": 1
        },
        "duplication": {
          "duplicated_lines": 0,
          "duplicated_blocks": 0,
          "duplicated_files": 0,
          "duplicated_lines_density": 0.0
        },
        "reason": null
      },
      {
        "path": "./07-comment-closing-decoys/case.go",
        "classification": "source",
        "status": "complete",
        "metrics": {
          "lines": 7,
          "code_lines": 4,
          "comment_lines": 2
        },
        "duplication": {
          "duplicated_lines": 0,
          "duplicated_blocks": 0,
          "duplicated_files": 0,
          "duplicated_lines_density": 0.0
        },
        "reason": null
      },
      {
        "path": "./08-literal-and-comment-clean/case.go",
        "classification": "source",
        "status": "complete",
        "metrics": {
          "lines": 8,
          "code_lines": 4,
          "comment_lines": 2
        },
        "duplication": {
          "duplicated_lines": 0,
          "duplicated_blocks": 0,
          "duplicated_files": 0,
          "duplicated_lines_density": 0.0
        },
        "reason": null
      }
    ],
    "duplications": [],
    "duplication": {
      "duplicated_lines": 0,
      "duplicated_blocks": 0,
      "duplicated_files": 0,
      "duplicated_lines_density": 0.0
    },
    "complete": true,
    "warnings": [],
    "roots": [
      "."
    ]
  }
}"###;

const EXPECTED_GENERIC: &str = r###"{
  "issues": [
    {
      "primaryLocation": {
        "filePath": "./01-original-bad/case.go",
        "message": "Remove these useless parentheses.",
        "textRange": {
          "endColumn": 9,
          "endLine": 5,
          "startColumn": 8,
          "startLine": 5
        }
      },
      "ruleId": "go:S1110",
      "secondaryLocations": [
        {
          "filePath": "./01-original-bad/case.go",
          "message": "",
          "textRange": {
            "startLine": 5,
            "startColumn": 18,
            "endLine": 5,
            "endColumn": 19
          }
        }
      ]
    },
    {
      "primaryLocation": {
        "filePath": "./01-original-bad/case.go",
        "message": "Remove these useless parentheses.",
        "textRange": {
          "endColumn": 12,
          "endLine": 7,
          "startColumn": 11,
          "startLine": 7
        }
      },
      "ruleId": "go:S1110",
      "secondaryLocations": [
        {
          "filePath": "./01-original-bad/case.go",
          "message": "",
          "textRange": {
            "startLine": 7,
            "startColumn": 19,
            "endLine": 7,
            "endColumn": 20
          }
        }
      ]
    },
    {
      "primaryLocation": {
        "filePath": "./01-original-bad/case.go",
        "message": "Remove these useless parentheses.",
        "textRange": {
          "endColumn": 13,
          "endLine": 8,
          "startColumn": 12,
          "startLine": 8
        }
      },
      "ruleId": "go:S1110",
      "secondaryLocations": [
        {
          "filePath": "./01-original-bad/case.go",
          "message": "",
          "textRange": {
            "startLine": 8,
            "startColumn": 18,
            "endLine": 8,
            "endColumn": 19
          }
        }
      ]
    },
    {
      "primaryLocation": {
        "filePath": "./03-multiline/case.go",
        "message": "Remove these useless parentheses.",
        "textRange": {
          "endColumn": 13,
          "endLine": 5,
          "startColumn": 12,
          "startLine": 5
        }
      },
      "ruleId": "go:S1110",
      "secondaryLocations": [
        {
          "filePath": "./03-multiline/case.go",
          "message": "",
          "textRange": {
            "startLine": 6,
            "startColumn": 13,
            "endLine": 6,
            "endColumn": 14
          }
        }
      ]
    },
    {
      "primaryLocation": {
        "filePath": "./04-astral-crlf/case.go",
        "message": "Remove these useless parentheses.",
        "textRange": {
          "endColumn": 25,
          "endLine": 5,
          "startColumn": 24,
          "startLine": 5
        }
      },
      "ruleId": "go:S1110",
      "secondaryLocations": [
        {
          "filePath": "./04-astral-crlf/case.go",
          "message": "",
          "textRange": {
            "startLine": 5,
            "startColumn": 30,
            "endLine": 5,
            "endColumn": 31
          }
        }
      ]
    },
    {
      "primaryLocation": {
        "filePath": "./05-triple-nesting/case.go",
        "message": "Remove these useless parentheses.",
        "textRange": {
          "endColumn": 13,
          "endLine": 5,
          "startColumn": 12,
          "startLine": 5
        }
      },
      "ruleId": "go:S1110",
      "secondaryLocations": [
        {
          "filePath": "./05-triple-nesting/case.go",
          "message": "",
          "textRange": {
            "startLine": 5,
            "startColumn": 20,
            "endLine": 5,
            "endColumn": 21
          }
        }
      ]
    },
    {
      "primaryLocation": {
        "filePath": "./05-triple-nesting/case.go",
        "message": "Remove these useless parentheses.",
        "textRange": {
          "endColumn": 14,
          "endLine": 5,
          "startColumn": 13,
          "startLine": 5
        }
      },
      "ruleId": "go:S1110",
      "secondaryLocations": [
        {
          "filePath": "./05-triple-nesting/case.go",
          "message": "",
          "textRange": {
            "startLine": 5,
            "startColumn": 19,
            "endLine": 5,
            "endColumn": 20
          }
        }
      ]
    },
    {
      "primaryLocation": {
        "filePath": "./06-independent-pairs/case.go",
        "message": "Remove these useless parentheses.",
        "textRange": {
          "endColumn": 13,
          "endLine": 5,
          "startColumn": 12,
          "startLine": 5
        }
      },
      "ruleId": "go:S1110",
      "secondaryLocations": [
        {
          "filePath": "./06-independent-pairs/case.go",
          "message": "",
          "textRange": {
            "startLine": 5,
            "startColumn": 18,
            "endLine": 5,
            "endColumn": 19
          }
        }
      ]
    },
    {
      "primaryLocation": {
        "filePath": "./06-independent-pairs/case.go",
        "message": "Remove these useless parentheses.",
        "textRange": {
          "endColumn": 25,
          "endLine": 5,
          "startColumn": 24,
          "startLine": 5
        }
      },
      "ruleId": "go:S1110",
      "secondaryLocations": [
        {
          "filePath": "./06-independent-pairs/case.go",
          "message": "",
          "textRange": {
            "startLine": 5,
            "startColumn": 30,
            "endLine": 5,
            "endColumn": 31
          }
        }
      ]
    },
    {
      "primaryLocation": {
        "filePath": "./07-comment-closing-decoys/case.go",
        "message": "Remove these useless parentheses.",
        "textRange": {
          "endColumn": 13,
          "endLine": 5,
          "startColumn": 12,
          "startLine": 5
        }
      },
      "ruleId": "go:S1110",
      "secondaryLocations": [
        {
          "filePath": "./07-comment-closing-decoys/case.go",
          "message": "",
          "textRange": {
            "startLine": 5,
            "startColumn": 18,
            "endLine": 5,
            "endColumn": 19
          }
        }
      ]
    }
  ],
  "rules": [
    {
      "cleanCodeAttribute": "CLEAR",
      "description": "Hoonarqube finding for `go:S1110`.",
      "engineId": "hoonarqube",
      "id": "go:S1110",
      "impacts": [
        {
          "severity": "MEDIUM",
          "softwareQuality": "MAINTAINABILITY"
        }
      ],
      "name": "go:S1110",
      "severity": "MAJOR",
      "type": "CODE_SMELL"
    }
  ]
}"###;

const EXPECTED_MALFORMED_NATIVE: &str = r###"{"schema_version":1,"files":[{"path":"./09-malformed-missing-close/case.go","language":"go","issues":[{"rule_key":"go:S2260","message":"A parsing error occurred in this file.","range":{"start":{"line":5,"column":19},"end":{"line":5,"column":19}}}],"metrics":{"lines":7,"code_lines":4,"comment_lines":1}}],"project":{"metrics":{"files":0,"lines":0,"code_lines":0,"comment_lines":0},"files":[{"path":"./09-malformed-missing-close/case.go","classification":"source","status":"failed","metrics":null,"duplication":null,"reason":"syntax tree contains recovered or missing nodes"}],"duplications":[],"duplication":null,"complete":false,"warnings":["./09-malformed-missing-close/case.go: syntax tree contains recovered or missing nodes","cannot analyze ./09-malformed-missing-close/case.go: syntax tree contains recovered or missing nodes","duplication analysis skipped because one or more eligible source files failed","incomplete source facts for ./09-malformed-missing-close/case.go: syntax tree contains recovered or missing nodes"],"roots":["."]}}"###;

const EXPECTED_MALFORMED_GENERIC: &str = r###"{"issues":[{"primaryLocation":{"filePath":"./09-malformed-missing-close/case.go","message":"A parsing error occurred in this file.","textRange":{"endColumn":19,"endLine":5,"startColumn":19,"startLine":5}},"ruleId":"go:S2260"}],"rules":[{"cleanCodeAttribute":"CONVENTIONAL","description":"Hoonarqube finding for `go:S2260`.","engineId":"hoonarqube","id":"go:S2260","impacts":[{"severity":"MEDIUM","softwareQuality":"MAINTAINABILITY"}],"name":"go:S2260","severity":"MAJOR","type":"CODE_SMELL"}]}"###;

const EXPECTED_MALFORMED_STDERR: &str = "./09-malformed-missing-close/case.go: syntax tree contains recovered or missing nodes\ncannot analyze ./09-malformed-missing-close/case.go: syntax tree contains recovered or missing nodes\nduplication analysis skipped because one or more eligible source files failed\nincomplete source facts for ./09-malformed-missing-close/case.go: syntax tree contains recovered or missing nodes\n";
