use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s1128-alias-range-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("fixture directory");
        Self(path)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("run hoonarqube")
    }

    fn analyze_path(&self, path: &str, source: &str, profile: &str, format: &str) -> Value {
        std::fs::write(self.0.join(path), source).expect("source");
        let output = self.run(&["analyze", path, "--profile", profile, "--format", format]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("report");
        if format == "json" {
            assert_eq!(report["project"]["complete"], true);
            assert_eq!(report["project"]["files"][0]["status"], "complete");
        }
        assert_eq!(
            std::fs::read_to_string(self.0.join(path)).expect("readback"),
            source
        );
        report
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn targets(report: &Value, format: &str) -> Vec<Value> {
    let (issues, key) = if format == "json" {
        (&report["files"][0]["issues"], "rule_key")
    } else {
        (&report["issues"], "ruleId")
    };
    issues
        .as_array()
        .expect("issues")
        .iter()
        .filter(|issue| issue[key] == "python:S1128")
        .cloned()
        .collect()
}

fn range(line: u32, start: u32, end: u32) -> Value {
    json!({"start":{"line":line,"column":start},"end":{"line":line,"column":end}})
}

fn expected(format: &str, path: &str, line: u32, start: u32, end: u32) -> Value {
    if format == "json" {
        json!({"rule_key":"python:S1128","message":"Remove this unused import.",
            "range":range(line,start,end)})
    } else {
        json!({"ruleId":"python:S1128","primaryLocation":{"filePath":path,
            "message":"Remove this unused import.","textRange":{"startLine":line,
            "endLine":line,"startColumn":start,"endColumn":end}}})
    }
}

fn assert_alias_primaries(format: &str) {
    let fixture = Fixture::new();
    for (source, spans) in [
        (
            "from http import cookiejar as cookielib\n",
            vec![(1, 30, 39)],
        ),
        ("from os import sep as sep\n", vec![(1, 22, 25)]),
        (
            "from urllib.parse import urlparse as parse_uri, urlencode\n",
            vec![(1, 37, 46), (1, 48, 57)],
        ),
        (
            "from os.path import (\n    basename as base_name,\n    dirname,\n)\n",
            vec![(2, 16, 25), (3, 4, 11)],
        ),
        ("π = 1; from math import sqrt as root\n", vec![(1, 32, 36)]),
    ] {
        for profile in ["strict", "sonar-parity"] {
            let report = fixture.analyze_path("case.py", source, profile, format);
            assert_eq!(
                targets(&report, format),
                spans
                    .iter()
                    .map(|&(line, start, end)| { expected(format, "case.py", line, start, end) })
                    .collect::<Vec<_>>(),
                "{profile}/{format}/{source}"
            );
        }
    }
}

#[test]
fn native_from_import_alias_primaries_use_bound_names() {
    assert_alias_primaries("json");
}

#[test]
fn generic_from_import_alias_primaries_use_bound_names() {
    assert_alias_primaries("sonar");
}

#[test]
fn non_alias_imports_and_used_aliases_preserve_complete_issues_and_scope() {
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            for (path, source) in [
                (
                    "case.py",
                    "from http import cookiejar as cookielib\nprint(cookielib)\n",
                ),
                (
                    "case.py",
                    "from os import sep as separator\n__all__ = ['separator']\n",
                ),
                ("case.py", "from os import path as file_path\n# file_path\n"),
                ("case.py", "from typing import Any\n"),
                (
                    "case.py",
                    "from http import cookiejar as cookielib\nprint(globals())\n",
                ),
                ("__init__.py", "from http import cookiejar as cookielib\n"),
                (
                    "test_subject.py",
                    "from http import cookiejar as cookielib\n",
                ),
            ] {
                assert!(
                    targets(&fixture.analyze_path(path, source, profile, format), format)
                        .is_empty(),
                    "{path}/{profile}/{format}/{source}"
                );
            }
            for (source, span) in [
                ("from os import path\n", (15, 19)),
                ("import pathlib as paths\n", (7, 23)),
            ] {
                assert_eq!(
                    targets(
                        &fixture.analyze_path("case.py", source, profile, format),
                        format
                    ),
                    vec![expected(format, "case.py", 1, span.0, span.1)]
                );
            }
        }
    }
}

#[test]
fn requests_compat_selects_last_same_name_import_with_22_findings() {
    let fixture = Fixture::new();
    // Exact Requests611c6162 compat.py bytes from the real reference scan.
    // Keep the last JSONDecodeError candidate and every other complete issue.
    // This selection repair explicitly revises the preceding range-only 23 contract.
    let spans = [
        (78, 21, 36),
        (82, 28, 36),
        (82, 38, 45),
        (82, 47, 61),
        (83, 30, 39),
        (84, 25, 31),
        (85, 15, 23),
        (91, 4, 9),
        (92, 4, 14),
        (93, 4, 11),
        (94, 4, 16),
        (95, 4, 13),
        (96, 4, 13),
        (97, 4, 11),
        (98, 4, 12),
        (99, 4, 12),
        (100, 4, 14),
        (103, 4, 14),
        (104, 4, 26),
        (105, 4, 19),
        (106, 4, 16),
        (107, 4, 28),
    ];
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            assert_eq!(
                targets(
                    &fixture.analyze_path("case.py", REQUESTS_COMPAT, profile, format),
                    format
                ),
                spans
                    .iter()
                    .map(|&(line, start, end)| expected(format, "case.py", line, start, end))
                    .collect::<Vec<_>>()
            );
        }
    }
}

struct SelectionCase {
    name: &'static str,
    path: &'static str,
    source: &'static str,
    spans: &'static [(u32, u32, u32)],
    changes: bool,
}

// Static contract qualified by the installed reference candidate Map and the
// exact Requests witness; direct imports and existing guards remain native.
const SELECTION_CASES: &[SelectionCase] = &[
    SelectionCase {
        name: "sequential-same-name",
        path: "case.py",
        source: "from alpha import item\nfrom beta import item\n",
        spans: &[(2, 17, 21)],
        changes: true,
    },
    SelectionCase {
        name: "conditional-same-name",
        path: "case.py",
        source: "if available:\n    from alpha import item\nelse:\n    from beta import item\n",
        spans: &[(4, 21, 25)],
        changes: true,
    },
    SelectionCase {
        name: "different-imports-same-alias",
        path: "case.py",
        source: "from alpha import first as shared\nfrom beta import second as shared\n",
        spans: &[(2, 27, 33)],
        changes: true,
    },
    SelectionCase {
        name: "distinct-bound-aliases",
        path: "case.py",
        source: "from alpha import item as first\nfrom beta import item as second\n",
        spans: &[(1, 26, 31), (2, 25, 31)],
        changes: false,
    },
    SelectionCase {
        name: "same-statement-duplicate",
        path: "case.py",
        source: "from alpha import item, item\n",
        spans: &[(1, 24, 28)],
        changes: true,
    },
    SelectionCase {
        name: "self-alias-duplicate",
        path: "case.py",
        source: "from os import sep as sep\nfrom os import sep as sep\n",
        spans: &[(2, 22, 25)],
        changes: true,
    },
    SelectionCase {
        name: "plain-module",
        path: "case.py",
        source: "import socket  # noqa: F401\n",
        spans: &[(1, 7, 13)],
        changes: false,
    },
    SelectionCase {
        name: "plain-module-duplicates",
        path: "case.py",
        source: "import socket\nimport socket\n",
        spans: &[(1, 7, 13), (2, 7, 13)],
        changes: false,
    },
    SelectionCase {
        name: "mixed-direct-then-from",
        path: "case.py",
        source: "import item\nfrom alpha import item\nfrom beta import item\n",
        spans: &[(1, 7, 11), (3, 17, 21)],
        changes: true,
    },
    SelectionCase {
        name: "mixed-from-then-direct",
        path: "case.py",
        source: "from alpha import item\nfrom beta import item\nimport item\n",
        spans: &[(2, 17, 21), (3, 7, 11)],
        changes: true,
    },
    SelectionCase {
        name: "used-name",
        path: "case.py",
        source: "from alpha import item\nfrom beta import item\nprint(item)\n",
        spans: &[],
        changes: false,
    },
    SelectionCase {
        name: "literal-name",
        path: "case.py",
        source: "from alpha import item\nfrom beta import item\n__all__ = [\"item\"]\n",
        spans: &[],
        changes: false,
    },
    SelectionCase {
        name: "comment-name",
        path: "case.py",
        source: "from alpha import item\nfrom beta import item\n# item remains exported\n",
        spans: &[],
        changes: false,
    },
    SelectionCase {
        name: "facade",
        path: "__init__.py",
        source: "from alpha import item\nfrom beta import item\n",
        spans: &[],
        changes: false,
    },
    SelectionCase {
        name: "test-scope",
        path: "test_subject.py",
        source: "from alpha import item\nfrom beta import item\n",
        spans: &[],
        changes: false,
    },
    SelectionCase {
        name: "dynamic-names",
        path: "case.py",
        source: "from alpha import item\nfrom beta import item\nprint(globals())\n",
        spans: &[],
        changes: false,
    },
    SelectionCase {
        name: "allowed-unaliased",
        path: "case.py",
        source: "from __future__ import annotations\nfrom typing import Any\nfrom typing_extensions import Literal\nfrom sklearn.experimental import enable_iterative_imputer\n",
        spans: &[(4, 33, 57)],
        changes: false,
    },
    SelectionCase {
        name: "allowed-group-veto",
        path: "case.py",
        source: "from alpha import Any\nfrom typing import Any\n",
        spans: &[],
        changes: false,
    },
    SelectionCase {
        name: "allowed-alias-existing-overfires",
        path: "case.py",
        source: "from typing import Any as TypeAny\nfrom typing_extensions import Literal as LiteralType\nfrom sklearn.experimental import enable_iterative_imputer as iterative\n",
        spans: &[(1, 26, 33), (2, 41, 52), (3, 61, 70)],
        changes: false,
    },
    SelectionCase {
        name: "nested-local-imports",
        path: "case.py",
        source: "def one():\n    from alpha import item\ndef two():\n    from beta import item\n",
        spans: &[],
        changes: false,
    },
    SelectionCase {
        name: "unrelated-nested-token-veto",
        path: "case.py",
        source: "from alpha import item\ndef local():\n    from beta import item\n",
        spans: &[],
        changes: false,
    },
    SelectionCase {
        name: "alias-range-inherited",
        path: "case.py",
        source: "from http import cookiejar as cookielib\n",
        spans: &[(1, 30, 39)],
        changes: false,
    },
    SelectionCase {
        name: "direct-alias-range-inherited",
        path: "case.py",
        source: "import pathlib as paths\n",
        spans: &[(1, 7, 23)],
        changes: false,
    },
];

fn assert_selection_contract(changes: bool) {
    let fixture = Fixture::new();
    for case in SELECTION_CASES
        .iter()
        .filter(|case| case.changes == changes)
    {
        for profile in ["strict", "sonar-parity"] {
            for format in ["json", "sonar"] {
                let report = fixture.analyze_path(case.path, case.source, profile, format);
                assert_eq!(
                    targets(&report, format),
                    case.spans
                        .iter()
                        .map(|&(line, start, end)| expected(format, case.path, line, start, end))
                        .collect::<Vec<_>>(),
                    "{}/{profile}/{format}",
                    case.name
                );
            }
        }
    }
}

#[test]
fn same_name_from_imports_select_last_candidate_in_native_and_generic() {
    assert_selection_contract(true);
}

#[test]
fn same_name_selection_preserves_direct_imports_usage_exemptions_and_scope() {
    assert_selection_contract(false);
}

const REQUESTS_COMPAT: &str = r#""""
requests.compat
~~~~~~~~~~~~~~~

This module previously handled import compatibility issues
between Python 2 and Python 3. It remains for backwards
compatibility until the next major version.
"""

# pyright: reportUnusedImport=false

from __future__ import annotations

import importlib
import sys
from types import ModuleType
from typing import TYPE_CHECKING

# -------
# urllib3
# -------
from urllib3 import __version__ as urllib3_version

# Detect which major version of urllib3 is being used.
try:
    is_urllib3_1 = int(urllib3_version.split(".")[0]) == 1
except (TypeError, AttributeError):
    # If we can't discern a version, prefer old functionality.
    is_urllib3_1 = True

# -------------------
# Character Detection
# -------------------


def _resolve_char_detection() -> ModuleType | None:
    """Find supported character detection libraries."""
    chardet = None
    for lib in ("chardet", "charset_normalizer"):
        if chardet is None:
            try:
                chardet = importlib.import_module(lib)
            except ImportError:
                pass
    return chardet


if TYPE_CHECKING:
    import chardet
else:
    chardet = _resolve_char_detection()

# -------
# Pythons
# -------

# Syntax sugar.
_ver = sys.version_info

#: Python 2.x?
is_py2 = _ver[0] == 2

#: Python 3.x?
is_py3 = _ver[0] == 3

# json/simplejson module import resolution
has_simplejson = False
try:
    import simplejson as json  # type: ignore[import-not-found]

    has_simplejson = True
except ImportError:
    import json

if has_simplejson:
    from simplejson import JSONDecodeError  # type: ignore[import-not-found]
else:
    from json import JSONDecodeError

# Keep OrderedDict for backwards compatibility.
from collections import OrderedDict
from collections.abc import Callable, Mapping, MutableMapping
from http import cookiejar as cookielib
from http.cookies import Morsel
from io import StringIO

# --------------
# Legacy Imports
# --------------
from urllib.parse import (
    quote,
    quote_plus,
    unquote,
    unquote_plus,
    urldefrag,
    urlencode,
    urljoin,
    urlparse,
    urlsplit,
    urlunparse,
)
from urllib.request import (
    getproxies,
    getproxies_environment,
    parse_http_list,
    proxy_bypass,
    proxy_bypass_environment,  # type: ignore[attr-defined]  # https://github.com/python/cpython/issues/145331
)

builtin_str = str
str = str
bytes = bytes
basestring = (str, bytes)
numeric_types = (int, float)
integer_types = (int,)
"#;
