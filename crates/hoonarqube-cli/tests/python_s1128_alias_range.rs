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
fn requests_compat_preserves_all_23_import_findings_with_one_alias_range() {
    let fixture = Fixture::new();
    // Exact Requests611c6162 compat.py bytes from the real reference scan.
    // Preserve conditional JSONDecodeError and all other existing detections.
    let spans = [
        (76, 27, 42),
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

const REQUESTS_COMPAT: &str = r###""""
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
"###;
