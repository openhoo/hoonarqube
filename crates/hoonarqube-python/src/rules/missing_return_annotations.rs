use std::path::Path;

use crate::engine::file_context::FileContext;
use crate::support::is_test_scope_file;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6538 — function returns should have type hints ---------------------
//
// Every function definition without a return annotation is reported,
// regardless of decorators (`@abstractmethod`, `@overload`, `@property`,
// framework decorators), nesting, or body shape (`...` stubs, docstring-only,
// bare `return`) — that is exactly what the reference analyzer reports.  A
// constructor without `-> None` gets the constructor-specific message.
//
// Although the frozen catalog scope is ALL, SonarPython executes this check
// on production sources only: heuristic test files never see it (the requests
// oracle carries 446 unannotated test defs and reports zero of them), so
// test-scope sources stay silent here too.
pub(crate) fn check_missing_return_annotations(
    path: &Path,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    if is_test_scope_file(path) {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for function in &file_ctx.functions {
        if function.returns.is_some() {
            continue;
        }
        let message = if function.name.as_str() == "__init__" {
            "Annotate the return type of this constructor with `None`."
        } else {
            "Add a return type hint to this function declaration."
        };
        issues.push(issue_at(
            "python:S6538",
            message,
            function.name.range(),
            index,
            source,
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::test_support::{findings, scan};
    use crate::{AnalyzerOptions, analyze};

    fn messages_for(path: &str, source: &str) -> Vec<String> {
        findings(
            &analyze(PathBuf::from(path), source, &AnalyzerOptions::default()),
            "python:S6538",
        )
        .iter()
        .map(|issue| issue.message.clone())
        .collect()
    }

    #[test]
    fn s6538_fires_by_default_on_unannotated_functions() {
        let source = "def _implementation(name):\n    return {\"name\": name}\n";
        assert_eq!(messages_for("m.py", source).len(), 1);
    }

    #[test]
    fn s6538_pins_the_requests_oracle_sites_and_messages() {
        // requests help.py:35 / status_codes.py:109 / help.py:126.
        let sources = [
            "def _implementation():\n    return {\"name\": \"CPython\"}\n",
            "def _init():\n    for code in (1, 2):\n        pass\n",
            "def main():\n    print(\"{}\")\n",
        ];
        for source in sources {
            assert_eq!(
                messages_for("m.py", source),
                vec![String::from(
                    "Add a return type hint to this function declaration."
                )]
            );
        }
    }

    #[test]
    fn s6538_annotated_functions_stay_silent() {
        let sources = [
            "def f() -> int:\n    return 1\n",
            "def f() -> None:\n    pass\n",
            "async def f() -> str:\n    return \"x\"\n",
        ];
        for source in sources {
            assert!(messages_for("m.py", source).is_empty(), "{source}");
        }
    }

    #[test]
    fn s6538_reports_constructors_with_the_constructor_message() {
        let source = "class K:\n    def __init__(self):\n        self.x = 1\n\n    def __str__(self):\n        return \"K\"\n";
        let messages = messages_for("m.py", source);
        assert_eq!(messages.len(), 2);
        assert!(messages.iter().any(|message| {
            message == "Annotate the return type of this constructor with `None`."
        }));
        assert!(
            messages.iter().any(|message| {
                message == "Add a return type hint to this function declaration."
            })
        );
    }

    #[test]
    fn s6538_reports_methods_nested_and_async_functions() {
        let source = "class K:\n    def m(self):\n        return 1\n\ndef outer():\n    def inner():\n        return 2\n    return inner\n\nasync def fetch():\n    return 1\n";
        assert_eq!(messages_for("m.py", source).len(), 4);
    }

    #[test]
    fn s6538_does_not_exempt_decorators_abstract_methods_or_stubs() {
        // Pinned against the reference analyzer: decorators, abstract
        // methods, protocol members, and `...` stubs are all reported.
        let sources = [
            "import functools\n\n@functools.lru_cache\ndef cached():\n    return 1\n",
            "from abc import ABC, abstractmethod\n\nclass A(ABC):\n    @abstractmethod\n    def run(self):\n        ...\n",
            "def stub():\n    ...\n",
            "class P:\n    @property\n    def name(self):\n        return \"x\"\n",
        ];
        for source in sources {
            assert_eq!(messages_for("m.py", source).len(), 1, "{source}");
        }
    }

    #[test]
    fn s6538_stays_silent_on_test_scope_files() {
        // The reference analyzer executes this check on production code only
        // even though the catalog scope is ALL.
        let source = "def test_x():\n    pass\n\ndef helper(a):\n    return a\n";
        assert!(messages_for("tests/test_x.py", source).is_empty());
        assert!(messages_for("tests/conftest.py", source).is_empty());
        assert_eq!(messages_for("src/m.py", source).len(), 2);
    }

    #[test]
    fn s6538_gated_parameter_rule_keeps_its_knob() {
        // The `require_type_hints` knob no longer gates S6538 itself.
        let source = "def add(a, b):\n    return a\n";
        let options = AnalyzerOptions {
            require_type_hints: false,
            ..AnalyzerOptions::default()
        };
        let report = analyze(PathBuf::from("t.py"), source, &options);
        assert_eq!(findings(&report, "python:S6538").len(), 1);
        let _ = scan("def add(a, b):\n    return a\n");
    }
}
