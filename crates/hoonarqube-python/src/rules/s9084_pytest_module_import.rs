use ruff_python_ast::{ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::{for_each_stmt, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S9084";
const FROM_MESSAGE: &str = "Import \"pytest\" as a module.";
const ALIAS_MESSAGE: &str = "Do not alias the \"pytest\" module.";

/// python:S9084 — pytest is conventionally imported as a module
/// (`import pytest`), so `from pytest import …` (and any `from pytest.*`
/// submodule import) scatters unbound helper names, and `import pytest as pt`
/// hides the standard name. A `from` import whose module's first segment is
/// `pytest` anchors the whole statement; an `import` alias anchors the
/// aliased name (`import pytest as pt` flags `pytest as pt`). Plain
/// `import pytest`, `import pytest as pytest`, relative imports, and
/// non-pytest modules stay silent.
pub(crate) fn check_s9084_pytest_module_import(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        match stmt {
            Stmt::ImportFrom(import) => {
                // `dottedPrefixForModule` empty ⇔ `level == 0` (absolute).
                if import.level == 0
                    && import
                        .module
                        .as_ref()
                        .is_some_and(|module| is_pytest_module(module.as_str()))
                {
                    issues.push(issue_at(
                        RULE_KEY,
                        FROM_MESSAGE,
                        import.range(),
                        index,
                        source,
                    ));
                }
            }
            Stmt::Import(import) => {
                for alias in &import.names {
                    let Some(asname) = &alias.asname else {
                        continue;
                    };
                    if asname.as_str() != "pytest" && is_pytest_module(alias.name.as_str()) {
                        issues.push(issue_at(
                            RULE_KEY,
                            ALIAS_MESSAGE,
                            alias.range(),
                            index,
                            source,
                        ));
                    }
                }
            }
            _ => {}
        }
    });
    issues
}

/// Whether the dotted module name's first segment is `pytest` (`pytest` and
/// `pytest.<sub>` both count).
fn is_pytest_module(dotted: &str) -> bool {
    dotted.split('.').next() == Some("pytest")
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan_test_file};

    fn found(source: &str) -> Vec<(String, hoonarqube_ir::Range)> {
        findings(&scan_test_file(source), "python:S9084")
            .into_iter()
            .map(|issue| (issue.message.clone(), issue.range.clone()))
            .collect()
    }

    #[test]
    fn s9084_flags_the_sonar_noncompliant_examples() {
        // `from pytest import mark, raises` anchors the whole statement
        // (line 1, columns 0-33); `import pytest as pt` anchors the aliased
        // name (columns 7-19).
        let from_import = found(concat!(
            "from pytest import mark, raises\n",
            "\n",
            "@mark.skip\n",
            "def test_invalid_input():\n",
            "    with raises(ValueError):\n",
            "        process_data('hello')\n",
        ));
        assert_eq!(from_import.len(), 1);
        assert_eq!(from_import[0].0, "Import \"pytest\" as a module.");
        assert_eq!(from_import[0].1.start, pos(1, 0));
        assert_eq!(from_import[0].1.end, pos(1, 31));

        let aliased = found(concat!(
            "import pytest as pt\n",
            "\n",
            "def test_invalid_input():\n",
            "    with pt.raises(ValueError):\n",
            "        process_data('hello')\n",
        ));
        assert_eq!(aliased.len(), 1);
        assert_eq!(aliased[0].0, "Do not alias the \"pytest\" module.");
        assert_eq!(aliased[0].1.start, pos(1, 7));
        assert_eq!(aliased[0].1.end, pos(1, 19));
    }

    #[test]
    fn s9084_accepts_the_sonar_compliant_example() {
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "@pytest.mark.skip\n",
                "def test_invalid_input():\n",
                "    with pytest.raises(ValueError):\n",
                "        process_data('hello')\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s9084_flags_submodule_from_imports_and_mixed_aliases() {
        // `from pytest.mark import …` and `import pytest.mark as m` count;
        // `import pytest as pytest` is the standard name and stays silent,
        // as do relative imports and other modules.
        let found = found(concat!(
            "from pytest.mark import parametrize\n",
            "import pytest.mark as marks\n",
            "import pytest as pytest\n",
            "import os as operating_system\n",
            "from .pytest import helper\n",
        ));
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, "Import \"pytest\" as a module.");
        assert_eq!(found[0].1.start, pos(1, 0));
        assert_eq!(found[1].0, "Do not alias the \"pytest\" module.");
        assert_eq!(found[1].1.start, pos(2, 7));
    }
}
