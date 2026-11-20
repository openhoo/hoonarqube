use crate::engine::scope::BindingKind;
use crate::engine::scope::FileFacts;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::name_used_in_tokens;
use crate::support::comment_tokens;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};
use std::collections::HashMap;
use std::path::Path;

// --- python:S1128 — unused imports ------------------------------------------
//
// The reference never reports `__init__.py` (facade re-export modules),
// exempts `__future__`/`typing`/`typing_extensions` imports and
// `sklearn.experimental.*` names, and treats a name mentioned in any comment
// or bound as a whole string literal (`__all__` entries, type-hint comments)
// as used.

const ALLOWED_MODULES: [&str; 3] = ["__future__", "typing", "typing_extensions"];
const ALLOWED_FQN_PREFIX: &str = "sklearn.experimental.";

pub(crate) fn check_unused_imports(
    parsed: &Parsed<ModModule>,
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
    path: &Path,
    file_ctx: &crate::engine::file_context::FileContext<'_>,
) -> Vec<Issue> {
    if path.file_name().is_some_and(|name| name == "__init__.py") {
        return Vec::new();
    }
    let import_modules = import_module_names(file_ctx);
    let from_ranges = from_import_name_ranges(file_ctx);
    let comments: Vec<&str> = comment_tokens(parsed)
        .map(|token| &source[token.range()])
        .collect();
    let mut issues = Vec::new();
    for (name, bindings) in &table.scopes[0].bindings {
        let import_ranges: Vec<TextRange> = bindings
            .iter()
            .filter(|binding| binding.kind == BindingKind::Import)
            .map(|binding| binding.range)
            .collect();
        if import_ranges.is_empty() {
            continue;
        }
        if import_ranges.iter().any(|range| {
            import_modules
                .get(range)
                .is_some_and(|module| import_is_allowed(module))
        }) {
            continue;
        }
        let used = table
            .resolved_index
            .get(name.as_str())
            .is_some_and(|indices| {
                indices
                    .iter()
                    .any(|&index| table.resolved_loads[index as usize].target == Some(0))
            })
            || name_used_in_tokens(facts, name, &import_ranges)
            || comments
                .iter()
                .any(|comment| comment.contains(name.as_str()))
            || facts.string_texts.iter().any(|text| text == name);
        if !used {
            let selected_from = import_ranges
                .iter()
                .copied()
                .rev()
                .find(|range| from_ranges.contains_key(range));
            for range in import_ranges
                .into_iter()
                .filter(|range| !from_ranges.contains_key(range) || Some(*range) == selected_from)
            {
                issues.push(issue_at(
                    "python:S1128",
                    "Remove this unused import.",
                    from_ranges.get(&range).copied().unwrap_or(range),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

/// The reference keeps the last `from` import for each bound name and reports
/// that Name. Match full definitions against root bindings above, retaining
/// every definition for usage exclusions and module exemptions.
fn from_import_name_ranges(
    file_ctx: &crate::engine::file_context::FileContext<'_>,
) -> HashMap<TextRange, TextRange> {
    let mut ranges = HashMap::new();
    for stmt in &file_ctx.stmts {
        let Stmt::ImportFrom(import) = stmt else {
            continue;
        };
        for alias in &import.names {
            let name = alias
                .asname
                .as_ref()
                .map_or_else(|| alias.name.range(), Ranged::range);
            ranges.insert(alias.range(), name);
        }
    }
    ranges
}

/// `__future__`, `typing`, `typing_extensions`, and `sklearn.experimental.*`
/// imports are exempt regardless of usage.
fn import_is_allowed(module: &str) -> bool {
    ALLOWED_MODULES.contains(&module) || module.starts_with(ALLOWED_FQN_PREFIX)
}

/// Maps each import binding range to its dotted module name: `from a.b
/// import c` yields `a.b` for `c`'s range, `import a.b` yields `a.b`.
fn import_module_names(
    file_ctx: &crate::engine::file_context::FileContext<'_>,
) -> HashMap<TextRange, String> {
    let mut modules = HashMap::new();
    for stmt in file_ctx.stmts.iter().copied() {
        match stmt {
            Stmt::ImportFrom(import) => {
                let module = import
                    .module
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                for alias in &import.names {
                    let range = alias
                        .asname
                        .as_ref()
                        .map_or_else(|| alias.name.range(), Ranged::range);
                    modules.insert(range, module.clone());
                }
            }
            Stmt::Import(import) => {
                for alias in &import.names {
                    let range = alias
                        .asname
                        .as_ref()
                        .map_or_else(|| alias.name.range(), Ranged::range);
                    modules.insert(range, alias.name.to_string());
                }
            }
            _ => {}
        }
    }
    modules
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::test_support::{issue, scan, scan_at, scan_test_file};
    use hoonarqube_ir::Issue;

    fn targets(report: hoonarqube_ir::FileReport) -> Vec<Issue> {
        report
            .issues
            .into_iter()
            .filter(|issue| issue.rule_key == "python:S1128")
            .collect()
    }

    fn unused(line: u32, start: u32, end: u32) -> Issue {
        issue(
            "python:S1128",
            "Remove this unused import.",
            (line, start),
            (line, end),
        )
    }

    #[test]
    fn from_import_alias_primary_uses_bound_name_without_changing_selection() {
        // The Requests witness and token controls select the exact installed
        // ImportFrom alias Name. Entire Issue equality also preserves no fix.
        for (source, expected) in [
            (
                "from http import cookiejar as cookielib\n",
                vec![unused(1, 30, 39)],
            ),
            ("from os import sep as sep\n", vec![unused(1, 22, 25)]),
            (
                "from urllib.parse import urlparse as parse_uri, urlencode\n",
                vec![unused(1, 37, 46), unused(1, 48, 57)],
            ),
            (
                "from os.path import (\n    basename as base_name,\n    dirname,\n)\n",
                vec![unused(2, 16, 25), unused(3, 4, 11)],
            ),
            (
                "π = 1; from math import sqrt as root\n",
                vec![unused(1, 32, 36)],
            ),
        ] {
            assert_eq!(targets(scan(source)), expected, "{source}");
        }
    }

    #[test]
    fn alias_display_preserves_non_alias_usage_exemptions_and_scope() {
        for source in [
            "from http import cookiejar as cookielib\nprint(cookielib)\n",
            "from os import sep as separator\n__all__ = ['separator']\n",
            "from os import path as file_path\n# file_path\n",
            "from typing import Any\n",
            "from http import cookiejar as cookielib\nprint(globals())\n",
        ] {
            assert!(targets(scan(source)).is_empty(), "{source}");
        }
        let source = "from http import cookiejar as cookielib\n";
        assert!(targets(scan_at(PathBuf::from("__init__.py"), source)).is_empty());
        assert!(targets(scan_test_file(source)).is_empty());
        assert_eq!(
            targets(scan("from os import path\n")),
            vec![unused(1, 15, 19)]
        );
        assert_eq!(
            targets(scan("import pathlib as paths\n")),
            vec![unused(1, 7, 23)]
        );
        // Existing aliased allowed-module overfires are an independent lead.
        // Preserve selection while applying the same alias display contract.
        assert_eq!(
            targets(scan("from typing import Any as TypeAny\n")),
            vec![unused(1, 26, 33)]
        );
    }

    #[test]
    fn from_import_selection_keeps_last_candidate_for_each_bound_name() {
        for (source, expected) in [
            (
                "from alpha import item\nfrom beta import item\n",
                vec![unused(2, 17, 21)],
            ),
            (
                "if available:\n    from alpha import item\nelse:\n    from beta import item\n",
                vec![unused(4, 21, 25)],
            ),
            (
                "from alpha import first as shared\nfrom beta import second as shared\n",
                vec![unused(2, 27, 33)],
            ),
            (
                "from alpha import item as first\nfrom beta import item as second\n",
                vec![unused(1, 26, 31), unused(2, 25, 31)],
            ),
            ("from alpha import item, item\n", vec![unused(1, 24, 28)]),
            (
                "from os import sep as sep\nfrom os import sep as sep\n",
                vec![unused(2, 22, 25)],
            ),
        ] {
            assert_eq!(targets(scan(source)), expected, "{source}");
        }
    }

    #[test]
    fn same_name_from_selection_preserves_each_direct_import() {
        for (source, expected) in [
            ("import socket  # noqa: F401\n", vec![unused(1, 7, 13)]),
            (
                "import socket\nimport socket\n",
                vec![unused(1, 7, 13), unused(2, 7, 13)],
            ),
            (
                "import item\nfrom alpha import item\nfrom beta import item\n",
                vec![unused(1, 7, 11), unused(3, 17, 21)],
            ),
            (
                "from alpha import item\nfrom beta import item\nimport item\n",
                vec![unused(2, 17, 21), unused(3, 7, 11)],
            ),
        ] {
            assert_eq!(targets(scan(source)), expected, "{source}");
        }
    }
}
