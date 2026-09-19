use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt, StmtClassDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::dotted_segments;
use crate::support::issue_at;

const RULE_KEY: &str = "python:S8514";
const MESSAGE: &str = "Add a type annotation to this dataclass attribute.";

/// python:S8514 — `@dataclass` only turns annotated class attributes
/// into fields; a plain `name = value` silently becomes a class variable
/// excluded from `__init__`, `__repr__`, and `__eq__`. Names that look
/// intentional (`_private`, `CONSTANT`) stay silent. The finding anchors
/// on the whole assignment statement.
pub(crate) fn check_dataclass_annotated_attributes(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let _ = parsed;
    let dataclass_names = dataclass_bindings(file_ctx);
    let mut issues = Vec::new();
    for class in &file_ctx.classes {
        check_class(class, &dataclass_names, index, source, &mut issues);
    }
    issues
}

fn check_class(
    class: &StmtClassDef,
    dataclass_names: &[String],
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if !class
        .decorator_list
        .iter()
        .any(|decorator| is_dataclass_decorator(&decorator.expression, dataclass_names))
    {
        return;
    }
    for stmt in &class.body {
        let Stmt::Assign(assign) = stmt else {
            continue;
        };
        if is_likely_intentional_class_var(assign) {
            continue;
        }
        issues.push(issue_at(RULE_KEY, MESSAGE, stmt.range(), index, source));
    }
}

/// Whether the assignment is a single `NAME = value` whose target reads
/// as an intentional class variable: a `_`-prefixed name or an all-caps
/// constant (uppercase letters, digits, and underscores, with at least
/// one uppercase letter).
fn is_likely_intentional_class_var(assign: &ruff_python_ast::StmtAssign) -> bool {
    let [Expr::Name(target)] = assign.targets.as_slice() else {
        return false;
    };
    let name = target.id.as_str();
    name.starts_with('_') || is_all_caps(name)
}

fn is_all_caps(name: &str) -> bool {
    let mut has_upper = false;
    for ch in name.chars() {
        if ch.is_uppercase() {
            has_upper = true;
        } else if !ch.is_ascii_digit() && ch != '_' {
            return false;
        }
    }
    has_upper
}

/// Whether the decorator resolves to `dataclasses.dataclass`: the bare
/// or qualified name, a call of either (`@dataclass(...)`,
/// `@dataclasses.dataclass(...)`), a `from dataclasses import dataclass
/// [as x]` binding, or a `dataclasses` module alias.
fn is_dataclass_decorator(expression: &Expr, bound_names: &[String]) -> bool {
    let callee = match expression {
        Expr::Call(call) => call.func.as_ref(),
        other => other,
    };
    let Some(segments) = dotted_segments(callee) else {
        return false;
    };
    if segments == ["dataclasses", "dataclass"] {
        return true;
    }
    bound_names
        .iter()
        .any(|name| name.split('.').eq(segments.iter().copied()))
}

/// Local names bound to `dataclasses.dataclass` by from-imports, plus
/// `dataclasses` module aliases (`import dataclasses as dc` binds
/// `dc.dataclass`).
fn dataclass_bindings(file_ctx: &FileContext) -> Vec<String> {
    let mut names = Vec::new();
    for import in &file_ctx.imports {
        match import {
            AnyImport::From(import) if import.level == 0 => {
                let module = import.module.as_ref().map_or("", |m| m.as_str());
                if module != "dataclasses" {
                    continue;
                }
                for alias in &import.names {
                    if matches!(alias.name.as_str(), "dataclass" | "*") {
                        names.push(
                            alias
                                .asname
                                .as_ref()
                                .map_or("dataclass", |a| a.as_str())
                                .to_string(),
                        );
                    }
                }
            }
            AnyImport::Plain(import) => {
                for alias in &import.names {
                    if alias.name.as_str() == "dataclasses" {
                        names.push(format!(
                            "{}.dataclass",
                            alias.asname.as_ref().map_or("dataclasses", |a| a.as_str())
                        ));
                    }
                }
            }
            AnyImport::From(_) => {}
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s8514_flags_unannotated_attributes_on_sonar_example() {
        // The reference Noncompliant example, verbatim.
        let flagged = scan(concat!(
            "from dataclasses import dataclass\n",
            "\n",
            "@dataclass\n",
            "class Config:\n",
            "    timeout = 30\n",
            "    retries = 3\n",
        ));
        let found = findings(&flagged, "python:S8514");
        assert_eq!(found.len(), 2);
        // Each anchor covers the whole assignment statement.
        assert_eq!(found[0].range.start, pos(5, 4));
        assert_eq!(found[0].range.end, pos(5, 16));
        assert_eq!(
            found[0].message,
            "Add a type annotation to this dataclass attribute."
        );
    }

    #[test]
    fn s8514_accepts_annotated_attributes_on_sonar_example() {
        // The reference Compliant solution, verbatim.
        let clean = scan(concat!(
            "from dataclasses import dataclass\n",
            "\n",
            "@dataclass\n",
            "class Config:\n",
            "    timeout: int = 30\n",
            "    retries: int = 3\n",
        ));
        assert!(findings(&clean, "python:S8514").is_empty());
    }

    #[test]
    fn s8514_accepts_classvar_and_intentional_names() {
        // `ClassVar` annotations are compliant, and `_`-prefixed or
        // all-caps names read as intentional class variables.
        let clean = scan(concat!(
            "from dataclasses import dataclass\n",
            "from typing import ClassVar\n",
            "\n",
            "@dataclass\n",
            "class Registry:\n",
            "    instance_count: ClassVar[int] = 0\n",
            "    _cache = {}\n",
            "    DEFAULT_TIMEOUT = 30\n",
        ));
        assert!(findings(&clean, "python:S8514").is_empty());
    }

    #[test]
    fn s8514_flags_qualified_and_called_decorators() {
        let flagged = scan(concat!(
            "import dataclasses\n",
            "import dataclasses as dc\n",
            "from dataclasses import dataclass as dc2\n",
            "\n",
            "@dataclasses.dataclass\n",
            "class A:\n",
            "    x = 1\n",
            "\n",
            "@dc.dataclass(frozen=True)\n",
            "class B:\n",
            "    y = 2\n",
            "\n",
            "@dc2\n",
            "class C:\n",
            "    z = 3\n",
        ));
        assert_eq!(findings(&flagged, "python:S8514").len(), 3);
    }

    #[test]
    fn s8514_ignores_non_dataclass_classes() {
        let clean = scan(concat!(
            "class Plain:\n",
            "    x = 1\n",
            "\n",
            "@other_decorator\n",
            "class Decorated:\n",
            "    y = 2\n",
        ));
        assert!(findings(&clean, "python:S8514").is_empty());
    }

    #[test]
    fn s8514_flags_multi_target_and_tuple_assignments() {
        // `a = b = 1` and `a, b = ...` are not single-name intentional
        // class variables, so the reference flags the whole statement.
        let flagged = scan(concat!(
            "from dataclasses import dataclass\n",
            "\n",
            "@dataclass\n",
            "class Config:\n",
            "    a = b = 1\n",
            "    c, d = 2, 3\n",
        ));
        assert_eq!(findings(&flagged, "python:S8514").len(), 2);
    }
}
