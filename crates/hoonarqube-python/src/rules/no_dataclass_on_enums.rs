use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::{dotted_segments, issue_at};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, StmtClassDef};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::{HashMap, HashSet};

const RULE_KEY: &str = "python:S8490";
const MESSAGE: &str = "Remove this \"@dataclass\" decorator; it is incompatible with Enum classes.";
const ENUM_BASES: [&str; 3] = ["enum.Enum", "enum.IntEnum", "enum.IntFlag"];

/// python:S8490 — `@dataclass` generates `__init__`/`__repr__`/`__eq__` in
/// ways that conflict with the `EnumMeta` metaclass; decorating an enum
/// raises `TypeError` at class creation. Scope `ALL`.
///
/// Mirrors `DataClassOnEnumCheck`: a class is an enum when one of its bases
/// resolves to `enum.Enum`, `enum.IntEnum`, or `enum.IntFlag` — directly or
/// transitively through classes defined in the same file (`isOrExtendsType`;
/// `enum.Flag` is not in the reference matcher). The decorator is flagged
/// when its expression (or call callee) resolves to
/// `dataclasses.dataclass`. Import aliases (`import enum as e`, `from
/// dataclasses import dataclass as dc`, wildcard imports) resolve through
/// the file's import statements; unresolved names stay silent. The issue
/// anchors on the decorator.
pub(crate) fn check_no_dataclass_on_enums(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let aliases = import_aliases(file_ctx);
    let classes: HashMap<&str, &StmtClassDef> = file_ctx
        .classes
        .iter()
        .map(|class| (class.name.as_str(), *class))
        .collect();
    let mut issues = Vec::new();
    for class in &file_ctx.classes {
        if class.decorator_list.is_empty() {
            continue;
        }
        if !is_enum_class(class, &classes, &aliases, &mut HashSet::new()) {
            continue;
        }
        for decorator in &class.decorator_list {
            if is_dataclass_decorator(&decorator.expression, &aliases) {
                issues.push(issue_at(
                    RULE_KEY,
                    MESSAGE,
                    decorator.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

/// Maps locally bound names to their fully qualified import targets:
/// `import enum as e` → `e` ↦ `enum`, `from enum import Enum as E` → `E` ↦
/// `enum.Enum`, `from enum import *` → `Enum` ↦ `enum.Enum` (and the other
/// public enum/dataclass names).
fn import_aliases(file_ctx: &FileContext) -> HashMap<String, String> {
    let mut aliases = HashMap::new();
    for import in &file_ctx.imports {
        match import {
            AnyImport::Plain(stmt) => plain_import_aliases(stmt, &mut aliases),
            AnyImport::From(stmt) => from_import_aliases(stmt, &mut aliases),
        }
    }
    aliases
}

/// `import a.b[ as c]` binds `c` (or `a`) to `a.b`.
fn plain_import_aliases(stmt: &ruff_python_ast::StmtImport, aliases: &mut HashMap<String, String>) {
    for alias in &stmt.names {
        let bound = alias.asname.as_ref().map_or_else(
            || alias.name.as_str().split('.').next().unwrap_or(""),
            ruff_python_ast::Identifier::as_str,
        );
        if !bound.is_empty() {
            aliases.insert(bound.to_string(), alias.name.as_str().to_string());
        }
    }
}

/// `from m import n[ as b]` binds `b` (or `n`) to `m.n`; `*` binds the
/// module's public names this rule resolves.
fn from_import_aliases(
    stmt: &ruff_python_ast::StmtImportFrom,
    aliases: &mut HashMap<String, String>,
) {
    let Some(module) = &stmt.module else {
        return;
    };
    for alias in &stmt.names {
        if alias.name.as_str() == "*" {
            for public in wildcard_names(module.as_str()) {
                aliases.insert(public.to_string(), format!("{}.{public}", module.as_str()));
            }
            continue;
        }
        let bound = alias.asname.as_ref().unwrap_or(&alias.name);
        aliases.insert(
            bound.as_str().to_string(),
            format!("{}.{}", module.as_str(), alias.name.as_str()),
        );
    }
}
/// Public names a wildcard import would bind for the modules this rule
/// resolves.
fn wildcard_names(module: &str) -> &'static [&'static str] {
    match module {
        "enum" => &["Enum", "IntEnum", "IntFlag", "Flag", "StrEnum", "EnumType"],
        "dataclasses" => &["dataclass", "field", "fields", "is_dataclass"],
        _ => &[],
    }
}

/// Resolves a name/attribute chain to its fully qualified path through the
/// import alias map; unresolvable roots return `None`.
fn qualified_path(expr: &Expr, aliases: &HashMap<String, String>) -> Option<String> {
    let segments = dotted_segments(expr)?;
    let root = aliases.get(segments[0])?;
    let mut path = root.clone();
    for segment in &segments[1..] {
        path.push('.');
        path.push_str(segment);
    }
    Some(path)
}

/// Whether the decorator expression denotes `dataclasses.dataclass` (call
/// callees unwrap, mirroring `getDecoratorFunctionExpression`).
fn is_dataclass_decorator(expr: &Expr, aliases: &HashMap<String, String>) -> bool {
    let target = match expr {
        Expr::Call(call) => call.func.as_ref(),
        other => other,
    };
    qualified_path(target, aliases).as_deref() == Some("dataclasses.dataclass")
}

/// Whether `class` is or extends `enum.Enum`/`enum.IntEnum`/`enum.IntFlag`,
/// following bases of classes defined in this file.
fn is_enum_class<'a>(
    class: &'a StmtClassDef,
    classes: &HashMap<&str, &'a StmtClassDef>,
    aliases: &HashMap<String, String>,
    visited: &mut HashSet<&'a str>,
) -> bool {
    if !visited.insert(class.name.as_str()) {
        return false;
    }
    let Some(arguments) = &class.arguments else {
        return false;
    };
    arguments.args.iter().any(|base| match base {
        Expr::Name(name) => {
            if qualified_path(base, aliases).is_some_and(|path| ENUM_BASES.contains(&path.as_str()))
            {
                return true;
            }
            classes
                .get(name.id.as_str())
                .is_some_and(|parent| is_enum_class(parent, classes, aliases, visited))
        }
        Expr::Attribute(_) | Expr::Subscript(_) => {
            let base_expr = match base {
                Expr::Subscript(subscript) => subscript.value.as_ref(),
                other => other,
            };
            qualified_path(base_expr, aliases)
                .is_some_and(|path| ENUM_BASES.contains(&path.as_str()))
        }
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S8490";

    /// Sonar's own pair: `@dataclass` on an `Enum` subclass flags the
    /// decorator; the undecorated enum is clean.
    #[test]
    fn s8490_flags_sonar_example() {
        let flagged = scan(concat!(
            "from dataclasses import dataclass\n",
            "from enum import Enum\n",
            "\n",
            "@dataclass\n",
            "class Status(Enum):\n",
            "    PENDING = 1\n",
            "    APPROVED = 2\n",
            "    REJECTED = 3\n",
        ));
        let hits = findings(&flagged, KEY);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].range.start.line, 4);
        let clean = scan(concat!(
            "from enum import Enum\n",
            "\n",
            "class Status(Enum):\n",
            "    PENDING = 1\n",
            "    APPROVED = 2\n",
            "    REJECTED = 3\n",
        ));
        assert!(findings(&clean, KEY).is_empty());
    }

    /// Qualified decorators, call forms, aliased imports, and transitive
    /// enum bases all flag; `enum.Flag` and non-enum classes stay silent.
    #[test]
    fn s8490_forms() {
        let report = scan(concat!(
            "import dataclasses\n",
            "import enum\n",
            "\n",
            "@dataclasses.dataclass\n",
            "class A(enum.IntEnum):\n",
            "    X = 1\n",
            "\n",
            "@dataclasses.dataclass()\n",
            "class B(enum.IntFlag):\n",
            "    Y = 2\n",
        ));
        assert_eq!(findings(&report, KEY).len(), 2);
        let transitive = scan(concat!(
            "from dataclasses import dataclass\n",
            "from enum import Enum\n",
            "\n",
            "class Base(Enum):\n",
            "    A = 1\n",
            "\n",
            "@dataclass\n",
            "class Child(Base):\n",
            "    B = 2\n",
        ));
        assert_eq!(findings(&transitive, KEY).len(), 1);
        let clean = scan(concat!(
            "from dataclasses import dataclass\n",
            "import enum\n",
            "\n",
            "@dataclass\n",
            "class Flags(enum.Flag):\n",
            "    A = 1\n",
            "\n",
            "@dataclass\n",
            "class Plain:\n",
            "    x: int\n",
        ));
        assert!(findings(&clean, KEY).is_empty());
    }
}
