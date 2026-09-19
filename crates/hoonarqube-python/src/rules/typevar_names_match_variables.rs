use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::dotted_segments;
use crate::support::issue_at;

const RULE_KEY: &str = "python:S8507";
const MESSAGE_TEMPLATE: &str = "Rename this string to match the variable name";
const TYPING_MEMBERS: [&str; 3] = ["TypeVar", "ParamSpec", "NewType"];
const TYPING_MODULES: [&str; 2] = ["typing", "typing_extensions"];

/// python:S8507 — the string passed to `TypeVar`, `ParamSpec`, or
/// `NewType` is what type checkers and error messages display, so it
/// should equal the variable the object is assigned to. The finding
/// anchors on the mismatched string literal.
pub(crate) fn check_typevar_names_match_variables(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let _ = parsed;
    let bindings = typing_construct_bindings(file_ctx);
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        check_assign(stmt, &bindings, index, source, &mut issues);
    }
    issues
}

/// Flags `X = TypeVar("Y")` (and `ParamSpec`/`NewType`) where the first
/// positional or `name=` argument is a string literal that differs from
/// the single assigned name. Multi-target assignments, annotated
/// assignments, and calls not directly assigned stay silent.
fn check_assign(
    stmt: &Stmt,
    bindings: &TypingBindings,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let Stmt::Assign(assign) = stmt else {
        return;
    };
    let Expr::Call(call) = assign.value.as_ref() else {
        return;
    };
    if !is_typing_construct(&call.func, bindings) {
        return;
    }
    let [Expr::Name(target)] = assign.targets.as_slice() else {
        return;
    };
    let Some(name_arg) = first_or_named_argument(call) else {
        return;
    };
    let Expr::StringLiteral(literal) = name_arg else {
        return;
    };
    if literal.value.to_str() == target.id.as_str() {
        return;
    }
    issues.push(issue_at(
        RULE_KEY,
        &format!("{MESSAGE_TEMPLATE} \"{}\".", target.id),
        literal.range(),
        index,
        source,
    ));
}

/// The call's first positional argument, or its `name=` keyword when no
/// positional precedes it — the reference's `nthArgumentOrKeyword(0,
/// "name", …)` lookup. `*`-unpacked arguments do not count as positional.
fn first_or_named_argument(call: &ruff_python_ast::ExprCall) -> Option<&Expr> {
    let positional = call
        .arguments
        .args
        .iter()
        .find(|arg| !matches!(arg, Expr::Starred(_)));
    if let Some(arg) = positional {
        return Some(arg);
    }
    call.arguments
        .keywords
        .iter()
        .find(|keyword| keyword.arg.as_deref() == Some("name"))
        .map(|keyword| &keyword.value)
}

/// Whether the callee resolves to `TypeVar`, `ParamSpec`, or `NewType`
/// from `typing`/`typing_extensions` — by qualified path, module alias,
/// or from-import binding (including `as`-aliases and star imports).
fn is_typing_construct(func: &Expr, bindings: &TypingBindings) -> bool {
    let Some(segments) = dotted_segments(func) else {
        return false;
    };
    if segments.len() == 2
        && TYPING_MEMBERS.contains(&segments[1])
        && (TYPING_MODULES.contains(&segments[0])
            || bindings
                .module_aliases
                .iter()
                .any(|alias| alias == segments[0]))
    {
        return true;
    }
    segments.len() == 1 && bindings.names.iter().any(|name| name == segments[0])
}

/// Local names bound to `typing`/`typing_extensions` `TypeVar`,
/// `ParamSpec`, or `NewType` by from-imports (star imports bind all
/// three canonical names), plus local aliases of the two modules.
struct TypingBindings {
    names: Vec<String>,
    module_aliases: Vec<String>,
}

fn typing_construct_bindings(file_ctx: &FileContext) -> TypingBindings {
    let mut names = Vec::new();
    let mut module_aliases = Vec::new();
    for import in &file_ctx.imports {
        match import {
            AnyImport::From(import) if import.level == 0 => {
                let module = import.module.as_ref().map_or("", |m| m.as_str());
                if !TYPING_MODULES.contains(&module) {
                    continue;
                }
                for alias in &import.names {
                    if alias.name.as_str() == "*" {
                        names.extend(TYPING_MEMBERS.iter().map(ToString::to_string));
                    } else if TYPING_MEMBERS.contains(&alias.name.as_str()) {
                        names.push(
                            alias
                                .asname
                                .as_ref()
                                .map_or_else(|| alias.name.to_string(), |a| a.as_str().to_string()),
                        );
                    }
                }
            }
            AnyImport::Plain(import) => {
                for alias in &import.names {
                    if TYPING_MODULES.contains(&alias.name.as_str())
                        && let Some(asname) = &alias.asname
                    {
                        module_aliases.push(asname.as_str().to_string());
                    }
                }
            }
            AnyImport::From(_) => {}
        }
    }
    TypingBindings {
        names,
        module_aliases,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s8507_flags_mismatched_names_on_sonar_example() {
        // The reference Noncompliant example, verbatim.
        let flagged = scan(concat!(
            "from typing import TypeVar, ParamSpec, NewType\n",
            "\n",
            "MyType = TypeVar(\"T\")\n",
            "MyParams = ParamSpec(\"P\")\n",
            "MyInt = NewType(\"Integer\", int)\n",
        ));
        let found = findings(&flagged, "python:S8507");
        assert_eq!(found.len(), 3);
        // Each anchor covers the mismatched string literal.
        assert_eq!(found[0].range.start, pos(3, 17));
        assert_eq!(found[0].range.end, pos(3, 20));
        assert_eq!(
            found[0].message,
            "Rename this string to match the variable name \"MyType\"."
        );
    }

    #[test]
    fn s8507_accepts_matching_names_on_sonar_example() {
        // The reference Compliant solution, verbatim.
        let clean = scan(concat!(
            "from typing import TypeVar, ParamSpec, NewType\n",
            "\n",
            "MyType = TypeVar(\"MyType\")\n",
            "MyParams = ParamSpec(\"MyParams\")\n",
            "MyInt = NewType(\"MyInt\", int)\n",
        ));
        assert!(findings(&clean, "python:S8507").is_empty());
    }

    #[test]
    fn s8507_flags_qualified_and_aliased_constructs() {
        let flagged = scan(concat!(
            "import typing\n",
            "import typing_extensions as te\n",
            "from typing import TypeVar as TV\n",
            "\n",
            "A = typing.TypeVar(\"B\")\n",
            "C = te.ParamSpec(\"D\")\n",
            "E = TV(\"F\")\n",
        ));
        assert_eq!(findings(&flagged, "python:S8507").len(), 3);
    }

    #[test]
    fn s8507_accepts_unassigned_and_multi_target_calls() {
        // TypeVar calls inside a tuple or a multi-target assignment are
        // not the direct `X = TypeVar(...)` shape the rule checks.
        let clean = scan(concat!(
            "pair = (TypeVar(\"T\"), TypeVar(\"U\"))\n",
            "x = y = TypeVar(\"Z\")\n",
        ));
        assert!(findings(&clean, "python:S8507").is_empty());
    }

    #[test]
    fn s8507_accepts_non_string_and_missing_name_arguments() {
        let clean = scan(concat!(
            "from typing import TypeVar\n",
            "\n",
            "A = TypeVar()\n",
            "B = TypeVar(name)\n",
            "C = TypeVar(*args)\n",
        ));
        assert!(findings(&clean, "python:S8507").is_empty());
    }
}
