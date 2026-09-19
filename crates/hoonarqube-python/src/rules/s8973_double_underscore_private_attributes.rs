use ruff_python_ast::{Expr, ModModule, Stmt, StmtClassDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{ClassIndex, ImportFqns, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8973";
const MESSAGE: &str =
    "Replace this double underscore prefix with a single underscore to avoid Python name mangling.";

/// python:S8973 — Pydantic private attributes use a single leading
/// underscore. A double-underscore name is mangled to
/// `_ClassName__attr` before Pydantic sees it, so external access via the
/// written name and subclass access via `self.__attr` both raise
/// `AttributeError` while the class still defines and instantiates
/// cleanly. On a Pydantic model, every annotated attribute whose name
/// starts with `__` and does not end with `__` flags on the name, and so
/// does every `Name` target of a plain assignment whose value is a
/// `pydantic.PrivateAttr(...)` call. Dunder names (`__x__`), single
/// underscores, non-`PrivateAttr` plain assignments, and non-model classes
/// stay silent.
pub(crate) fn check_s8973_double_underscore_private_attributes(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let _ = parsed;
    let fqns = ImportFqns::build(file_ctx);
    let classes = ClassIndex::build(file_ctx);
    let mut issues = Vec::new();
    for class in &file_ctx.classes {
        check_class(class, &fqns, &classes, index, source, &mut issues);
    }
    issues
}

fn check_class(
    class: &StmtClassDef,
    fqns: &ImportFqns,
    classes: &ClassIndex,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if !classes.is_pydantic_model(class, fqns) {
        return;
    }
    for stmt in &class.body {
        match stmt {
            // Annotated attributes flag unconditionally — the reference
            // checks the variable name without requiring `PrivateAttr`.
            Stmt::AnnAssign(assign) => check_attribute(&assign.target, index, source, issues),
            // Plain assignments flag only when the value is a
            // `PrivateAttr(...)` call; each `Name` target is checked.
            Stmt::Assign(assign) if is_private_attr_call(&assign.value, fqns) => {
                for target in &assign.targets {
                    check_attribute(target, index, source, issues);
                }
            }
            _ => {}
        }
    }
}

/// Whether the assigned value is a `pydantic.PrivateAttr(...)` call.
fn is_private_attr_call(value: &Expr, fqns: &ImportFqns) -> bool {
    let Expr::Call(call) = value else {
        return false;
    };
    fqns.is_fqn_in(
        &call.func,
        &["pydantic.PrivateAttr", "pydantic.fields.PrivateAttr"],
    )
}

/// Flags a `Name` target whose identifier starts with `__` but does not
/// end with `__` — the name-mangled private-attribute shape.
fn check_attribute(target: &Expr, index: &LineIndex, source: &str, issues: &mut Vec<Issue>) {
    let Expr::Name(name) = target else {
        return;
    };
    let identifier = name.id.as_str();
    if identifier.starts_with("__") && !identifier.ends_with("__") {
        issues.push(issue_at(RULE_KEY, MESSAGE, name.range(), index, source));
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S8973")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s8973_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: `__counter` anchors on the name
        // (line 5, columns 4-13).
        let ranges = found(concat!(
            "from pydantic import BaseModel, PrivateAttr\n",
            "\n",
            "class Model(BaseModel):\n",
            "    __counter: int = PrivateAttr(default=0)\n",
            "\n",
            "m = Model()\n",
            "print(m.__counter)\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(4, 4));
        assert_eq!(ranges[0].end, pos(4, 13));
    }

    #[test]
    fn s8973_accepts_the_sonar_compliant_example() {
        assert!(
            found(concat!(
                "from pydantic import BaseModel, PrivateAttr\n",
                "\n",
                "class Model(BaseModel):\n",
                "    _counter: int = PrivateAttr(default=0)\n",
                "\n",
                "m = Model()\n",
                "print(m._counter)\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8973_flags_annotated_names_and_private_attr_targets() {
        // Annotated `__` names flag without `PrivateAttr`; plain
        // assignments flag only through `PrivateAttr(...)`, on every
        // `Name` target.
        let ranges = found(concat!(
            "from pydantic import BaseModel, PrivateAttr\n",
            "\n",
            "class Model(BaseModel):\n",
            "    __a: int\n",
            "    __b = PrivateAttr(default=0)\n",
            "    __c = __d = PrivateAttr(default=1)\n",
            "    __e = 0\n",
            "    __f__: int = PrivateAttr(default=0)\n",
            "    _g: int\n",
        ));
        assert_eq!(ranges.len(), 4);
        assert_eq!(ranges[0].start, pos(4, 4));
        assert_eq!(ranges[0].end, pos(4, 7));
        assert_eq!(ranges[1].start, pos(5, 4));
        assert_eq!(ranges[1].end, pos(5, 7));
        assert_eq!(ranges[2].start, pos(6, 4));
        assert_eq!(ranges[2].end, pos(6, 7));
        assert_eq!(ranges[3].start, pos(6, 10));
        assert_eq!(ranges[3].end, pos(6, 13));
    }

    #[test]
    fn s8973_ignores_non_model_classes() {
        assert!(
            found(concat!(
                "from pydantic import PrivateAttr\n",
                "\n",
                "class Plain:\n",
                "    __a: int = PrivateAttr(default=0)\n",
                "    __b = PrivateAttr(default=0)\n",
            ))
            .is_empty()
        );
    }
}
