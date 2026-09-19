use ruff_python_ast::{Expr, ModModule, Stmt, StmtClassDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{ClassIndex, ImportFqns, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8396";
const MESSAGE: &str = "Add an explicit default value to this optional field.";

/// python:S8396 — `Optional[T]` only permits `None` as a value; it does not
/// make a Pydantic field optional during validation. An annotated model
/// field typed `Optional[…]` with no assigned value, or assigned
/// `Field(…)` (the ellipsis marks the field required) without a `default`/
/// `default_factory` keyword, still raises "field required" when the input
/// omits it. The finding anchors on the annotation expression. `T | None`,
/// `None | T`, and `Union[T, None]` annotations are explicit nullable
/// declarations and stay silent, as do `Optional` fields with any other
/// default and non-model classes.
pub(crate) fn check_s8396_optional_field_defaults(
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
        let Stmt::AnnAssign(assign) = stmt else {
            continue;
        };
        check_field(assign, fqns, index, source, issues);
    }
}

fn check_field(
    assign: &ruff_python_ast::StmtAnnAssign,
    fqns: &ImportFqns,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if !is_typing_optional(&assign.annotation, fqns) {
        return;
    }
    let missing_default = match assign.value.as_deref() {
        None => true,
        Some(value) => is_field_call_with_ellipsis(value, fqns),
    };
    if missing_default {
        issues.push(issue_at(
            RULE_KEY,
            MESSAGE,
            assign.annotation.range(),
            index,
            source,
        ));
    }
}

/// Whether the annotation is `Optional[…]` — a subscript whose object
/// resolves to `typing.Optional` (the reference's `isType` match; the
/// `typing_extensions` re-export is accepted as the same declaration).
fn is_typing_optional(annotation: &Expr, fqns: &ImportFqns) -> bool {
    let Expr::Subscript(subscript) = annotation else {
        return false;
    };
    fqns.is_fqn_in(
        &subscript.value,
        &["typing.Optional", "typing_extensions.Optional"],
    )
}

/// Whether the assigned value is a `pydantic.Field(…)` call whose first
/// positional argument is the ellipsis and which carries no `default` or
/// `default_factory` keyword — the contradictory "required Optional" form.
fn is_field_call_with_ellipsis(value: &Expr, fqns: &ImportFqns) -> bool {
    let Expr::Call(call) = value else {
        return false;
    };
    if !fqns.is_fqn_in(&call.func, &["pydantic.Field", "pydantic.fields.Field"]) {
        return false;
    }
    let [first, ..] = &call.arguments.args[..] else {
        return false;
    };
    if !matches!(first, Expr::EllipsisLiteral(_)) {
        return false;
    }
    !call.arguments.keywords.iter().any(|keyword| {
        keyword
            .arg
            .as_ref()
            .is_some_and(|arg| matches!(arg.as_str(), "default" | "default_factory"))
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S8396")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s8396_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: `Optional[TwitterAccount]` without a
        // default anchors on the annotation (line 10, columns 21-45).
        let ranges = found(concat!(
            "from typing import Optional\n",
            "from pydantic import BaseModel, Field\n",
            "\n",
            "class TwitterAccount(BaseModel):\n",
            "    username: str\n",
            "    followers: int\n",
            "\n",
            "class UserRead(BaseModel):\n",
            "    name: str\n",
            "    twitter_account: Optional[TwitterAccount]\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(10, 21));
        assert_eq!(ranges[0].end, pos(10, 45));
    }

    #[test]
    fn s8396_accepts_the_sonar_compliant_example() {
        assert!(
            found(concat!(
                "from typing import Optional, Union\n",
                "from pydantic import BaseModel, Field\n",
                "\n",
                "class TwitterAccount(BaseModel):\n",
                "    username: str\n",
                "    followers: int\n",
                "\n",
                "class UserRead(BaseModel):\n",
                "    name: str\n",
                "    twitter_account: Optional[TwitterAccount] = None\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8396_flags_field_ellipsis_but_not_other_defaults() {
        // `Field(…)` marks the field required — a contradiction with the
        // `Optional` hint — while `Field(default=None)` and
        // `Field(default_factory=…)` provide real defaults.
        let ranges = found(concat!(
            "from typing import Optional\n",
            "from pydantic import BaseModel, Field\n",
            "\n",
            "class Model(BaseModel):\n",
            "    required: Optional[int] = Field(...)\n",
            "    described: Optional[int] = Field(..., description=\"x\")\n",
            "    defaulted: Optional[int] = Field(default=None)\n",
            "    factory: Optional[list] = Field(default_factory=list)\n",
            "    plain: Optional[int] = 5\n",
        ));
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, pos(5, 14));
        assert_eq!(ranges[0].end, pos(5, 27));
        assert_eq!(ranges[1].start, pos(6, 15));
        assert_eq!(ranges[1].end, pos(6, 28));
    }

    #[test]
    fn s8396_accepts_explicit_nullable_annotations() {
        // The documented exceptions: `T | None`, `None | T`, and
        // `Union[T, None]` are explicit nullable declarations, compliant
        // with or without a default.
        assert!(
            found(concat!(
                "from typing import Optional, Union\n",
                "from pydantic import BaseModel\n",
                "\n",
                "class Model(BaseModel):\n",
                "    a: int | None\n",
                "    b: None | int\n",
                "    c: Union[int, None]\n",
                "    d: Union[int, None] = None\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8396_ignores_non_model_classes_and_non_optional_fields() {
        // Plain classes are not Pydantic models; required non-Optional
        // fields and `Optional` imported from elsewhere stay silent.
        assert!(
            found(concat!(
                "from typing import Optional\n",
                "from pydantic import BaseModel\n",
                "\n",
                "class Plain:\n",
                "    value: Optional[int]\n",
                "\n",
                "class Model(BaseModel):\n",
                "    name: str\n",
                "    count: int = 0\n",
            ))
            .is_empty()
        );
        assert!(
            found(concat!(
                "from other import Optional\n",
                "from pydantic import BaseModel\n",
                "\n",
                "class Model(BaseModel):\n",
                "    value: Optional[int]\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8396_flags_models_inheriting_through_local_bases() {
        // A model reached through an in-file base chain is still a Pydantic
        // model; `typing.Optional` and aliased imports resolve the same.
        let ranges = found(concat!(
            "import typing\n",
            "import pydantic as pd\n",
            "\n",
            "class Base(pd.BaseModel):\n",
            "    pass\n",
            "\n",
            "class Model(Base):\n",
            "    a: typing.Optional[int]\n",
            "    b: typing.Optional[int] = None\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(8, 7));
        assert_eq!(ranges[0].end, pos(8, 27));
    }
}
