use ruff_python_ast::{Expr, ExprCall, ExprSubscript, ModModule, Stmt, StmtClassDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{ClassIndex, ImportFqns, NameResolver, NameValue, flow_location, issue_at};
use hoonarqube_ir::{Issue, IssueFlow};

const RULE_KEY: &str = "python:S8971";
const MESSAGE: &str =
    "Remove either \"SkipValidation\" or the validation constraints from this annotation.";
const SECONDARY_MESSAGE: &str = "Validation constraint is set here.";

/// `Annotated` subscript heads the reference accepts
/// (`typing.Annotated` and `typing_extensions.Annotated`).
const ANNOTATED_FQNS: &[&str] = &["typing.Annotated", "typing_extensions.Annotated"];

/// `SkipValidation` FQNs the reference's `withFQN` matchers accept.
const SKIP_VALIDATION_FQNS: &[&str] = &[
    "pydantic.SkipValidation",
    "pydantic.functional_validators.SkipValidation",
];

/// `Field` FQNs the reference's `isType` matcher accepts for the
/// constraint-keyword check.
const FIELD_FQNS: &[&str] = &["pydantic.Field", "pydantic.fields.Field"];

/// `Field(...)` keyword names that carry a validation constraint.
const FIELD_CONSTRAINT_ARGS: &[&str] = &[
    "gt",
    "ge",
    "lt",
    "le",
    "multiple_of",
    "min_length",
    "max_length",
    "pattern",
    "max_digits",
    "decimal_places",
];

/// Validator/serializer FQNs the reference's `withFQN` matchers accept as
/// direct constraints, called or bare.
const VALIDATION_CONSTRAINT_FQNS: &[&str] = &[
    "pydantic.StringConstraints",
    "pydantic.types.StringConstraints",
    "pydantic.AfterValidator",
    "pydantic.functional_validators.AfterValidator",
    "pydantic.BeforeValidator",
    "pydantic.functional_validators.BeforeValidator",
    "pydantic.PlainValidator",
    "pydantic.functional_validators.PlainValidator",
    "pydantic.WrapValidator",
    "pydantic.functional_validators.WrapValidator",
    "pydantic.WrapSerializer",
    "pydantic.functional_serializers.WrapSerializer",
    "pydantic.PlainSerializer",
    "pydantic.functional_serializers.PlainSerializer",
];

/// python:S8971 — `SkipValidation` rewrites a field's schema to
/// `any_schema`: as the outermost `Annotated` metadata it silently drops
/// inner constraints, and inside `Annotated` it skips the type check so
/// wrong-typed values hit constraints as `TypeError`s instead of clean
/// `ValidationError`s. An `Annotated[…]` field on a Pydantic model whose
/// flattened metadata contains both `SkipValidation` and a validation
/// constraint flags the `SkipValidation` element; every constraint
/// expression is a secondary location. Constraints are `Field(...)` calls
/// carrying a constraint keyword (`gt`, `ge`, `lt`, `le`, `multiple_of`,
/// `min_length`, `max_length`, `pattern`, `max_digits`, `decimal_places`),
/// `StringConstraints`, and the `After`/`Before`/`Plain`/`Wrap` validators
/// and `Plain`/`Wrap` serializers — called or bare — plus names bound once
/// to one of those. `SkipValidation` alone, constraints without
/// `SkipValidation`, and non-model classes stay silent.
pub(crate) fn check_s8971_skip_validation_constraints(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let fqns = ImportFqns::build(file_ctx);
    let classes = ClassIndex::build(file_ctx);
    let resolver = NameResolver::build(parsed, source);
    let mut issues = Vec::new();
    for class in &file_ctx.classes {
        check_class(
            class,
            &fqns,
            &classes,
            &resolver,
            index,
            source,
            &mut issues,
        );
    }
    issues
}

fn check_class(
    class: &StmtClassDef,
    fqns: &ImportFqns,
    classes: &ClassIndex,
    resolver: &NameResolver,
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
        check_field_annotation(assign, fqns, resolver, index, source, issues);
    }
}

fn check_field_annotation(
    assign: &ruff_python_ast::StmtAnnAssign,
    fqns: &ImportFqns,
    resolver: &NameResolver,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let Expr::Subscript(subscript) = assign.annotation.as_ref() else {
        return;
    };
    if !fqns.is_fqn_in(&subscript.value, ANNOTATED_FQNS) {
        return;
    }
    let elements = collect_annotated_elements(subscript, fqns);
    let Some(skip_validation) = elements
        .iter()
        .find(|element| is_skip_validation(element, fqns))
    else {
        return;
    };
    let constraints: Vec<&Expr> = elements
        .iter()
        .filter_map(|element| resolve_constraint_secondary(element, fqns, resolver))
        .collect();
    if constraints.is_empty() {
        return;
    }
    let mut issue = issue_at(RULE_KEY, MESSAGE, skip_validation.range(), index, source);
    issue.flows.push(IssueFlow {
        locations: constraints
            .iter()
            .map(|constraint| flow_location(SECONDARY_MESSAGE, constraint.range(), index, source))
            .collect(),
    });
    issues.push(issue);
}

/// The flattened `Annotated` metadata: every subscript element except the
/// type position, recursing into nested `Annotated[…]` elements — the
/// reference's `collectAnnotatedElements` (metadata first, then the
/// type-position element when it is itself `Annotated`).
fn collect_annotated_elements<'a>(
    subscript: &'a ExprSubscript,
    fqns: &ImportFqns,
) -> Vec<&'a Expr> {
    let mut elements = Vec::new();
    let slice = subscript.slice.as_ref();
    let items: &[Expr] = match slice {
        Expr::Tuple(tuple) => &tuple.elts,
        other => std::slice::from_ref(other),
    };
    for element in &items[1..] {
        collect_element(element, fqns, &mut elements);
    }
    if let Some(first) = items.first() {
        collect_element(first, fqns, &mut elements);
    }
    elements
}

fn collect_element<'a>(element: &'a Expr, fqns: &ImportFqns, elements: &mut Vec<&'a Expr>) {
    if let Expr::Subscript(nested) = element
        && fqns.is_fqn_in(&nested.value, ANNOTATED_FQNS)
    {
        elements.extend(collect_annotated_elements(nested, fqns));
        return;
    }
    elements.push(element);
}

/// Whether the element is `SkipValidation` — bare or subscripted
/// (`SkipValidation[int]`), per the reference's `withFQN` matcher.
fn is_skip_validation(element: &Expr, fqns: &ImportFqns) -> bool {
    match element {
        Expr::Subscript(subscript) => fqns.is_fqn_in(&subscript.value, SKIP_VALIDATION_FQNS),
        other => fqns.is_fqn_in(other, SKIP_VALIDATION_FQNS),
    }
}

/// The expression a constraint secondary anchors on: the element itself
/// when it is a direct constraint, or the expression its single assignment
/// bound when the element is a `Name` (the reference's
/// `resolveConstraintSecondary`).
fn resolve_constraint_secondary<'a>(
    element: &'a Expr,
    fqns: &ImportFqns,
    resolver: &NameResolver<'a>,
) -> Option<&'a Expr> {
    if is_direct_constraint(element, fqns) {
        return Some(element);
    }
    if let Expr::Name(_) = element
        && let NameValue::Single(value) = resolver.resolve(element)
        && is_direct_constraint(value, fqns)
    {
        return Some(value);
    }
    None
}

/// Whether the expression is a validation constraint: a call to a
/// constraint factory, a `Field(...)` call carrying a constraint keyword,
/// or a bare constraint-typed name (`StringConstraints`,
/// `AfterValidator`, …).
fn is_direct_constraint(expr: &Expr, fqns: &ImportFqns) -> bool {
    match expr {
        Expr::Call(call) => {
            if fqns.is_fqn_in(&call.func, VALIDATION_CONSTRAINT_FQNS) {
                return true;
            }
            if fqns.is_fqn_in(&call.func, FIELD_FQNS) {
                return has_field_constraint_arg(call);
            }
            false
        }
        other => fqns.is_fqn_in(other, VALIDATION_CONSTRAINT_FQNS),
    }
}

/// Whether a `Field(...)` call sets any validation-constraint keyword.
fn has_field_constraint_arg(call: &ExprCall) -> bool {
    call.arguments.keywords.iter().any(|keyword| {
        keyword
            .arg
            .as_ref()
            .is_some_and(|arg| FIELD_CONSTRAINT_ARGS.contains(&arg.as_str()))
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8971")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8971_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: both `SkipValidation` elements
        // flag — the outer one drops `Field(gt=0)`, the inner one skips
        // the type check before `Field(gt=0)`. `Field` is imported from
        // `pydantic.fields`, the FQN the reference matches.
        let flagged = found(concat!(
            "from typing import Annotated\n",
            "from pydantic import BaseModel, SkipValidation\n",
            "from pydantic.fields import Field\n",
            "\n",
            "class Model(BaseModel):\n",
            "    value: Annotated[Annotated[int, Field(gt=0)], SkipValidation]\n",
            "    other: Annotated[int, SkipValidation, Field(gt=0)]\n",
        ));
        assert_eq!(flagged.len(), 2);
        // `SkipValidation` in `value` (line 6, columns 50-64).
        assert_eq!(flagged[0].range.start, pos(6, 50));
        assert_eq!(flagged[0].range.end, pos(6, 64));
        assert_eq!(flagged[0].flows[0].locations.len(), 1);
        assert_eq!(flagged[0].flows[0].locations[0].range.start, pos(6, 36));
        // `SkipValidation` in `other` (line 7, columns 26-40).
        assert_eq!(flagged[1].range.start, pos(7, 26));
        assert_eq!(flagged[1].range.end, pos(7, 40));
        assert_eq!(
            flagged[1].flows[0].locations[0].message,
            "Validation constraint is set here."
        );
    }

    #[test]
    fn s8971_accepts_the_sonar_compliant_example() {
        assert!(
            found(concat!(
                "from typing import Annotated\n",
                "from pydantic import BaseModel, SkipValidation\n",
                "from pydantic.fields import Field\n",
                "\n",
                "class Model(BaseModel):\n",
                "    validated: Annotated[int, Field(gt=0)]\n",
                "    trusted: SkipValidation[int]\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8971_flags_validators_and_string_constraints() {
        // `StringConstraints`, `AfterValidator`, and `WrapSerializer` are
        // constraints too — called or bare — and a name bound once to a
        // constraint resolves to the assigned expression.
        let flagged = found(concat!(
            "from typing import Annotated\n",
            "from pydantic import BaseModel, SkipValidation, StringConstraints\n",
            "from pydantic.functional_validators import AfterValidator\n",
            "\n",
            "CHECK = AfterValidator(int)\n",
            "\n",
            "class Model(BaseModel):\n",
            "    a: Annotated[str, SkipValidation, StringConstraints(min_length=1)]\n",
            "    b: Annotated[int, SkipValidation, AfterValidator]\n",
            "    c: Annotated[int, SkipValidation, CHECK]\n",
        ));
        assert_eq!(flagged.len(), 3);
        // `CHECK`'s secondary anchors on the assigned `AfterValidator(int)`
        // call (line 5), not the name use.
        assert_eq!(flagged[2].flows[0].locations[0].range.start, pos(5, 8));
    }

    #[test]
    fn s8971_accepts_skip_validation_alone_and_non_constraint_fields() {
        // `SkipValidation` without constraints, `Field` without constraint
        // keywords, and non-model classes stay silent.
        assert!(
            found(concat!(
                "from typing import Annotated\n",
                "from pydantic import BaseModel, SkipValidation\n",
                "from pydantic.fields import Field\n",
                "\n",
                "class Model(BaseModel):\n",
                "    a: Annotated[int, SkipValidation]\n",
                "    b: Annotated[int, SkipValidation, Field(alias=\"x\")]\n",
                "    c: Annotated[int, Field(gt=0)]\n",
                "\n",
                "class Plain:\n",
                "    d: Annotated[int, SkipValidation, Field(gt=0)]\n",
            ))
            .is_empty()
        );
    }
}
