use std::collections::HashSet;

use ruff_python_ast::{Expr, ExprCall, ModModule, Stmt, StmtClassDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::engine::file_context::FileContext;
use crate::support::{ClassIndex, ImportFqns, NameResolver, NameValue, flow_location, issue_at};
use hoonarqube_ir::{Issue, IssueFlow};

const RULE_KEY: &str = "python:S8978";
const MESSAGE: &str =
    "Explicitly set 'revalidate_instances' in this Pydantic model's configuration.";
const SECONDARY_MESSAGE: &str = "The dataclass-typed field is defined here.";

/// `ConfigDict` FQNs the reference's `isType("pydantic.ConfigDict")`
/// matcher accepts.
const CONFIG_DICT_FQNS: &[&str] = &["pydantic.ConfigDict", "pydantic.config.ConfigDict"];

/// python:S8978 — dataclasses perform no runtime type checking, so a
/// `BaseModel` field typed as a dataclass accepts an already-constructed
/// instance without revalidating it unless `revalidate_instances` is
/// configured. The reference flags the model's class name when it holds
/// an annotated field whose type resolves to a same-file
/// `dataclasses.dataclass`-decorated class — through `Optional`/`List`/
/// `Annotated`/`dict[…]` subscripts and PEP-604 `X | Y` unions — and no
/// `revalidate_instances` is set: not as a class keyword argument, not in
/// any class-body assignment whose value is a `ConfigDict(...)` call or a
/// dict literal containing the key (a name resolves through its single
/// assignment, chasing aliases), and not inherited from an in-file
/// ancestor. Each dataclass-typed field is a secondary location. Pydantic
/// dataclasses, plain classes, unresolved annotations, and non-model
/// classes stay silent.
pub(crate) fn check_s8978_pydantic_dataclass_revalidation(
    _parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let fqns = ImportFqns::build(file_ctx);
    let classes = ClassIndex::build(file_ctx);
    let resolver = NameResolver::build(file_ctx);
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
    if has_explicit_revalidate_instances(class, fqns, resolver)
        || has_revalidate_instances_keyword_arg(class)
        || has_inherited_revalidate_instances(class, classes, fqns, resolver)
    {
        return;
    }
    let dataclass_fields: Vec<&Expr> = class
        .body
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::AnnAssign(assign)
                if is_dataclass_annotation(&assign.annotation, classes, fqns) =>
            {
                Some(assign.target.as_ref())
            }
            _ => None,
        })
        .collect();
    if dataclass_fields.is_empty() {
        return;
    }
    let mut issue = issue_at(RULE_KEY, MESSAGE, class.name.range(), index, source);
    issue.flows.push(IssueFlow {
        locations: dataclass_fields
            .iter()
            .map(|field| flow_location(SECONDARY_MESSAGE, field.range(), index, source))
            .collect(),
    });
    issues.push(issue);
}

/// Whether any class-body assignment's value sets `revalidate_instances`:
/// a `ConfigDict(...)` call carrying the keyword or a dict literal
/// containing the key. The reference inspects every `AssignmentStatement`
/// regardless of the assigned name, and resolves a `Name` right-hand side
/// through its single assignment (chasing aliases until a non-name
/// value).
fn has_explicit_revalidate_instances(
    class: &StmtClassDef,
    fqns: &ImportFqns,
    resolver: &NameResolver,
) -> bool {
    class.body.iter().any(|stmt| {
        let Stmt::Assign(assign) = stmt else {
            return false;
        };
        let Some(rhs) = resolve_non_name_value(&assign.value, resolver) else {
            return false;
        };
        match rhs {
            Expr::Call(call) => {
                fqns.is_fqn_in(&call.func, CONFIG_DICT_FQNS)
                    && has_revalidate_instances_keyword(call)
            }
            Expr::Dict(dict) => dict.items.iter().any(|item| {
                matches!(
                    &item.key,
                    Some(Expr::StringLiteral(key))
                        if key.value.to_str() == "revalidate_instances"
                )
            }),
            _ => false,
        }
    })
}

/// The expression a `Name` ultimately resolves to through single
/// assignments, or the expression itself when it is not a name — the
/// reference's `ifNameGetSingleAssignedNonNameValue` (a name that is not
/// provably single-assigned resolves to `None`).
fn resolve_non_name_value<'a>(expr: &'a Expr, resolver: &NameResolver<'a>) -> Option<&'a Expr> {
    let mut current = expr;
    let mut visited: HashSet<TextRange> = HashSet::new();
    while let Expr::Name(_) = current {
        if !visited.insert(current.range()) {
            return None;
        }
        match resolver.resolve(current) {
            NameValue::Single(value) => current = value,
            _ => return None,
        }
    }
    Some(current)
}

/// Whether the class declaration passes `revalidate_instances` as a
/// keyword argument (`class Foo(BaseModel, revalidate_instances='always')`).
fn has_revalidate_instances_keyword_arg(class: &StmtClassDef) -> bool {
    class.arguments.as_ref().is_some_and(|arguments| {
        arguments.keywords.iter().any(|keyword| {
            keyword
                .arg
                .as_ref()
                .is_some_and(|arg| arg.as_str() == "revalidate_instances")
        })
    })
}

/// Whether `call` carries a `revalidate_instances` keyword argument.
fn has_revalidate_instances_keyword(call: &ExprCall) -> bool {
    call.arguments.keywords.iter().any(|keyword| {
        keyword
            .arg
            .as_ref()
            .is_some_and(|arg| arg.as_str() == "revalidate_instances")
    })
}

/// Whether any in-file ancestor of `class` sets `revalidate_instances` —
/// the reference's MRO walk restricted to same-file `ClassDef`s (bases
/// that resolve to nothing contribute nothing, matching the reference's
/// conservative cross-file behavior).
fn has_inherited_revalidate_instances(
    class: &StmtClassDef,
    classes: &ClassIndex,
    fqns: &ImportFqns,
    resolver: &NameResolver,
) -> bool {
    let mut visited: HashSet<TextRange> = HashSet::new();
    let mut pending: Vec<&StmtClassDef> = vec![class];
    while let Some(current) = pending.pop() {
        if !visited.insert(current.name.range()) {
            continue;
        }
        if current.name.range() != class.name.range()
            && (has_explicit_revalidate_instances(current, fqns, resolver)
                || has_revalidate_instances_keyword_arg(current))
        {
            return true;
        }
        let Some(arguments) = &current.arguments else {
            continue;
        };
        for base in &arguments.args {
            if let Expr::Name(name) = base
                && let Some(parent) = classes.local_class(name.id.as_str())
            {
                pending.push(parent);
            }
        }
    }
    false
}

/// Whether the annotation refers to a same-file class decorated with
/// `dataclasses.dataclass`: a bare name, any element of a subscript
/// (`Optional[User]`, `dict[str, User]`, `Annotated[User, 'meta']`), or
/// either side of a PEP-604 `X | Y` union.
fn is_dataclass_annotation(annotation: &Expr, classes: &ClassIndex, fqns: &ImportFqns) -> bool {
    match annotation {
        Expr::Name(name) => classes
            .local_class(name.id.as_str())
            .is_some_and(|class| is_dataclass_decorated(class, fqns)),
        Expr::Subscript(subscript) => slice_elements(&subscript.slice)
            .iter()
            .any(|element| is_dataclass_annotation(element, classes, fqns)),
        Expr::BinOp(binop) if matches!(binop.op, ruff_python_ast::Operator::BitOr) => {
            is_dataclass_annotation(&binop.left, classes, fqns)
                || is_dataclass_annotation(&binop.right, classes, fqns)
        }
        _ => false,
    }
}

/// The expressions inside a subscript's brackets: the single slice
/// expression, or every element of a tuple slice.
fn slice_elements(slice: &Expr) -> Vec<&Expr> {
    match slice {
        Expr::Tuple(tuple) => tuple.elts.iter().collect(),
        other => vec![other],
    }
}

/// Whether `class` is decorated with `dataclasses.dataclass`, called or
/// bare (the reference unwraps the call to its callee).
fn is_dataclass_decorated(class: &StmtClassDef, fqns: &ImportFqns) -> bool {
    class.decorator_list.iter().any(|decorator| {
        let expression = match &decorator.expression {
            Expr::Call(call) => call.func.as_ref(),
            other => other,
        };
        fqns.is_fqn(expression, "dataclasses.dataclass")
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8978")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8978_flags_the_sonar_noncompliant_example() {
        let flagged = found(concat!(
            "import dataclasses\n",
            "from pydantic import BaseModel\n",
            "\n",
            "@dataclasses.dataclass\n",
            "class User:\n",
            "    name: str\n",
            "\n",
            "class Foo(BaseModel):\n",
            "    user: User\n",
        ));
        assert_eq!(flagged.len(), 1);
        // The issue anchors on the class name `Foo` (line 8, columns 6-9)
        // with the `user` field as secondary (line 9, columns 4-8).
        assert_eq!(flagged[0].range.start, pos(8, 6));
        assert_eq!(flagged[0].range.end, pos(8, 9));
        assert_eq!(
            flagged[0].message,
            "Explicitly set 'revalidate_instances' in this Pydantic model's configuration."
        );
        assert_eq!(flagged[0].flows[0].locations.len(), 1);
        assert_eq!(flagged[0].flows[0].locations[0].range.start, pos(9, 4));
        assert_eq!(flagged[0].flows[0].locations[0].range.end, pos(9, 8));
        assert_eq!(
            flagged[0].flows[0].locations[0].message,
            "The dataclass-typed field is defined here."
        );
    }

    #[test]
    fn s8978_flags_wrapped_annotations_and_pep604_unions() {
        let flagged = found(concat!(
            "import dataclasses\n",
            "from pydantic import BaseModel, ConfigDict\n",
            "from typing import Optional, List, Annotated, Union\n",
            "\n",
            "@dataclasses.dataclass\n",
            "class User:\n",
            "    name: str\n",
            "\n",
            "@dataclasses.dataclass\n",
            "class Address:\n",
            "    street: str\n",
            "\n",
            "class WrappedOptional(BaseModel):\n",
            "    user: Optional[User]\n",
            "class WrappedList(BaseModel):\n",
            "    users: List[User]\n",
            "class WrappedAnnotated(BaseModel):\n",
            "    user: Annotated[User, 'meta']\n",
            "class WrappedUnion(BaseModel):\n",
            "    user: Union[User, None]\n",
            "class WrappedNestedGeneric(BaseModel):\n",
            "    data: dict[str, User]\n",
            "class PEP604Union(BaseModel):\n",
            "    user: User | None\n",
            "class PEP604UnionRightOperand(BaseModel):\n",
            "    user: None | User\n",
            "class MultiField(BaseModel):\n",
            "    user: User\n",
            "    address: Address\n",
        ));
        assert_eq!(flagged.len(), 8);
        // `MultiField` carries one secondary per dataclass-typed field.
        assert_eq!(flagged[7].flows[0].locations.len(), 2);
    }

    #[test]
    fn s8978_accepts_explicit_revalidate_instances() {
        assert!(
            found(concat!(
                "import dataclasses\n",
                "from pydantic import BaseModel, ConfigDict\n",
                "from typing import Optional, List, Annotated, Union\n",
                "\n",
                "@dataclasses.dataclass\n",
                "class User:\n",
                "    name: str\n",
                "\n",
                "@dataclasses.dataclass\n",
                "class Address:\n",
                "    street: str\n",
                "\n",
                "class Compliant(BaseModel):\n",
                "    model_config = ConfigDict(revalidate_instances='always')\n",
                "    user: User\n",
                "class CompliantNonStandardVarName(BaseModel):\n",
                "    my_config = ConfigDict(revalidate_instances='always')\n",
                "    user: User\n",
                "class CompliantNever(BaseModel):\n",
                "    model_config = ConfigDict(revalidate_instances='never')\n",
                "    user: User\n",
                "class CompliantKwargAlways(BaseModel, revalidate_instances='always'):\n",
                "    user: User\n",
                "class CompliantKwargNever(BaseModel, revalidate_instances='never'):\n",
                "    user: User\n",
                "class CompliantDictLiteral(BaseModel):\n",
                "    model_config = {'frozen': True, 'revalidate_instances': 'always'}\n",
                "    user: User\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8978_accepts_inherited_and_aliased_configuration() {
        assert!(
            found(concat!(
                "import dataclasses\n",
                "from pydantic import BaseModel, ConfigDict\n",
                "from typing import Optional, List, Annotated, Union\n",
                "\n",
                "@dataclasses.dataclass\n",
                "class User:\n",
                "    name: str\n",
                "\n",
                "@dataclasses.dataclass\n",
                "class Address:\n",
                "    street: str\n",
                "\n",
                "class BaseWithConfigDictReval(BaseModel):\n",
                "    model_config = ConfigDict(revalidate_instances='always')\n",
                "class ChildOfConfigDictBase(BaseWithConfigDictReval):\n",
                "    user: User\n",
                "class BaseWithKwargReval(BaseModel, revalidate_instances='always'):\n",
                "    pass\n",
                "class ChildOfKwargBase(BaseWithKwargReval):\n",
                "    user: User\n",
                "class GrandchildOfConfigDictBase(ChildOfConfigDictBase):\n",
                "    address: Address\n",
                "COMMON_CONFIG = ConfigDict(revalidate_instances='always')\n",
                "class CompliantModuleLevelConfigVar(BaseModel):\n",
                "    model_config = COMMON_CONFIG\n",
                "    user: User\n",
                "ALIAS_A = ConfigDict(revalidate_instances='always')\n",
                "ALIAS_B = ALIAS_A\n",
                "class CompliantChainedAlias(BaseModel):\n",
                "    model_config = ALIAS_B\n",
                "    user: User\n",
                "DICT_CONFIG = {'revalidate_instances': 'always'}\n",
                "class CompliantModuleLevelDictVar(BaseModel):\n",
                "    model_config = DICT_CONFIG\n",
                "    user: User\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8978_flags_configs_without_revalidate_instances() {
        // A `ConfigDict` without the key, a call-produced config, and an
        // ambiguously bound config name all stay unconfigured.
        let flagged = found(concat!(
            "import dataclasses\n",
            "from pydantic import BaseModel, ConfigDict\n",
            "from typing import Optional, List, Annotated, Union\n",
            "\n",
            "@dataclasses.dataclass\n",
            "class User:\n",
            "    name: str\n",
            "\n",
            "@dataclasses.dataclass\n",
            "class Address:\n",
            "    street: str\n",
            "\n",
            "class Baz(BaseModel):\n",
            "    model_config = ConfigDict(frozen=True)\n",
            "    user: User\n",
            "def make_config():\n",
            "    return ConfigDict(revalidate_instances='always')\n",
            "class ModelWithCallRHS(BaseModel):\n",
            "    model_config = make_config()\n",
            "    user: User\n",
            "AMBIGUOUS = ConfigDict(revalidate_instances='always')\n",
            "AMBIGUOUS = ConfigDict(frozen=True)\n",
            "class ModelWithAmbiguousConfig(BaseModel):\n",
            "    model_config = AMBIGUOUS\n",
            "    user: User\n",
            "BAD_CONFIG = ConfigDict(frozen=True)\n",
            "class NoncompliantModuleLevelConfigVar(BaseModel):\n",
            "    model_config = BAD_CONFIG\n",
            "    user: User\n",
        ));
        assert_eq!(flagged.len(), 4);
    }

    #[test]
    fn s8978_accepts_non_dataclass_fields_and_non_models() {
        assert!(
            found(concat!(
                "import dataclasses\n",
                "import pydantic.dataclasses as pydantic_dataclasses\n",
                "from pydantic import BaseModel\n",
                "\n",
                "@dataclasses.dataclass\n",
                "class User:\n",
                "    name: str\n",
                "\n",
                "@pydantic_dataclasses.dataclass\n",
                "class PydanticUser:\n",
                "    name: str\n",
                "\n",
                "class PlainClass:\n",
                "    name: str\n",
                "\n",
                "class WithPydanticDataclass(BaseModel):\n",
                "    user: PydanticUser\n",
                "class WithPlainClass(BaseModel):\n",
                "    obj: PlainClass\n",
                "class NoDataclassField(BaseModel):\n",
                "    name: str\n",
                "class ModelWithUnresolved(BaseModel):\n",
                "    user: UnknownType\n",
                "class ModelWithLiteralAnnotation(BaseModel):\n",
                "    value: 42\n",
                "@dataclasses.dataclass\n",
                "class Container:\n",
                "    user: User\n",
            ))
            .is_empty()
        );
    }
}
