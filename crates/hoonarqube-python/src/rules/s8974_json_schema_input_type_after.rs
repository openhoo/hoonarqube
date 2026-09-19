use ruff_python_ast::{Expr, ExprCall};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{NameResolution, WebFrameworkFacts, flow_location, issue_at};
use hoonarqube_ir::{Issue, IssueFlow};

const RULE_KEY: &str = "python:S8974";
const MESSAGE: &str = "Remove \"json_schema_input_type\" or change the validator mode to \"before\", \"plain\", or \"wrap\".";
const SECONDARY_MESSAGE: &str = "mode is set here.";

/// `field_validator` FQNs the reference's matchers accept: the direct
/// `pydantic.functional_validators.field_validator` definition and the
/// `pydantic.field_validator` package-root re-export (which resolves as
/// an unresolved-import FQN in the reference).
const FIELD_VALIDATOR_FQNS: &[&str] = &[
    "pydantic.functional_validators.field_validator",
    "pydantic.field_validator",
];

/// python:S8974 — `json_schema_input_type` describes the raw input type a
/// field validator's schema should expect, but with `mode='after'` (the
/// default when `mode` is omitted) the validator runs after Pydantic's
/// own conversion, so the combination always raises `PydanticUserError`
/// at class definition time. The reference flags the
/// `json_schema_input_type` keyword of a `field_validator(...)` decorator
/// call when `mode` is absent or the literal `'after'`, with the `mode`
/// value as a secondary location. `mode='before'`/`'plain'`/`'wrap'`,
/// non-literal `mode` values, decorators without `json_schema_input_type`,
/// bare `@field_validator`, and same-named local functions stay silent.
pub(crate) fn check_s8974_json_schema_input_type_after(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    // The reference subscribes to decorators only: a `field_validator(...)`
    // call outside decorator position is not inspected.
    let decorators = file_ctx
        .functions
        .iter()
        .flat_map(|function| function.decorator_list.iter())
        .chain(
            file_ctx
                .classes
                .iter()
                .flat_map(|class| class.decorator_list.iter()),
        );
    for decorator in decorators {
        let Expr::Call(call) = &decorator.expression else {
            continue;
        };
        if !callee_fqn(&call.func, &facts)
            .is_some_and(|fqn| FIELD_VALIDATOR_FQNS.contains(&fqn.as_str()))
        {
            continue;
        }
        check_decorator_call(call, index, source, &mut issues);
    }
    issues
}

/// The FQN of a decorator callee: a name resolves to the latest binding
/// preceding the use (so a later same-named `def` shadows the import only
/// for uses after it), and an attribute chain appends its tail.
fn callee_fqn(expr: &Expr, facts: &WebFrameworkFacts) -> Option<String> {
    match expr {
        Expr::Name(name) => match facts.resolve_name_before(name.id.as_str(), name.range()) {
            NameResolution::Import(fqn) => Some(fqn),
            _ => None,
        },
        Expr::Attribute(attribute) => {
            let base = callee_fqn(&attribute.value, facts)?;
            Some(format!("{}.{}", base, attribute.attr.as_str()))
        }
        _ => None,
    }
}
fn check_decorator_call(call: &ExprCall, index: &LineIndex, source: &str, issues: &mut Vec<Issue>) {
    let Some(json_schema) = keyword_by_name(call, "json_schema_input_type") else {
        return;
    };
    let mode = keyword_by_name(call, "mode");
    if !is_after_mode_or_default(mode) {
        return;
    }
    // The reference anchors on the keyword's `Name`, not the whole
    // `name=value` argument.
    let Some(anchor) = json_schema.arg.as_ref() else {
        return;
    };
    let mut issue = issue_at(RULE_KEY, MESSAGE, anchor.range(), index, source);
    if let Some(mode) = mode {
        issue.flows.push(IssueFlow {
            locations: vec![flow_location(
                SECONDARY_MESSAGE,
                mode.value.range(),
                index,
                source,
            )],
        });
    }
    issues.push(issue);
}

/// The keyword argument `name` of `call` (`**kwargs` unpackings carry no
/// name and never match), mirroring `TreeUtils.argumentByKeyword`.
fn keyword_by_name<'a>(call: &'a ExprCall, name: &str) -> Option<&'a ruff_python_ast::Keyword> {
    call.arguments
        .keywords
        .iter()
        .find(|keyword| keyword.arg.as_ref().is_some_and(|arg| arg.as_str() == name))
}

/// Whether `mode` is absent (the validator defaults to `'after'`) or the
/// literal `'after'`; any other value — including non-literal
/// expressions — stays silent.
fn is_after_mode_or_default(mode: Option<&ruff_python_ast::Keyword>) -> bool {
    match mode {
        None => true,
        Some(mode) => matches!(
            &mode.value,
            Expr::StringLiteral(literal) if literal.value.to_str() == "after"
        ),
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8974")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8974_flags_the_sonar_noncompliant_examples() {
        let flagged = found(concat!(
            "from pydantic import BaseModel, field_validator\n",
            "\n",
            "class ModelAfterMode(BaseModel):\n",
            "    a: str\n",
            "    @field_validator('a', mode='after', json_schema_input_type=str)\n",
            "    @classmethod\n",
            "    def validate_a(cls, v):\n",
            "        return v\n",
            "\n",
            "class ModelDefaultMode(BaseModel):\n",
            "    a: str\n",
            "    @field_validator('a', json_schema_input_type=str)\n",
            "    @classmethod\n",
            "    def validate_a_default(cls, v):\n",
            "        return v\n",
            "\n",
            "class ModelModeAfterExplicit(BaseModel):\n",
            "    a: str\n",
            "    @field_validator('a', json_schema_input_type=int, mode='after')\n",
            "    @classmethod\n",
            "    def validate_a2(cls, v):\n",
            "        return v\n",
        ));
        assert_eq!(flagged.len(), 3);
        // The issue anchors on the `json_schema_input_type` keyword name
        // (line 5, columns 40-62); the `mode` value `'after'` is the
        // secondary location (columns 31-38).
        assert_eq!(flagged[0].range.start, pos(5, 40));
        assert_eq!(flagged[0].range.end, pos(5, 62));
        assert_eq!(flagged[0].flows[0].locations.len(), 1);
        assert_eq!(flagged[0].flows[0].locations[0].range.start, pos(5, 31));
        assert_eq!(flagged[0].flows[0].locations[0].range.end, pos(5, 38));
        assert!(flagged[1].flows.is_empty());
    }

    #[test]
    fn s8974_accepts_other_modes_and_missing_arguments() {
        assert!(
            found(concat!(
                "from pydantic import BaseModel, field_validator\n",
                "\n",
                "class M(BaseModel):\n",
                "    a: str\n",
                "    @field_validator('a', mode='before', json_schema_input_type=str)\n",
                "    @classmethod\n",
                "    def v1(cls, v):\n",
                "        return v\n",
                "    @field_validator('a', mode='plain', json_schema_input_type=str)\n",
                "    @classmethod\n",
                "    def v2(cls, v):\n",
                "        return v\n",
                "    @field_validator('a', mode='wrap', json_schema_input_type=str)\n",
                "    @classmethod\n",
                "    def v3(cls, v, handler):\n",
                "        return handler(v)\n",
                "    @field_validator('a', mode='after')\n",
                "    @classmethod\n",
                "    def v4(cls, v):\n",
                "        return v\n",
                "    @field_validator('a')\n",
                "    @classmethod\n",
                "    def v5(cls, v):\n",
                "        return v\n",
                "    VALIDATOR_MODE = 'after'\n",
                "    @field_validator('a', mode=VALIDATOR_MODE, json_schema_input_type=str)\n",
                "    @classmethod\n",
                "    def v6(cls, v):\n",
                "        return v\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8974_flags_direct_and_aliased_imports() {
        let flagged = found(concat!(
            "from pydantic import BaseModel\n",
            "from pydantic.functional_validators import field_validator as fv_direct\n",
            "from pydantic import field_validator as fv_alias\n",
            "\n",
            "class M1(BaseModel):\n",
            "    a: str\n",
            "    @fv_direct('a', mode='after', json_schema_input_type=str)\n",
            "    @classmethod\n",
            "    def v1(cls, v):\n",
            "        return v\n",
            "\n",
            "class M2(BaseModel):\n",
            "    a: str\n",
            "    @fv_alias('a', json_schema_input_type=str)\n",
            "    @classmethod\n",
            "    def v2(cls, v):\n",
            "        return v\n",
        ));
        assert_eq!(flagged.len(), 2);
    }

    #[test]
    fn s8974_accepts_a_local_field_validator() {
        // A same-named local function is not `pydantic.field_validator`.
        assert!(
            found(concat!(
                "def field_validator(*fields, **kwargs):\n",
                "    pass\n",
                "\n",
                "@field_validator('a', mode='after', json_schema_input_type=str)\n",
                "def validate_local(cls, v):\n",
                "    return v\n",
            ))
            .is_empty()
        );
    }
}
