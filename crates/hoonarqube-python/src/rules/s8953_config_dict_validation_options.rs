use ruff_python_ast::{Expr, Keyword, ModModule};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{ImportFqns, NameResolver, NameValue, flow_location, issue_at};
use hoonarqube_ir::{Issue, IssueFlow};

const RULE_KEY: &str = "python:S8953";
const MESSAGE: &str = "Enable at least one of \"validate_by_alias\" or \"validate_by_name\".";
const SECONDARY_MESSAGE: &str = "Also set to \"False\" here.";

/// python:S8953 — a `pydantic.ConfigDict` that disables both
/// `validate_by_alias` and `validate_by_name` leaves the model no way to
/// accept input and raises `PydanticUserError` at class definition time.
/// When both keywords carry a falsy value, the `validate_by_name` argument
/// anchors the finding and the `validate_by_alias` argument is the
/// secondary location. Falsy mirrors the reference's `Expressions.isFalsy`:
/// `False`, `None`, empty strings, the zero literals `0`/`0.0`/`0j`, empty
/// `[]`/`()`/`{}` literals, and names bound exactly once to one of those.
/// Missing keywords, truthy values, and non-`ConfigDict` calls stay silent.
pub(crate) fn check_s8953_config_dict_validation_options(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let fqns = ImportFqns::build(file_ctx);
    let resolver = NameResolver::build(parsed, source);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        check_call(call, &fqns, &resolver, index, source, &mut issues);
    }
    issues
}

fn check_call(
    call: &ruff_python_ast::ExprCall,
    fqns: &ImportFqns,
    resolver: &NameResolver,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if !fqns.is_fqn(&call.func, "pydantic.ConfigDict") {
        return;
    }
    let (Some(by_alias), Some(by_name)) = (
        keyword_argument(&call.arguments.keywords, "validate_by_alias"),
        keyword_argument(&call.arguments.keywords, "validate_by_name"),
    ) else {
        return;
    };
    if !is_falsy(&by_alias.value, resolver, source) || !is_falsy(&by_name.value, resolver, source) {
        return;
    }
    let mut issue = issue_at(RULE_KEY, MESSAGE, by_name.range(), index, source);
    issue.flows.push(IssueFlow {
        locations: vec![flow_location(
            SECONDARY_MESSAGE,
            by_alias.range(),
            index,
            source,
        )],
    });
    issues.push(issue);
}

/// The keyword argument named `name` (`**kwargs` unpackings carry no name
/// and never match), mirroring `TreeUtils.argumentByKeyword`.
fn keyword_argument<'a>(keywords: &'a [Keyword], name: &str) -> Option<&'a Keyword> {
    keywords
        .iter()
        .find(|keyword| keyword.arg.as_ref().is_some_and(|arg| arg.as_str() == name))
}

/// The reference's `Expressions.isFalsy`: literal falsy shapes, and a
/// `Name` resolves through its single assigned value (one hop, matching
/// the reference's non-recursive `isFalsyInternal` on the resolved
/// expression).
fn is_falsy(expr: &Expr, resolver: &NameResolver, source: &str) -> bool {
    if let Expr::Name(_) = expr
        && let NameValue::Single(value) = resolver.resolve(expr)
    {
        return is_falsy_literal(value, source);
    }
    is_falsy_literal(expr, source)
}

/// Literal falsy shapes: `False`, `None`, the empty string, the zero
/// literals `0`/`0.0`/`0j` (the reference compares the literal's source
/// text), and empty `[]`/`()`/`{}` literals.
fn is_falsy_literal(expr: &Expr, source: &str) -> bool {
    match expr {
        Expr::BooleanLiteral(boolean) => !boolean.value,
        Expr::NoneLiteral(_) => true,
        Expr::StringLiteral(string) => string.value.to_str().is_empty(),
        Expr::NumberLiteral(_) => matches!(&source[expr.range()], "0" | "0.0" | "0j"),
        Expr::List(list) => list.elts.is_empty(),
        Expr::Tuple(tuple) => tuple.elts.is_empty(),
        Expr::Dict(dict) => dict.items.is_empty(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8953")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8953_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: the `validate_by_name=False`
        // argument anchors the finding (line 6, columns 8-30) and the
        // `validate_by_alias=False` argument is the secondary location.
        let flagged = found(concat!(
            "from pydantic import BaseModel, ConfigDict, Field\n",
            "\n",
            "class Model(BaseModel):\n",
            "    model_config = ConfigDict(\n",
            "        validate_by_alias=False,\n",
            "        validate_by_name=False\n",
            "    )\n",
            "    my_field: str = Field(alias='my_alias')\n",
        ));
        assert_eq!(flagged.len(), 1);
        let issue = &flagged[0];
        assert_eq!(
            issue.message,
            "Enable at least one of \"validate_by_alias\" or \"validate_by_name\"."
        );
        assert_eq!(issue.range.start, pos(6, 8));
        assert_eq!(issue.range.end, pos(6, 30));
        assert_eq!(issue.flows.len(), 1);
        let locations = &issue.flows[0].locations;
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].message, "Also set to \"False\" here.");
        assert_eq!(locations[0].range.start, pos(5, 8));
        assert_eq!(locations[0].range.end, pos(5, 31));
    }

    #[test]
    fn s8953_accepts_the_sonar_compliant_example() {
        assert!(
            found(concat!(
                "from pydantic import BaseModel, ConfigDict, Field\n",
                "\n",
                "class Model(BaseModel):\n",
                "    model_config = ConfigDict(\n",
                "        validate_by_alias=False,\n",
                "        validate_by_name=True\n",
                "    )\n",
                "    my_field: str = Field(alias='my_alias')\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8953_flags_other_falsy_shapes_and_single_assigned_names() {
        // `None`, `0`, `""`, `[]`, `()`, `{}` are falsy too; a name bound
        // once to `False` resolves through its assignment.
        let flagged = found(concat!(
            "from pydantic import ConfigDict\n",
            "\n",
            "OFF = False\n",
            "\n",
            "a = ConfigDict(validate_by_alias=None, validate_by_name=0)\n",
            "b = ConfigDict(validate_by_alias=\"\", validate_by_name=[])\n",
            "c = ConfigDict(validate_by_alias=OFF, validate_by_name=False)\n",
        ));
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start, pos(5, 39));
        assert_eq!(flagged[1].range.start, pos(6, 37));
        assert_eq!(flagged[2].range.start, pos(7, 38));
    }

    #[test]
    fn s8953_accepts_missing_keywords_truthy_values_and_other_calls() {
        // One option enabled, one option absent, truthy values, ambiguous
        // names, and non-ConfigDict calls all stay silent.
        assert!(
            found(concat!(
                "from pydantic import ConfigDict\n",
                "\n",
                "OFF = False\n",
                "OFF = True\n",
                "\n",
                "a = ConfigDict(validate_by_alias=False, validate_by_name=True)\n",
                "b = ConfigDict(validate_by_alias=False)\n",
                "c = ConfigDict(validate_by_name=False)\n",
                "d = ConfigDict(validate_by_alias=0.0, validate_by_name=1)\n",
                "e = ConfigDict(validate_by_alias=OFF, validate_by_name=False)\n",
                "f = dict(validate_by_alias=False, validate_by_name=False)\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8953_resolves_qualified_and_aliased_config_dict() {
        // `import pydantic` / `import pydantic as pd` / `from pydantic
        // import ConfigDict as CD` all resolve to `pydantic.ConfigDict`.
        let flagged = found(concat!(
            "import pydantic\n",
            "import pydantic as pd\n",
            "from pydantic import ConfigDict as CD\n",
            "\n",
            "a = pydantic.ConfigDict(validate_by_alias=False, validate_by_name=False)\n",
            "b = pd.ConfigDict(validate_by_alias=False, validate_by_name=False)\n",
            "c = CD(validate_by_alias=False, validate_by_name=False)\n",
        ));
        assert_eq!(flagged.len(), 3);
    }
}
