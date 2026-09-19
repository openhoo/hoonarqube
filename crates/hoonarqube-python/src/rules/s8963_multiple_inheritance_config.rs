use std::collections::HashSet;

use ruff_python_ast::{ModModule, StmtClassDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{
    ClassIndex, ConfigDefiner, ImportFqns, defines_model_config_locally, flow_location, issue_at,
};
use hoonarqube_ir::{Issue, IssueFlow};

const RULE_KEY: &str = "python:S8963";
const MESSAGE: &str =
    "Refactor this Pydantic model to avoid multiple inheritance with conflicting configurations.";
const SECONDARY_MESSAGE: &str = "This base class defines \"model_config\".";

/// python:S8963 — Pydantic does not follow the C3 MRO when merging
/// `model_config` from multiple bases, so a model inheriting from two or
/// more bases that each carry a `model_config` definition (their own or an
/// ancestor's) resolves its configuration unpredictably. The class name
/// anchors the finding; every base contributing a previously unseen
/// `model_config` definer is a secondary location. A model that defines
/// its own `model_config` makes the resolution explicit and stays silent,
/// as do single-inheritance models, models whose extra bases carry no
/// config, and bases that only re-inherit an already-seen config (a
/// diamond shares one definer, so it is not a conflict).
pub(crate) fn check_s8963_multiple_inheritance_config(
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
    if !classes.is_pydantic_model(class, fqns) || defines_model_config_locally(class) {
        return;
    }
    let Some(arguments) = &class.arguments else {
        return;
    };
    if arguments.args.len() < 2 {
        return;
    }
    // A base "contributes" when its MRO introduces at least one
    // `model_config` definer no earlier base already carried — the
    // reference's union-of-definers accumulation, which keeps diamonds and
    // repeated bases silent.
    let mut seen: HashSet<ConfigDefiner> = HashSet::new();
    let mut contributing = Vec::new();
    for base in &arguments.args {
        let definers = classes.model_config_definers(base, fqns);
        // Insert every definer before judging: a base contributes when its
        // MRO introduces at least one definer no earlier base carried.
        let mut added_new = false;
        for definer in definers {
            added_new |= seen.insert(definer);
        }
        if added_new {
            contributing.push(base.range());
        }
    }
    if contributing.len() < 2 {
        return;
    }
    let mut issue = issue_at(RULE_KEY, MESSAGE, class.name.range(), index, source);
    issue.flows.push(IssueFlow {
        locations: contributing
            .iter()
            .map(|range| flow_location(SECONDARY_MESSAGE, *range, index, source))
            .collect(),
    });
    issues.push(issue);
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8963")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8963_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: two bases each defining
        // `model_config`; the class name anchors (line 9, columns 6-11)
        // and both bases are secondary locations.
        let flagged = found(concat!(
            "from pydantic import BaseModel, ConfigDict\n",
            "\n",
            "class Base1(BaseModel):\n",
            "    model_config = ConfigDict(str_to_lower=True)\n",
            "\n",
            "class Base2(BaseModel):\n",
            "    model_config = ConfigDict(str_to_upper=True)\n",
            "\n",
            "class Model(Base1, Base2):\n",
            "    x: str\n",
        ));
        assert_eq!(flagged.len(), 1);
        let issue = &flagged[0];
        assert_eq!(
            issue.message,
            "Refactor this Pydantic model to avoid multiple inheritance with conflicting configurations."
        );
        assert_eq!(issue.range.start, pos(9, 6));
        assert_eq!(issue.range.end, pos(9, 11));
        assert_eq!(issue.flows.len(), 1);
        let locations = &issue.flows[0].locations;
        assert_eq!(locations.len(), 2);
        assert_eq!(
            locations[0].message,
            "This base class defines \"model_config\"."
        );
        assert_eq!(locations[0].range.start, pos(9, 12));
        assert_eq!(locations[0].range.end, pos(9, 17));
        assert_eq!(locations[1].range.start, pos(9, 19));
        assert_eq!(locations[1].range.end, pos(9, 24));
    }

    #[test]
    fn s8963_accepts_the_sonar_compliant_example() {
        assert!(
            found(concat!(
                "from pydantic import BaseModel, ConfigDict\n",
                "\n",
                "class Base1(BaseModel):\n",
                "    model_config = ConfigDict(str_to_lower=True)\n",
                "\n",
                "class Model(Base1):\n",
                "    model_config = ConfigDict(str_to_lower=True)\n",
                "    x: str\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8963_flags_configs_inherited_through_intermediate_bases() {
        // Sonar's second Noncompliant example: `Intermediate` carries
        // `Base1`'s config through the MRO, so `Model(Intermediate, Base2)`
        // conflicts even though both configs are identical.
        let flagged = found(concat!(
            "from pydantic import BaseModel, ConfigDict\n",
            "\n",
            "class Base1(BaseModel):\n",
            "    model_config = ConfigDict(frozen=True)\n",
            "\n",
            "class Base2(BaseModel):\n",
            "    model_config = ConfigDict(frozen=True)\n",
            "\n",
            "class Intermediate(Base1):\n",
            "    pass\n",
            "\n",
            "class Model(Intermediate, Base2):\n",
            "    x: str\n",
        ));
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start, pos(12, 6));
        assert_eq!(flagged[0].flows[0].locations.len(), 2);
    }

    #[test]
    fn s8963_accepts_own_config_configless_mixins_and_diamonds() {
        // A model defining its own `model_config` is explicit; a mixin
        // without config contributes nothing; a diamond shares one definer.
        assert!(
            found(concat!(
                "from pydantic import BaseModel, ConfigDict\n",
                "\n",
                "class Base1(BaseModel):\n",
                "    model_config = ConfigDict(frozen=True)\n",
                "\n",
                "class Base2(BaseModel):\n",
                "    model_config = ConfigDict(frozen=True)\n",
                "\n",
                "class Mixin:\n",
                "    pass\n",
                "\n",
                "class OwnConfig(Base1, Base2):\n",
                "    model_config = ConfigDict(frozen=True)\n",
                "\n",
                "class WithMixin(Base1, Mixin):\n",
                "    x: str\n",
                "\n",
                "class Diamond(Base1, Base1):\n",
                "    x: str\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8963_ignores_non_model_multiple_inheritance() {
        // Multiple inheritance between plain classes is out of scope.
        assert!(
            found(concat!(
                "class Base1:\n",
                "    model_config = dict(frozen=True)\n",
                "\n",
                "class Base2:\n",
                "    model_config = dict(frozen=True)\n",
                "\n",
                "class Model(Base1, Base2):\n",
                "    x: str\n",
            ))
            .is_empty()
        );
    }
}
