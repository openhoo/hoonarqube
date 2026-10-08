use crate::engine::calls::concrete_hint;
use crate::engine::calls::hint_accepts_literal;
use crate::engine::file_context::FileContext;
use crate::engine::project_context::{
    GraphqlResolver, PythonProjectContext, build_current_module_facts,
};
use crate::support::expr_normalized_text;
use crate::support::issue_at;
use crate::support::to_range;
use crate::support::typed_literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5890 — assigned values should match their annotations -----------

/// python:S5890 — flags `x: T = <literal>` assignments whose literal kind
/// provably contradicts the simple concrete annotation `T`.
pub(crate) fn check_s5890_annotated_assignment_kinds(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    module_name: &str,
    project: &PythonProjectContext,
) -> Vec<Issue> {
    let module = build_current_module_facts(module_name, file_ctx.parsed, project);
    let resolver = GraphqlResolver::new(&module, project);
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::AnnAssign(assign) = stmt else {
            continue;
        };
        let Some(value) = assign.value.as_deref() else {
            continue;
        };
        let Some(kind) = typed_literal_kind(value) else {
            continue;
        };
        let hint = concrete_hint(&assign.annotation);
        if kind == "none"
            && (hint.is_some() || resolver.known_non_optional_class(&assign.annotation))
        {
            let annotation_text = expr_normalized_text(&assign.annotation, source);
            let mut issue = issue_at(
                "python:S5890",
                &format!(
                    "Replace the type hint \"{annotation_text}\" with \"Optional[{annotation_text}]\" or don't assign \"None\" to this expression"
                ),
                value.range(),
                index,
                source,
            );
            issue
                .flows
                .push(annotation_flow(&assign.annotation, index, source));
            issues.push(issue);
            continue;
        }
        let Some(hint) = hint else {
            continue;
        };
        if hint_accepts_literal(hint, kind) {
            continue;
        }
        let annotation_text = expr_normalized_text(&assign.annotation, source);
        let target_text = expr_normalized_text(&assign.target, source);
        let actual_type = match kind {
            "string" => "str",
            "boolean" => "bool",
            "none" => "None",
            other => other,
        };
        let mut issue = issue_at(
            "python:S5890",
            &format!(
                "Assign to \"{target_text}\" a value of type \"{annotation_text}\" instead of \"{actual_type}\" or update its type hint."
            ),
            value.range(),
            index,
            source,
        );
        issue
            .flows
            .push(annotation_flow(&assign.annotation, index, source));
        issues.push(issue);
    }
    issues
}

fn annotation_flow(
    annotation: &ruff_python_ast::Expr,
    index: &LineIndex,
    source: &str,
) -> hoonarqube_ir::IssueFlow {
    hoonarqube_ir::IssueFlow {
        locations: vec![hoonarqube_ir::FlowLocation::in_primary_file(
            "",
            to_range(annotation.range(), index, source),
        )],
    }
}

#[cfg(test)]
mod tests {
    use crate::PythonProjectContext;
    use crate::test_support::{findings, scan, scan_in_project};
    use std::path::PathBuf;

    #[test]
    fn none_requires_optional_for_resolved_nominal_fields() {
        let mut project = PythonProjectContext::new();
        project.add_module("pkg.map", "class Map: pass\n");
        let report = scan_in_project(
            &project,
            PathBuf::from("pkg/rules.py"),
            concat!(
                "from .map import Map\n",
                "class Rule:\n",
                "    def __init__(self):\n",
                "        self.map: Map = None  # type: ignore\n",
            ),
        );
        let issues = findings(&report, "python:S5890");
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].message,
            "Replace the type hint \"Map\" with \"Optional[Map]\" or don't assign \"None\" to this expression"
        );
        assert_eq!(issues[0].range.start.line, 4);
        assert_eq!(issues[0].range.start.column, 24);
        assert_eq!(issues[0].range.end.column, 28);
        assert_eq!(issues[0].flows.len(), 1);
        let hint = &issues[0].flows[0].locations[0];
        assert!(hint.message.is_empty());
        assert_eq!(hint.range.start.line, 4);
        assert_eq!(hint.range.end.line, 4);
        assert_eq!(hint.range.start.column, 18);
        assert_eq!(hint.range.end.column, 21);
    }

    #[test]
    fn optional_unknown_and_rebound_annotations_stay_clean() {
        let report = scan(concat!(
            "from typing import Optional, Any, Union\n",
            "class Map: pass\n",
            "a: Optional[Map] = None\n",
            "b: Map | None = None\n",
            "c: Union[Map, None] = None\n",
            "d: object = None\n",
            "e: Any = None\n",
            "f: Unknown = None\n",
            "def f(Map):\n    value: Map = None\n",
        ));
        assert!(findings(&report, "python:S5890").is_empty());
    }
}
