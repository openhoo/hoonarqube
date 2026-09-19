use std::collections::BTreeMap;

use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::engine::file_context::FileContext;
use crate::support::flow_location;
use crate::support::issue_at;
use crate::support::to_u32;

const RULE_KEY: &str = "python:S8512";
const SECONDARY_MESSAGE: &str = "Reassignment.";

/// python:S8512 — a class field assigned twice at class-body level keeps
/// only the last value; every earlier assignment is dead code. The
/// finding anchors on each superseded name and points at the line of the
/// next assignment, which is the secondary location.
pub(crate) fn check_no_duplicate_class_fields(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let _ = parsed;
    let mut issues = Vec::new();
    for class in &file_ctx.classes {
        check_class(class, index, source, &mut issues);
    }
    issues
}

fn check_class(
    class: &ruff_python_ast::StmtClassDef,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    // Only unconditional top-level class-body statements count: a plain
    // `name = value` or an annotated `name: T = value`. Tuple targets,
    // multi-target assignments, bare annotations, and definitions inside
    // control flow or nested scopes are not field redefinitions.
    let mut definitions: BTreeMap<&str, Vec<TextRange>> = BTreeMap::new();
    for stmt in &class.body {
        let name = match stmt {
            Stmt::Assign(assign) => match assign.targets.as_slice() {
                [Expr::Name(target)] => Some(target),
                _ => None,
            },
            Stmt::AnnAssign(assign) if assign.value.is_some() => match assign.target.as_ref() {
                Expr::Name(target) => Some(target),
                _ => None,
            },
            _ => None,
        };
        if let Some(target) = name {
            definitions
                .entry(target.id.as_str())
                .or_default()
                .push(target.range());
        }
    }
    for (name, ranges) in &definitions {
        for (position, range) in ranges.iter().enumerate().take(ranges.len() - 1) {
            let next = ranges[position + 1];
            let next_line = to_u32(index.line_column(next.start(), source).line.get());
            let mut issue = issue_at(
                RULE_KEY,
                &format!(
                    "Remove this assignment; \"{name}\" is assigned again on line {next_line}."
                ),
                *range,
                index,
                source,
            );
            issue = issue.with_flow(vec![flow_location(SECONDARY_MESSAGE, next, index, source)]);
            issues.push(issue);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s8512_flags_duplicate_field_on_sonar_example() {
        // The reference Noncompliant example, verbatim.
        let flagged = scan(concat!(
            "class MyClass:\n",
            "    x = 1\n",
            "    y = 2\n",
            "    x = 3\n",
        ));
        let found = findings(&flagged, "python:S8512");
        assert_eq!(found.len(), 1);
        // The anchor covers the first `x` target.
        assert_eq!(found[0].range.start, pos(2, 4));
        assert_eq!(found[0].range.end, pos(2, 5));
        assert_eq!(
            found[0].message,
            "Remove this assignment; \"x\" is assigned again on line 4."
        );
    }

    #[test]
    fn s8512_accepts_single_definitions_on_sonar_example() {
        // The reference Compliant solution, verbatim.
        let clean = scan(concat!("class MyClass:\n", "    x = 3\n", "    y = 2\n",));
        assert!(findings(&clean, "python:S8512").is_empty());
    }

    #[test]
    fn s8512_flags_each_superseded_assignment() {
        // Three definitions of `x` flag the first two; annotated
        // assignments with values count too.
        let flagged = scan(concat!(
            "class Config:\n",
            "    x = 1\n",
            "    x: int = 2\n",
            "    x = 3\n",
        ));
        let found = findings(&flagged, "python:S8512");
        assert_eq!(found.len(), 2);
        assert_eq!(
            found[0].message,
            "Remove this assignment; \"x\" is assigned again on line 3."
        );
        assert_eq!(
            found[1].message,
            "Remove this assignment; \"x\" is assigned again on line 4."
        );
    }

    #[test]
    fn s8512_ignores_conditional_and_nested_definitions() {
        // Assignments inside `if` blocks, methods, and nested classes do
        // not count as unconditional field definitions.
        let clean = scan(concat!(
            "import sys\n",
            "\n",
            "class Config:\n",
            "    x = 1\n",
            "    if sys.platform == \"win32\":\n",
            "        x = 2\n",
            "    def method(self):\n",
            "        x = 3\n",
            "    class Inner:\n",
            "        x = 4\n",
        ));
        assert!(findings(&clean, "python:S8512").is_empty());
    }

    #[test]
    fn s8512_ignores_non_name_and_bare_annotation_targets() {
        // Tuple targets, multi-target assignments, attribute targets,
        // and bare `x: int` annotations are not field definitions.
        let clean = scan(concat!(
            "class Config:\n",
            "    x, y = 1, 2\n",
            "    a = b = 3\n",
            "    x: int\n",
            "    obj.attr = 4\n",
        ));
        assert!(findings(&clean, "python:S8512").is_empty());
    }
}
