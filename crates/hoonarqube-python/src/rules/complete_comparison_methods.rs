use std::collections::BTreeMap;

use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt, StmtClassDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::child_bodies;
use crate::support::dotted_segments;
use crate::support::flow_location;
use crate::support::issue_at;

const RULE_KEY: &str = "python:S8500";
const MESSAGE: &str = "Add the missing comparison methods or use \"functools.total_ordering\".";
const ORDERING_METHODS: [&str; 4] = ["__lt__", "__le__", "__gt__", "__ge__"];

/// python:S8500 — a class defining some but not all of `__lt__`,
/// `__le__`, `__gt__`, `__ge__` without `functools.total_ordering` leaves
/// Python unable to infer the missing orderings. The finding anchors on
/// the class name; each defined ordering method is a secondary location.
pub(crate) fn check_complete_comparison_methods(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let _ = parsed;
    let total_ordering_names = total_ordering_bindings(file_ctx);
    let mut issues = Vec::new();
    for class in &file_ctx.classes {
        check_class(class, &total_ordering_names, index, source, &mut issues);
    }
    issues
}

fn check_class(
    class: &StmtClassDef,
    total_ordering_names: &[String],
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let mut definitions: BTreeMap<&str, TextRange> = BTreeMap::new();
    collect_ordering_definitions(&class.body, &mut definitions);
    if definitions.is_empty() || definitions.len() == ORDERING_METHODS.len() {
        return;
    }
    if class
        .decorator_list
        .iter()
        .any(|decorator| is_total_ordering(&decorator.expression, total_ordering_names))
    {
        return;
    }
    let mut issue = issue_at(RULE_KEY, MESSAGE, class.name.range(), index, source);
    issue = issue.with_flow(
        definitions
            .iter()
            .map(|(name, range)| {
                flow_location(
                    &format!("\"{name}\" is defined here."),
                    *range,
                    index,
                    source,
                )
            })
            .collect(),
    );
    issues.push(issue);
}

/// First-definition ranges of ordering methods anywhere in the class
/// body except inside nested `def`/`class` scopes. Both `def __lt__` and
/// `__lt__ = ...`/`__lt__: T = ...` count, matching the reference.
fn collect_ordering_definitions<'a>(
    stmts: &'a [Stmt],
    definitions: &mut BTreeMap<&'a str, TextRange>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(function) => {
                let name = function.name.as_str();
                if ORDERING_METHODS.contains(&name) {
                    definitions
                        .entry(name)
                        .or_insert_with(|| function.name.range());
                }
            }
            Stmt::ClassDef(_) => {}
            Stmt::Assign(assign) => {
                if let [Expr::Name(target)] = assign.targets.as_slice()
                    && ORDERING_METHODS.contains(&target.id.as_str())
                {
                    definitions
                        .entry(target.id.as_str())
                        .or_insert_with(|| target.range());
                }
                for body in child_bodies(stmt) {
                    collect_ordering_definitions(body, definitions);
                }
            }
            Stmt::AnnAssign(assign) => {
                if assign.value.is_some()
                    && let Expr::Name(target) = assign.target.as_ref()
                    && ORDERING_METHODS.contains(&target.id.as_str())
                {
                    definitions
                        .entry(target.id.as_str())
                        .or_insert_with(|| target.range());
                }
                for body in child_bodies(stmt) {
                    collect_ordering_definitions(body, definitions);
                }
            }
            _ => {
                for body in child_bodies(stmt) {
                    collect_ordering_definitions(body, definitions);
                }
            }
        }
    }
}

/// Whether the decorator resolves to `functools.total_ordering`: the
/// qualified path, a `from functools import total_ordering [as x]`
/// binding, or a `functools` module alias (`import functools as f`).
fn is_total_ordering(expression: &Expr, bound_names: &[String]) -> bool {
    let Some(segments) = dotted_segments(expression) else {
        return false;
    };
    if segments == ["functools", "total_ordering"] {
        return true;
    }
    bound_names
        .iter()
        .any(|name| name.split('.').eq(segments.iter().copied()))
}

/// Local names bound to `functools.total_ordering` by from-imports, plus
/// module aliases for `functools` (`import functools as f` binds `f` so
/// `f.total_ordering` resolves).
fn total_ordering_bindings(file_ctx: &FileContext) -> Vec<String> {
    let mut names = Vec::new();
    for import in &file_ctx.imports {
        match import {
            AnyImport::From(import) if import.level == 0 => {
                let module = import.module.as_ref().map_or("", |m| m.as_str());
                if module != "functools" {
                    continue;
                }
                for alias in &import.names {
                    if matches!(alias.name.as_str(), "total_ordering" | "*") {
                        names.push(
                            alias
                                .asname
                                .as_ref()
                                .map_or("total_ordering", |a| a.as_str())
                                .to_string(),
                        );
                    }
                }
            }
            AnyImport::Plain(import) => {
                for alias in &import.names {
                    if alias.name.as_str() == "functools" {
                        names.push(format!(
                            "{}.total_ordering",
                            alias.asname.as_ref().map_or("functools", |a| a.as_str())
                        ));
                    }
                }
            }
            AnyImport::From(_) => {}
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s8500_flags_partial_ordering_on_sonar_example() {
        // The reference Noncompliant example, verbatim.
        let flagged = scan(concat!(
            "class Person:\n",
            "    def __init__(self, name, age):\n",
            "        self.name = name\n",
            "        self.age = age\n",
            "\n",
            "    def __lt__(self, other):\n",
            "        return self.age < other.age\n",
        ));
        let found = findings(&flagged, "python:S8500");
        assert_eq!(found.len(), 1);
        // The anchor covers the class name.
        assert_eq!(found[0].range.start, pos(1, 6));
        assert_eq!(found[0].range.end, pos(1, 12));
        assert_eq!(
            found[0].message,
            "Add the missing comparison methods or use \"functools.total_ordering\"."
        );
    }

    #[test]
    fn s8500_accepts_total_ordering_on_sonar_example() {
        // The reference Compliant solution, verbatim.
        let clean = scan(concat!(
            "from functools import total_ordering\n",
            "\n",
            "@total_ordering\n",
            "class Person:\n",
            "    def __init__(self, name, age):\n",
            "        self.name = name\n",
            "        self.age = age\n",
            "\n",
            "    def __eq__(self, other):\n",
            "        return self.age == other.age\n",
            "\n",
            "    def __lt__(self, other):\n",
            "        return self.age < other.age\n",
        ));
        assert!(findings(&clean, "python:S8500").is_empty());
    }

    #[test]
    fn s8500_accepts_all_four_ordering_methods() {
        // The second reference Compliant solution, verbatim.
        let clean = scan(concat!(
            "class Point:\n",
            "    def __init__(self, x, y):\n",
            "        self.x = x\n",
            "        self.y = y\n",
            "\n",
            "    def __lt__(self, other):\n",
            "        return self.x < other.x\n",
            "\n",
            "    def __le__(self, other):\n",
            "        return self.x <= other.x\n",
            "\n",
            "    def __gt__(self, other):\n",
            "        return self.x > other.x\n",
            "\n",
            "    def __ge__(self, other):\n",
            "        return self.x >= other.x\n",
        ));
        assert!(findings(&clean, "python:S8500").is_empty());
    }

    #[test]
    fn s8500_accepts_qualified_and_aliased_total_ordering() {
        let clean = scan(concat!(
            "import functools\n",
            "import functools as f\n",
            "from functools import total_ordering as ordering\n",
            "\n",
            "@functools.total_ordering\n",
            "class A:\n",
            "    def __lt__(self, other):\n",
            "        return True\n",
            "\n",
            "@f.total_ordering\n",
            "class B:\n",
            "    def __le__(self, other):\n",
            "        return True\n",
            "\n",
            "@ordering\n",
            "class C:\n",
            "    def __gt__(self, other):\n",
            "        return True\n",
        ));
        assert!(findings(&clean, "python:S8500").is_empty());
    }

    #[test]
    fn s8500_accepts_classes_without_ordering_methods() {
        let clean = scan(concat!(
            "class Plain:\n",
            "    def __eq__(self, other):\n",
            "        return True\n",
            "\n",
            "    def __ne__(self, other):\n",
            "        return not self.__eq__(other)\n",
        ));
        assert!(findings(&clean, "python:S8500").is_empty());
    }

    #[test]
    fn s8500_counts_assigned_and_conditional_definitions() {
        // `__lt__ = ...` and a conditional `def __le__` both count, so
        // this class still lacks `__gt__`/`__ge__` and flags once.
        let flagged = scan(concat!(
            "import sys\n",
            "\n",
            "class Mixed:\n",
            "    __lt__ = lambda self, other: True\n",
            "    if sys.version_info > (3,):\n",
            "        def __le__(self, other):\n",
            "            return True\n",
        ));
        assert_eq!(findings(&flagged, "python:S8500").len(), 1);
    }

    #[test]
    fn s8500_ignores_nested_class_and_function_definitions() {
        // Ordering methods of a nested class or nested function do not
        // count toward the outer class — but the nested class is checked
        // on its own definitions and flags for `Inner`.
        let flagged = scan(concat!(
            "class Outer:\n",
            "    class Inner:\n",
            "        def __lt__(self, other):\n",
            "            return True\n",
            "\n",
            "    def helper(self):\n",
            "        def __le__(self, other):\n",
            "            return True\n",
        ));
        let found = findings(&flagged, "python:S8500");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start, pos(2, 10));
        assert_eq!(found[0].range.end, pos(2, 15));
    }
}
