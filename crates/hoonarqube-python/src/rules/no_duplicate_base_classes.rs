use std::collections::BTreeMap;

use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::engine::file_context::FileContext;
use crate::support::dotted_segments;
use crate::support::flow_location;
use crate::support::issue_at;

const RULE_KEY: &str = "python:S8509";
const MESSAGE: &str = "Remove this duplicate base class.";
const SECONDARY_MESSAGE: &str = "Already listed here.";

/// python:S8509 — listing the same base class twice in an inheritance
/// list is always a mistake: Python's MRO keeps each class once, so the
/// duplicate is dead syntax. The finding anchors on the first
/// occurrence; later occurrences are secondary locations.
pub(crate) fn check_no_duplicate_base_classes(
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
    let Some(arguments) = &class.arguments else {
        return;
    };
    let mut occurrences: BTreeMap<String, Vec<TextRange>> = BTreeMap::new();
    for base in &arguments.args {
        if let Some(key) = base_key(base) {
            occurrences.entry(key).or_default().push(base.range());
        }
    }
    for ranges in occurrences.values() {
        if ranges.len() < 2 {
            continue;
        }
        let mut issue = issue_at(RULE_KEY, MESSAGE, ranges[0], index, source);
        issue = issue.with_flow(
            ranges[1..]
                .iter()
                .map(|range| flow_location(SECONDARY_MESSAGE, *range, index, source))
                .collect(),
        );
        issues.push(issue);
    }
}

/// Identity key of a base-class expression, approximating the
/// reference's fully-qualified-name comparison: a plain or dotted name
/// keys on its path, a subscript on its head (`Generic[T]` and
/// `Generic[S]` share `Generic`), and a call on its callee. Anything
/// else (literals, unpacking, keywords) has no resolvable identity.
fn base_key(base: &Expr) -> Option<String> {
    match base {
        Expr::Subscript(subscript) => dotted_path(&subscript.value),
        Expr::Call(call) => dotted_path(&call.func),
        _ => dotted_path(base),
    }
}

fn dotted_path(expr: &Expr) -> Option<String> {
    dotted_segments(expr).map(|segments| segments.join("."))
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s8509_flags_duplicate_base_on_sonar_example() {
        // The reference Noncompliant example, verbatim.
        let flagged = scan(concat!(
            "class MyWidget(QWidget, Serializable, QWidget):\n",
            "    pass\n",
        ));
        let found = findings(&flagged, "python:S8509");
        assert_eq!(found.len(), 1);
        // The anchor covers the first `QWidget` occurrence.
        assert_eq!(found[0].range.start, pos(1, 15));
        assert_eq!(found[0].range.end, pos(1, 22));
        assert_eq!(found[0].message, "Remove this duplicate base class.");
    }

    #[test]
    fn s8509_accepts_distinct_bases_on_sonar_example() {
        // The reference Compliant solution, verbatim.
        let clean = scan(concat!(
            "class MyWidget(QWidget, Serializable):\n",
            "    pass\n",
        ));
        assert!(findings(&clean, "python:S8509").is_empty());
    }

    #[test]
    fn s8509_flags_dotted_and_generic_duplicates() {
        // `m.Base` twice and `Generic[T]`/`Generic[S]` share one
        // identity each; `metaclass=` keywords are not bases.
        let flagged = scan(concat!(
            "import typing\n",
            "import module as m\n",
            "\n",
            "class A(m.Base, m.Base):\n",
            "    pass\n",
            "\n",
            "class B(typing.Generic[typing.T], typing.Generic[typing.S]):\n",
            "    pass\n",
            "\n",
            "class C(m.Base, metaclass=m.Base):\n",
            "    pass\n",
        ));
        assert_eq!(findings(&flagged, "python:S8509").len(), 2);
    }

    #[test]
    fn s8509_accepts_distinct_and_unkeyed_bases() {
        let clean = scan(concat!(
            "class A(Base, other.Base):\n",
            "    pass\n",
            "\n",
            "class B(factory(), factory2()):\n",
            "    pass\n",
            "\n",
            "class C(*bases):\n",
            "    pass\n",
        ));
        assert!(findings(&clean, "python:S8509").is_empty());
    }
}
