use crate::support::for_each_annotation;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6542 / S6543 / S6545 / S6546 — hint shapes -------------------------

pub(crate) fn check_any_type_hints(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_annotation(parsed.syntax().body.as_slice(), &mut |annotation| {
        // Sonar's isTypeAny only matches annotations that are exactly
        // `typing.Any` — `list[Any]` nests it inside a generic and stays
        // silent.
        if matches!(annotation, Expr::Name(name) if name.id.as_str() == "Any") {
            issues.push(issue_at(
                "python:S6542",
                "Use a more specific type than `Any` for this type hint.",
                annotation.range(),
                index,
                source,
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, issue, pos, scan};

    #[test]
    fn s6542_existing_bare_annotations_use_reference_message_and_full_ranges() {
        let report = scan(
            "from typing import Any\ndef handler(value: Any) -> Any:\n    local: Any = value\n    return local\n",
        );
        let expected = [
            issue(
                "python:S6542",
                "Use a more specific type than `Any` for this type hint.",
                (2, 19),
                (2, 22),
            ),
            issue(
                "python:S6542",
                "Use a more specific type than `Any` for this type hint.",
                (2, 27),
                (2, 30),
            ),
            issue(
                "python:S6542",
                "Use a more specific type than `Any` for this type hint.",
                (3, 11),
                (3, 14),
            ),
        ];
        assert_eq!(
            findings(&report, "python:S6542"),
            expected.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn s6542_unimported_any_keeps_existing_selection_and_reference_message() {
        // The retained reference does not report unresolved Any. Preserve this
        // native extra while correcting the message of every existing finding.
        let report = scan("def parse(payload: Any) -> int:\n    return 1\n");
        assert_eq!(
            findings(&report, "python:S6542"),
            vec![&issue(
                "python:S6542",
                "Use a more specific type than `Any` for this type hint.",
                (1, 19),
                (1, 22),
            )]
        );
    }

    #[test]
    fn s6542_non_any_and_variadic_annotations_stay_clean() {
        for source in [
            "def parse(payload: bytes) -> int:\n    return 1\n",
            "from typing import Any\ndef handler(*args: Any, **kwargs: Any) -> int:\n    return 1\n",
            "import typing as t\ndef handler(value: t.Any) -> t.Any:\n    return value\n",
            "text = \"Any\"\n",
        ] {
            assert!(findings(&scan(source), "python:S6542").is_empty());
        }
    }

    #[test]
    fn s6542_flags_any_type_hints() {
        let flagged = scan("def f(x: Any) -> int:\n    return 1\n");
        assert_eq!(findings(&flagged, "python:S6542").len(), 1);
    }

    // Issue #621: Sonar's isTypeAny only matches annotations that are
    // exactly `typing.Any`; `Any` nested inside a generic subscription
    // stays silent.
    #[test]
    fn s6542_ignores_any_nested_in_generics() {
        let clean =
            scan("from typing import Any\ndef f(x: list[Any]) -> dict[str, Any]:\n    return {}\n");
        assert!(findings(&clean, "python:S6542").is_empty());
    }

    #[test]
    fn s6542_ignores_any_nested_in_annotated_assignment() {
        let clean = scan("from typing import Any\nitems: list[Any] = []\n");
        assert!(findings(&clean, "python:S6542").is_empty());
    }

    #[test]
    fn s6542_still_flags_bare_any_annotations() {
        let flagged =
            scan("from typing import Any\ndef f(x: Any) -> Any:\n    y: Any = x\n    return y\n");
        let found = findings(&flagged, "python:S6542");
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].range.start, pos(2, 9));
        assert_eq!(found[1].range.start, pos(2, 17));
        assert_eq!(found[2].range.start, pos(3, 7));
    }
}
