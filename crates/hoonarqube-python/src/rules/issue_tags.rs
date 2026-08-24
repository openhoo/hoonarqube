use crate::support::FIXME_TAG;
use crate::support::TODO_TAG;
use crate::support::comment_tokens;
use crate::support::has_person_reference;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S1134/S1135/S1707 — track FIXME/TODO comments and require a person
/// reference matching `[ ]*\([ _a-zA-Z0-9@.]+\)` right after the tag.
pub(crate) fn check_issue_tags(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for comment in comment_tokens(parsed) {
        let text = source[comment.range()].to_lowercase();
        if !text.contains(FIXME_TAG) && !text.contains(TODO_TAG) {
            continue;
        }
        for (key, tag) in [("python:S1134", FIXME_TAG), ("python:S1135", TODO_TAG)] {
            if text.contains(tag) {
                issues.push(Issue {
                    rule_key: key.to_string(),
                    message: format!(
                        "Resolve this {} comment or clarify it with a person reference.",
                        tag.to_uppercase()
                    ),
                    range: to_range(comment.range(), index, source),
                });
            }
        }
        if !has_person_reference(&text) {
            issues.push(Issue {
                rule_key: "python:S1707".to_string(),
                message: "Add a person reference such as '(jane)' to this TODO/FIXME comment."
                    .to_string(),
                range: to_range(comment.range(), index, source),
            });
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::test_support::issue;
    use crate::{AnalyzerOptions, analyze};

    #[test]
    fn todo_and_fixme_tags_are_tracked_with_person_reference() {
        let report = analyze(
            PathBuf::from("t.py"),
            "# FIXME fix later\n# TODO (jane) improve\n",
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            report.issues,
            vec![
                issue(
                    "python:S1134",
                    "Resolve this FIXME comment or clarify it with a person reference.",
                    (1, 0),
                    (1, 17),
                ),
                issue(
                    "python:S1707",
                    "Add a person reference such as '(jane)' to this TODO/FIXME comment.",
                    (1, 0),
                    (1, 17),
                ),
                issue(
                    "python:S1135",
                    "Resolve this TODO comment or clarify it with a person reference.",
                    (2, 0),
                    (2, 21),
                ),
            ]
        );
    }
}
