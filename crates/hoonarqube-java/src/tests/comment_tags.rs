use crate::{AnalyzerOptions, analyze};
use hoonarqube_ir::{Issue, Pos, Range};
use std::path::PathBuf;

// Source files and expectations come from the independently compiled 23-file
// SonarQube 26.9 / Java 8.41 reference, including duplicate same-line trivia.
type CommentCase = (
    &'static str,
    &'static str,
    &'static [(&'static str, u32, u32)],
);
const CASES: &[CommentCase] = &[
    (
        "AsciiCase.java",
        include_str!("../../tests/fixtures/comment_tags/AsciiCase.java"),
        &[("java:S1134", 1, 13), ("java:S1135", 1, 13)],
    ),
    (
        "AstralLetters.java",
        include_str!("../../tests/fixtures/comment_tags/AstralLetters.java"),
        &[("java:S1134", 1, 17), ("java:S1135", 1, 17)],
    ),
    (
        "BlockLines.java",
        include_str!("../../tests/fixtures/comment_tags/BlockLines.java"),
        &[
            ("java:S1135", 1, 7),
            ("java:S1134", 2, 13),
            ("java:S1135", 2, 13),
            ("java:S1134", 3, 8),
        ],
    ),
    (
        "BmpLetters.java",
        include_str!("../../tests/fixtures/comment_tags/BmpLetters.java"),
        &[],
    ),
    (
        "BothTags.java",
        include_str!("../../tests/fixtures/comment_tags/BothTags.java"),
        &[("java:S1134", 1, 24), ("java:S1135", 1, 24)],
    ),
    (
        "Clean.java",
        include_str!("../../tests/fixtures/comment_tags/Clean.java"),
        &[],
    ),
    (
        "CombiningMarks.java",
        include_str!("../../tests/fixtures/comment_tags/CombiningMarks.java"),
        &[("java:S1135", 1, 17), ("java:S1134", 1, 17)],
    ),
    (
        "CrLf.java",
        include_str!("../../tests/fixtures/comment_tags/CrLf.java"),
        &[
            ("java:S1135", 1, 7),
            ("java:S1134", 2, 8),
            ("java:S1135", 3, 7),
        ],
    ),
    (
        "CrOnly.java",
        include_str!("../../tests/fixtures/comment_tags/CrOnly.java"),
        &[("java:S1135", 1, 7), ("java:S1134", 2, 8)],
    ),
    (
        "Digits.java",
        include_str!("../../tests/fixtures/comment_tags/Digits.java"),
        &[("java:S1134", 1, 17), ("java:S1135", 1, 17)],
    ),
    (
        "EscapedBoundary.java",
        include_str!("../../tests/fixtures/comment_tags/EscapedBoundary.java"),
        &[("java:S1134", 1, 25), ("java:S1135", 1, 25)],
    ),
    (
        "EscapedTag.java",
        include_str!("../../tests/fixtures/comment_tags/EscapedTag.java"),
        &[],
    ),
    (
        "EscapedTrivia.java",
        include_str!("../../tests/fixtures/comment_tags/EscapedTrivia.java"),
        &[],
    ),
    (
        "FirstEmbedded.java",
        include_str!("../../tests/fixtures/comment_tags/FirstEmbedded.java"),
        &[],
    ),
    (
        "Javadoc.java",
        include_str!("../../tests/fixtures/comment_tags/Javadoc.java"),
        &[("java:S1135", 1, 8), ("java:S1134", 2, 8)],
    ),
    (
        "Letters.java",
        include_str!("../../tests/fixtures/comment_tags/Letters.java"),
        &[],
    ),
    (
        "Literals.java",
        include_str!("../../tests/fixtures/comment_tags/Literals.java"),
        &[],
    ),
    (
        "MultipleTrivia.java",
        include_str!("../../tests/fixtures/comment_tags/MultipleTrivia.java"),
        &[
            ("java:S1134", 1, 30),
            ("java:S1135", 1, 30),
            ("java:S1135", 1, 30),
        ],
    ),
    (
        "SimpleFixme.java",
        include_str!("../../tests/fixtures/comment_tags/SimpleFixme.java"),
        &[("java:S1134", 1, 15)],
    ),
    (
        "SimpleTodo.java",
        include_str!("../../tests/fixtures/comment_tags/SimpleTodo.java"),
        &[("java:S1135", 1, 14)],
    ),
    (
        "Trailing.java",
        include_str!("../../tests/fixtures/comment_tags/Trailing.java"),
        &[("java:S1134", 1, 38), ("java:S1135", 1, 38)],
    ),
    (
        "TurkishCase.java",
        include_str!("../../tests/fixtures/comment_tags/TurkishCase.java"),
        &[("java:S1134", 1, 14)],
    ),
    (
        "Underscore.java",
        include_str!("../../tests/fixtures/comment_tags/Underscore.java"),
        &[("java:S1134", 1, 17), ("java:S1135", 1, 17)],
    ),
];

fn targets(name: &str, source: &str) -> Vec<Issue> {
    analyze(PathBuf::from(name), source, &AnalyzerOptions::default())
        .issues
        .into_iter()
        .filter(|issue| matches!(issue.rule_key.as_str(), "java:S1134" | "java:S1135"))
        .collect()
}

#[test]
fn java_comment_tags_match_reference_messages_per_trivia_and_line() {
    for (name, source, expected) in CASES.iter().filter(|(_, _, rows)| !rows.is_empty()) {
        let actual = targets(name, source);
        assert_eq!(actual.len(), expected.len(), "{name}");
        for issue in actual {
            let message = match issue.rule_key.as_str() {
                "java:S1134" => {
                    "Take the required action to fix the issue indicated by this comment."
                }
                "java:S1135" => "Complete the task associated to this TODO comment.",
                _ => unreachable!(),
            };
            assert_eq!(issue.message, message, "{name}");
            assert!(issue.fix.is_none());
            assert!(issue.flows.is_empty());
            assert!(issue.alternatives.is_empty());
        }
    }
}

#[test]
fn java_comment_tags_match_full_line_ranges_and_duplicate_multiplicity() {
    for (name, source, expected) in CASES.iter().filter(|(_, _, rows)| !rows.is_empty()) {
        let mut actual: Vec<_> = targets(name, source)
            .into_iter()
            .map(|issue| (issue.rule_key, issue.range))
            .collect();
        let mut expected: Vec<_> = expected
            .iter()
            .map(|(key, line, end)| {
                (
                    (*key).to_owned(),
                    Range {
                        start: Pos {
                            line: *line,
                            column: 0,
                        },
                        end: Pos {
                            line: *line,
                            column: *end,
                        },
                    },
                )
            })
            .collect();
        actual.sort_by_key(|(key, range)| (key.clone(), range.start.line, range.end.column));
        expected.sort_by_key(|(key, range)| (key.clone(), range.start.line, range.end.column));
        assert_eq!(actual, expected, "{name}");
    }
}

#[test]
fn java_comment_tags_keep_first_embedded_occurrence_literals_and_escaped_tags_clean() {
    let mut clean = 0;
    for (name, source, _) in CASES.iter().filter(|(_, _, rows)| rows.is_empty()) {
        assert!(targets(name, source).is_empty(), "{name}");
        clean += 1;
    }
    assert_eq!(clean, 7);
}

#[test]
fn java_comment_tags_fail_closed_on_malformed_roots() {
    assert!(targets("Broken.java", "class Broken { void broken( // TODO FIXME\n").is_empty());
}
