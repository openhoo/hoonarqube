use std::path::PathBuf;

use hoonarqube_ir::Issue;

use crate::{AnalyzerOptions, analyze};

fn tags(source: &str) -> Vec<Issue> {
    analyze(
        PathBuf::from("control.rb"),
        source,
        &AnalyzerOptions::default(),
    )
    .issues
    .into_iter()
    .filter(|issue| matches!(issue.rule_key.as_str(), "ruby:S1134" | "ruby:S1135"))
    .collect()
}

fn identity(issue: &Issue) -> (&str, u32, u32, u32, u32) {
    (
        &issue.rule_key,
        issue.range.start.line,
        issue.range.start.column,
        issue.range.end.line,
        issue.range.end.column,
    )
}

#[test]
fn comment_tags_report_first_match_per_real_comment_with_exact_messages_and_spans() {
    let findings = tags("# TODO TODO FIXME FIXME\nvalue = 1 # TODO\n");
    assert_eq!(
        findings.iter().map(identity).collect::<Vec<_>>(),
        vec![
            ("ruby:S1135", 1, 2, 1, 6),
            ("ruby:S1134", 1, 12, 1, 17),
            ("ruby:S1135", 2, 12, 2, 16),
        ]
    );
    assert_eq!(
        findings[0].message,
        "Complete the task associated to this TODO comment."
    );
    assert_eq!(
        findings[1].message,
        "Take the required action to fix the issue indicated by this \"FIXME\" comment."
    );
    for issue in findings {
        assert!(issue.fix.is_none());
        assert!(issue.alternatives.is_empty());
        assert!(issue.flows.is_empty());
    }
}

#[test]
fn comment_tags_follow_reference_ascii_case_and_unicode_letter_digit_boundaries() {
    for source in [
        "# todo fixme\n",
        "# ToDo FiXmE\n",
        "# _TODO_ _FIXME_\n",
        "# (TODO) [FIXME]\n",
        "# ١TODO١ ٢FIXME٢\n",
        "# \u{301}TODO\u{301} \u{301}FIXME\u{301}\n",
    ] {
        assert_eq!(tags(source).len(), 2, "{source:?}");
    }
    for source in [
        "# xTODO xFIXME\n",
        "# TODOx FIXMEx\n",
        "# 1TODO 2FIXME\n",
        "# TODO1 FIXME2\n",
        "# éTODO πFIXME\n",
        "# TODOé FIXMEπ\n",
        "# ordinary task description\n",
    ] {
        assert!(tags(source).is_empty(), "{source:?}");
    }
}

#[test]
fn comment_tags_preserve_embedded_document_crlf_and_code_point_ranges() {
    let findings = tags("=begin\nfirst line\nTODO TODO\nFIXME FIXME\n=end\nvalue = 1\n");
    assert_eq!(
        findings.iter().map(identity).collect::<Vec<_>>(),
        vec![("ruby:S1135", 3, 0, 3, 4), ("ruby:S1134", 4, 0, 4, 5)]
    );
    let findings = tags("value = \"é\" # TODO FIXME\r\n");
    assert_eq!(
        findings.iter().map(identity).collect::<Vec<_>>(),
        vec![("ruby:S1135", 1, 14, 1, 18), ("ruby:S1134", 1, 19, 1, 24)]
    );
    let findings = tags("# 🦉TODO 🦉FIXME\n");
    assert_eq!(
        findings.iter().map(identity).collect::<Vec<_>>(),
        vec![("ruby:S1135", 1, 3, 1, 7), ("ruby:S1134", 1, 9, 1, 14)]
    );
}

#[test]
fn comment_tags_ignore_literals_heredoc_end_data_and_malformed_sources() {
    for source in [
        "a = \"# TODO FIXME\"\nb = '# TODO FIXME'\nc = %q{# TODO FIXME}\nd = /# TODO FIXME/\n",
        "value = <<~TEXT\n# TODO FIXME\nTEXT\n",
        "value = 1\n__END__\n# TODO FIXME\n",
        "=begin\nxTODO\nxFIXME\n=end\nvalue = 1\n",
        "def broken(\n# TODO FIXME\n",
    ] {
        assert!(tags(source).is_empty(), "{source:?}");
    }
}
