use crate::cst::issue;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;

/// csharpsquid:S1451 — required file header. An empty `header_format`
/// disables the check; regular-expression headers are not evaluated because
/// this analyzer carries no regex engine.
pub(crate) fn check(source: &str, language: CsLanguage, options: &AnalyzerOptions) -> Vec<Issue> {
    if options.header_format.is_empty() || options.header_is_regular_expression {
        return Vec::new();
    }
    if matches_literal_header(source, &options.header_format) {
        return Vec::new();
    }
    vec![issue(
        language,
        "S1451",
        "Add or update the header of this file.",
        hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line: 1, column: 0 },
            end: hoonarqube_ir::Pos { line: 1, column: 0 },
        },
    )]
}

fn matches_literal_header(source: &str, header: &str) -> bool {
    if header.ends_with('\n') {
        let without_terminator = header
            .strip_suffix('\n')
            .and_then(|value| value.strip_suffix('\r').or(Some(value)))
            .unwrap_or(header);
        return source.starts_with(header) || source == without_terminator;
    }
    source.strip_prefix(header).is_some_and(|remainder| {
        remainder.is_empty() || remainder.starts_with('\n') || remainder.starts_with("\r\n")
    })
}

#[cfg(test)]
mod tests {
    use crate::AnalyzerOptions;
    use crate::tests::{analyze_options, with_key};

    #[test]
    fn s1451_does_not_accept_a_longer_prefix_as_the_header() {
        let options = AnalyzerOptions {
            header_format: "// Copyright\n".to_owned(),
            ..AnalyzerOptions::default()
        };
        let report = analyze_options("// Copyright infringement\nclass C {}\n", &options);
        assert_eq!(with_key(&report, "csharpsquid:S1451").len(), 1);

        let header_only = analyze_options("// Copyright", &options);
        assert!(with_key(&header_only, "csharpsquid:S1451").is_empty());

        let no_newline_option = AnalyzerOptions {
            header_format: "// Copyright".to_owned(),
            ..AnalyzerOptions::default()
        };
        let longer = analyze_options(
            "// Copyright infringement\nclass C {}\n",
            &no_newline_option,
        );
        assert_eq!(with_key(&longer, "csharpsquid:S1451").len(), 1);
    }
}
