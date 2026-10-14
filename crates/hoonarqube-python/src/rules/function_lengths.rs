use crate::AnalyzerOptions;
use crate::support::for_each_function_def;
use crate::support::issue_at;
use crate::support::to_u32;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::token::TokenKind;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S138 — body code-token lines against `maximumFunctionLength`.
pub(crate) fn check_function_lengths(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_function_def(
        parsed.syntax().body.as_slice(),
        false,
        &mut |function, is_method| {
            // The reference counts distinct lines holding code tokens inside
            // the body (comments and blank lines carry no tokens) and
            // subtracts the lines spanned by the docstring.
            let body_range = ruff_text_size::TextRange::new(
                function
                    .body
                    .first()
                    .map_or_else(|| function.range().start(), ruff_text_size::Ranged::start),
                function
                    .body
                    .last()
                    .map_or_else(|| function.range().end(), ruff_text_size::Ranged::end),
            );
            let mut code_lines = std::collections::HashSet::new();
            for token in parsed.tokens() {
                if token.kind().is_trivia()
                    || matches!(
                        token.kind(),
                        TokenKind::Newline | TokenKind::Indent | TokenKind::Dedent
                    )
                    || !body_range.contains_range(token.range())
                {
                    continue;
                }
                let first = index.line_column(token.range().start(), source).line.get();
                let last = index.line_column(token.range().end(), source).line.get();
                for line in first..=last {
                    code_lines.insert(line);
                }
            }
            if let Some(ruff_python_ast::Stmt::Expr(doc)) = function.body.first()
                && matches!(doc.value.as_ref(), ruff_python_ast::Expr::StringLiteral(_))
            {
                let first = index.line_column(doc.range().start(), source).line.get();
                let last = index.line_column(doc.range().end(), source).line.get();
                for line in first..=last {
                    code_lines.remove(&line);
                }
            }
            let lines = to_u32(code_lines.len());
            let maximum = options.maximum_function_length;
            if lines > maximum {
                let kind = if is_method { "method" } else { "function" };
                issues.push(issue_at(
                    "python:S138",
                    &format!(
                        "This {kind} \"{}\" has {lines} lines of code, which is greater than \
                         the {maximum} authorized. Split it into smaller {kind}s.",
                        function.name
                    ),
                    function.name.range(),
                    index,
                    source,
                ));
            }
        },
    );
    issues
}

#[cfg(test)]
mod s138_code_line_count_tests {
    use super::*;
    use crate::test_support::{issue, scan_with_options};

    fn findings(source: &str, maximum: u32) -> Vec<Issue> {
        let options = AnalyzerOptions {
            maximum_function_length: maximum,
            ..AnalyzerOptions::default()
        };
        scan_with_options(source, &options)
            .issues
            .into_iter()
            .filter(|issue| issue.rule_key == "python:S138")
            .collect()
    }

    fn expected(name: &str, kind: &str, lines: u32, maximum: u32, line: u32, col: u32) -> Issue {
        issue(
            "python:S138",
            &format!(
                "This {kind} \"{name}\" has {lines} lines of code, which is greater than \
                 the {maximum} authorized. Split it into smaller {kind}s."
            ),
            (line, col),
            (line, col + u32::try_from(name.len()).expect("name length")),
        )
    }

    fn function_with_lines(count: u32) -> String {
        let mut source = String::from("def work():\n");
        for number in 0..count {
            source.push_str(&format!("    consume({number})\n\n    # comment\n"));
        }
        source
    }

    #[test]
    fn logical_newline_endpoints_do_not_count_blank_or_comment_lines() {
        let source = "def work():\n    first()\n\n    # comment after a logical newline\n    second()\n    # another comment\n    third()\n";
        assert_eq!(
            findings(source, 2),
            vec![expected("work", "function", 3, 2, 1, 4)]
        );
        assert!(findings(source, 3).is_empty());
    }

    #[test]
    fn default_budget_accepts_100_code_lines_and_reports_exactly_101() {
        assert!(findings(&function_with_lines(100), 100).is_empty());
        assert_eq!(
            findings(&function_with_lines(101), 100),
            vec![expected("work", "function", 101, 100, 1, 4)]
        );
    }

    #[test]
    fn only_the_own_docstring_is_subtracted_from_code_lines() {
        let source = "def work():\n    \"\"\"Documentation.\n\n    # documentation text\n    \"\"\"\n    first()\n\n    # ordinary comment\n    second()\n";
        assert!(findings(source, 2).is_empty());
        assert_eq!(
            findings(source, 1),
            vec![expected("work", "function", 2, 1, 1, 4)]
        );
    }

    #[test]
    fn multiline_non_docstring_literals_keep_their_physical_token_lines() {
        let source = "def work():\n    value = \"\"\"first\n\n# literal text\nlast\"\"\"\n    return value\n";
        assert_eq!(
            findings(source, 4),
            vec![expected("work", "function", 5, 4, 1, 4)]
        );
        assert!(findings(source, 5).is_empty());
    }

    #[test]
    fn class_body_definitions_use_method_wording() {
        let source = "class Worker:\n    def work(self):\n        first()\n\n        # comment\n        second()\n        third()\n";
        assert_eq!(
            findings(source, 2),
            vec![expected("work", "method", 3, 2, 2, 8)]
        );
    }

    #[test]
    fn functions_nested_inside_methods_keep_function_wording() {
        let source = "class Worker:\n    def outer(self):\n        def inner():\n            first()\n            second()\n            third()\n        return inner\n";
        assert_eq!(
            findings(source, 2),
            vec![
                expected("outer", "method", 5, 2, 2, 8),
                expected("inner", "function", 3, 2, 3, 12),
            ]
        );
    }
}
