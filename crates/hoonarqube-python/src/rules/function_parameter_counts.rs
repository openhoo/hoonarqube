use crate::AnalyzerOptions;
use crate::support::for_each_function_def;
use crate::support::issue_at;
use crate::support::to_u32;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S107 — parameter count against `maximumFunctionParameters`;
/// `*args` and `**kwargs` each count as one parameter.
pub(crate) fn check_function_parameter_counts(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_function_def(
        parsed.syntax().body.as_slice(),
        false,
        &mut |function, in_class_body| {
            let parameters = &function.parameters;
            let mut count = parameters.posonlyargs.len()
                + parameters.args.len()
                + parameters.kwonlyargs.len()
                + usize::from(parameters.vararg.is_some())
                + usize::from(parameters.kwarg.is_some());
            // The receiver is implicitly passed, so methods (except
            // staticmethods) count one parameter fewer.
            let is_method =
                in_class_body && !crate::support::has_decorator(function, "staticmethod");
            if is_method {
                count = count.saturating_sub(1);
            }
            let maximum = options.maximum_function_parameters;
            if to_u32(count) > maximum {
                let kind = if is_method { "Method" } else { "Function" };
                issues.push(issue_at(
                    "python:S107",
                    &format!(
                        "{kind} \"{}\" has {count} parameters, which is greater than the \
                         {maximum} authorized.",
                        function.name
                    ),
                    parameter_list_range(parsed, &function.parameters),
                    index,
                    source,
                ));
            }
        },
    );
    issues
}

fn parameter_list_range(
    parsed: &Parsed<ModModule>,
    parameters: &ruff_python_ast::Parameters,
) -> ruff_text_size::TextRange {
    let first = parameters
        .iter_source_order()
        .next()
        .expect("nonempty parameters");
    let last = parameters
        .iter_source_order()
        .last()
        .expect("nonempty parameters");
    // Ruff omits the bare keyword-only separator from formal parameters;
    // the reference parameter-list node includes it as its first child.
    let start = if parameters.posonlyargs.is_empty()
        && parameters.args.is_empty()
        && parameters.vararg.is_none()
        && !parameters.kwonlyargs.is_empty()
    {
        parsed
            .tokens()
            .iter()
            .find(|token| {
                token.kind() == ruff_python_ast::token::TokenKind::Star
                    && token.start() >= parameters.start()
                    && token.end() <= first.start()
            })
            .map_or(first.start(), Ranged::start)
    } else {
        first.start()
    };
    // The reference parameter-list node retains a trailing comma, while
    // ignoring trivia between it and the closing parenthesis.
    let end = parsed
        .tokens()
        .iter()
        .find(|token| {
            token.kind() == ruff_python_ast::token::TokenKind::Comma
                && token.start() >= last.end()
                && token.end() < parameters.end()
        })
        .map_or(last.end(), Ranged::end);
    ruff_text_size::TextRange::new(start, end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hoonarqube_ir::{Pos, Range};

    fn findings(source: &str, maximum: u32) -> Vec<Issue> {
        let parsed = crate::support::parse(source);
        let index = LineIndex::from_source_text(source);
        let options = AnalyzerOptions {
            maximum_function_parameters: maximum,
            ..AnalyzerOptions::default()
        };
        check_function_parameter_counts(&parsed, &index, source, &options)
    }

    fn expected(start: (u32, u32), end: (u32, u32)) -> Issue {
        Issue {
            rule_key: "python:S107".into(),
            message:
                "Function \"wide\" has 14 parameters, which is greater than the 13 authorized."
                    .into(),
            range: Range {
                start: Pos {
                    line: start.0,
                    column: start.1,
                },
                end: Pos {
                    line: end.0,
                    column: end.1,
                },
            },
            fix: None,
            flows: Vec::new(),
            alternatives: Vec::new(),
        }
    }

    #[test]
    fn s107_leading_marker_inline_matches_reference_tree_range() {
        let source = "def wide(*, a, b, c, d, e, f, g, h, i, j, k, l, m, n):\n    pass\n";
        assert_eq!(findings(source, 13), vec![expected((1, 9), (1, 52))]);
    }

    #[test]
    fn s107_leading_marker_multiline_matches_reference_tree_range() {
        let source = "def wide(\n    *,\n    a: int = 1,\n    b: int = 2,\n    c: int = 3,\n    d: int = 4,\n    e: int = 5,\n    f: int = 6,\n    g: int = 7,\n    h: int = 8,\n    i: int = 9,\n    j: int = 10,\n    k: int = 11,\n    l: int = 12,\n    m: int = 13,\n    n: int = 14,\n):\n    pass\n";
        assert_eq!(findings(source, 13), vec![expected((2, 4), (16, 16))]);
    }

    #[test]
    fn s107_leading_marker_decorated_async_matches_reference_tree_range() {
        let source = "@decorator\nasync def wide(\n    *,\n    a: int = 1,\n    b: int = 2,\n    c: int = 3,\n    d: int = 4,\n    e: int = 5,\n    f: int = 6,\n    g: int = 7,\n    h: int = 8,\n    i: int = 9,\n    j: int = 10,\n    k: int = 11,\n    l: int = 12,\n    m: int = 13,\n    n: int = 14,\n):\n    pass\n";
        assert_eq!(findings(source, 13), vec![expected((3, 4), (17, 16))]);
    }

    #[test]
    fn s107_leading_marker_trivia_matches_reference_tree_range() {
        let source = "def wide(\n    # * comment\n    *, # marker\n    a: str = \"*\",\n    b: str = \"*\",\n    c: str = \"*\",\n    d: str = \"*\",\n    e: str = \"*\",\n    f: str = \"*\",\n    g: str = \"*\",\n    h: str = \"*\",\n    i: str = \"*\",\n    j: str = \"*\",\n    k: str = \"*\",\n    l: str = \"*\",\n    m: str = \"*\",\n    n: str = \"*\",\n):\n    pass\n";
        assert_eq!(findings(source, 13), vec![expected((3, 4), (17, 17))]);
    }

    #[test]
    fn s107_leading_marker_no_trailing_comma_matches_reference_tree_range() {
        let source = "def wide(\n    *,\n    a: int = 1,\n    b: int = 2,\n    c: int = 3,\n    d: int = 4,\n    e: int = 5,\n    f: int = 6,\n    g: int = 7,\n    h: int = 8,\n    i: int = 9,\n    j: int = 10,\n    k: int = 11,\n    l: int = 12,\n    m: int = 13,\n    n: int = 14\n):\n    pass\n";
        assert_eq!(findings(source, 13), vec![expected((2, 4), (16, 15))]);
    }

    #[test]
    fn s107_bare_marker_does_not_count_toward_budget() {
        for source in ["def f(*, a, b):\n    pass\n", "def f():\n    pass\n"] {
            assert!(findings(source, 2).is_empty());
        }
        let over = findings("def f(*, a, b, c):\n    pass\n", 2);
        assert_eq!(over.len(), 1);
        assert_eq!(
            over[0].message,
            "Function \"f\" has 3 parameters, which is greater than the 2 authorized."
        );
    }

    #[test]
    fn s107_ordinary_trailing_comma_and_formal_counts_are_preserved() {
        let source = "def f(\n    a: int,\n    b: str = 'fallback',\n):\n    pass\n";
        let ordinary = findings(source, 1);
        assert_eq!(ordinary.len(), 1);
        assert_eq!(ordinary[0].range.start, Pos { line: 2, column: 4 });
        assert_eq!(
            ordinary[0].range.end,
            Pos {
                line: 3,
                column: 24
            }
        );
        for (source, count) in [
            ("def f(a, /, b, *, c):\n    pass\n", 3),
            ("def f(*args, a, **kwargs):\n    pass\n", 3),
            ("class C:\n    def f(self, a, b):\n        pass\n", 2),
            (
                "class C:\n    @classmethod\n    def f(cls, a, b):\n        pass\n",
                2,
            ),
            (
                "class C:\n    @staticmethod\n    def f(a, b):\n        pass\n",
                2,
            ),
        ] {
            assert!(findings(source, count).is_empty());
            assert_eq!(findings(source, count - 1).len(), 1);
        }
    }
}
