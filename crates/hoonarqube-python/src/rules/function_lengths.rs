use crate::AnalyzerOptions;
use crate::support::for_each_function_def;
use crate::support::issue_at;
use crate::support::to_u32;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S138 — function line span against `maximumFunctionLength`.
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
        &mut |function, _| {
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
                if token.kind().is_trivia() || !body_range.contains_range(token.range()) {
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
                issues.push(issue_at(
                    "python:S138",
                    &format!(
                        "This function \"{}\" has {lines} lines of code, which is greater than \
                         the {maximum} authorized. Split it into smaller functions.",
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
