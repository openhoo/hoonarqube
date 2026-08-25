use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::percent_conversions;
use crate::support::percent_format_parts;
use crate::support::string_value_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;

pub(crate) fn check_percent_argument_types(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Some((format_text, arguments, _, range)) = percent_format_parts(expr) else {
            continue;
        };
        let Some(conversions) = percent_conversions(&format_text) else {
            continue;
        };
        for (conversion, argument) in conversions.iter().zip(arguments) {
            let mismatch = match argument {
                Expr::StringLiteral(literal) => {
                    let numeric = matches!(
                        conversion,
                        b'd' | b'i'
                            | b'u'
                            | b'x'
                            | b'X'
                            | b'o'
                            | b'e'
                            | b'E'
                            | b'f'
                            | b'F'
                            | b'g'
                            | b'G'
                    );
                    let character = *conversion == b'c'
                        && string_value_text(&literal.value).chars().count() != 1;
                    numeric || character
                }
                _ => false,
            };
            if mismatch {
                issues.push(issue_at(
                    "python:S3457",
                    "Use a conversion in this format string that matches the argument types.",
                    range,
                    index,
                    source,
                ));
                break;
            }
        }
    }
    issues
}
