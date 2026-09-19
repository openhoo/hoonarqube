use crate::engine::file_context::FileContext;
use crate::support::AwsLambdaFacts;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::StmtFunctionDef;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

// --- python:S7614 — Lambda handlers must not be async --------------------------

const RULE_KEY: &str = "python:S7614";
const MESSAGE: &str = "Remove the `async` keyword from this AWS Lambda handler definition.";

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Range of the `async` keyword preceding `def` (Sonar anchors the issue on
/// the token, not the whole definition).
fn async_keyword_range(function: &StmtFunctionDef, source: &str) -> Option<TextRange> {
    if !function.is_async {
        return None;
    }
    let start = function.range().start().to_usize();
    let name_start = function.name.range().start().to_usize();
    let window = source.get(start..name_start)?;
    // The `def` keyword is the rightmost standalone word before the name.
    for (index, _) in window.rmatch_indices("def") {
        let bytes = window.as_bytes();
        let left_ok = index == 0 || !is_identifier_byte(bytes[index - 1]);
        let right_ok = index + 3 >= bytes.len() || !is_identifier_byte(bytes[index + 3]);
        if !(left_ok && right_ok) {
            continue;
        }
        let mut async_end = index;
        while async_end > 0 && bytes[async_end - 1].is_ascii_whitespace() {
            async_end -= 1;
        }
        if async_end >= 5
            && &window[async_end - 5..async_end] == "async"
            && (async_end == 5 || !is_identifier_byte(bytes[async_end - 6]))
        {
            let from = TextSize::try_from(start + async_end - 5).ok()?;
            let to = TextSize::try_from(start + async_end).ok()?;
            return Some(TextRange::new(from, to));
        }
        return None;
    }
    None
}

/// python:S7614 — the Lambda runtime invokes a synchronous handler, so an
/// `async def` matching the handler signature (`*_handler`/`*Handler` with
/// `(event, context|ctx)`) fails at runtime. Sonar's `isOnlyLambdaHandler`
/// gates on the signature only, not on the call graph.
pub(crate) fn check_s7614_async_lambda_handler(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let lambda = AwsLambdaFacts::build(file_ctx);
    let mut issues = Vec::new();
    for function in &file_ctx.functions {
        if !function.is_async || !lambda.is_only_lambda_handler(function) {
            continue;
        }
        if let Some(range) = async_keyword_range(function, source) {
            issues.push(issue_at(RULE_KEY, MESSAGE, range, index, source));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, pos, scan};

    const KEY: &str = "python:S7614";

    #[test]
    fn s7614_flags_async_lambda_handler_on_async_keyword() {
        let flagged = scan(concat!(
            "async def async_lambda_handler(event, context):\n",
            "    result = some_logic()\n",
            "    return {\"status\": result}\n",
        ));
        let issues = findings(&flagged, KEY);
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].message,
            "Remove the `async` keyword from this AWS Lambda handler definition."
        );
        assert_eq!(issues[0].range.start, pos(1, 0));
        assert_eq!(issues[0].range.end, pos(1, 5));
    }

    #[test]
    fn s7614_spares_sync_handlers_and_non_handler_async_functions() {
        let quiet = scan(concat!(
            "def lambda_handler(event, context):\n",
            "    return {\"status\": \"ok\"}\n",
            "async def not_a_lambda_entry_point():\n",
            "    pass\n",
            "async def helper(event, context):\n",
            "    pass\n",
            "async def my_handler(event, extra):\n",
            "    pass\n",
        ));
        assert!(findings(&quiet, KEY).is_empty());
    }

    #[test]
    fn s7614_flags_handler_suffix_and_ctx_parameter() {
        let flagged = scan(concat!(
            "async def orderHandler(event, ctx):\n",
            "    pass\n",
        ));
        assert_eq!(findings(&flagged, KEY).len(), 1);
    }
}
