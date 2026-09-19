use crate::engine::file_context::FileContext;
use crate::support::AwsLambdaFacts;
use crate::support::NameResolution;
use crate::support::innermost_function;
use crate::support::issue_at;
use crate::support::nth_argument_or_keyword;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ExprCall;
use ruff_python_ast::StmtFunctionDef;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7620 — Lambda handlers must clean up /tmp files ---------------

const MESSAGE: &str = "Clean up this temporary file before the Lambda function completes.";

pub(crate) fn check_s7620_lambda_tmp_cleanup(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let lambda = AwsLambdaFacts::build(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Some(handler) = innermost_function(file_ctx, call.range()) else {
            continue;
        };
        if !lambda.is_lambda_handler(handler) {
            continue;
        }
        if is_open_call(&lambda, call) && !is_temp_file_cleaned_up(&lambda, file_ctx, call, handler)
        {
            issues.push(issue_at(
                "python:S7620",
                MESSAGE,
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}

/// The `open` builtin: unbound `open` or an explicit `builtins.open` import.
fn is_open_call(lambda: &AwsLambdaFacts<'_>, call: &ExprCall) -> bool {
    match call.func.as_ref() {
        Expr::Name(name) if name.id.as_str() == "open" => matches!(
            lambda.facts.resolve_name("open", call.range()),
            NameResolution::Unbound
        ),
        _ => lambda
            .facts
            .expr_fqn(&call.func)
            .is_some_and(|fqn| fqn == "builtins.open"),
    }
}

fn is_os_remove_or_unlink(lambda: &AwsLambdaFacts<'_>, call: &ExprCall) -> bool {
    lambda
        .facts
        .expr_fqn(&call.func)
        .is_some_and(|fqn| fqn == "os.remove" || fqn == "os.unlink")
}

/// Sonar's `isTempFileCleanedUp`: only a `Name` argument bound to a literal
/// `/tmp/...` path can be noncompliant; literals and unresolvable names are
/// treated as already handled.
fn is_temp_file_cleaned_up(
    lambda: &AwsLambdaFacts<'_>,
    file_ctx: &FileContext,
    call: &ExprCall,
    handler: &StmtFunctionDef,
) -> bool {
    let Some(path_expr) = nth_argument_or_keyword(&call.arguments, 0, "file") else {
        return true;
    };
    let Some(path_value) = string_value_of(lambda, path_expr) else {
        return true;
    };
    if !path_value.starts_with("/tmp/") {
        return true;
    }
    has_cleanup_call(lambda, file_ctx, handler, &path_value)
        || is_path_passed_to_other_function(lambda, file_ctx, path_expr)
}

/// A literal, or a name whose single assignment is a literal.
fn string_value_of(lambda: &AwsLambdaFacts<'_>, expr: &Expr) -> Option<String> {
    if let Some(text) = string_literal_text(expr) {
        return Some(text);
    }
    if let Expr::Name(name) = expr {
        return lambda
            .facts
            .single_assigned_value(name.id.as_str(), expr.range())
            .and_then(string_literal_text);
    }
    None
}

/// Any `os.remove`/`os.unlink` call inside the handler with the same literal
/// path argument counts as cleanup.
fn has_cleanup_call(
    lambda: &AwsLambdaFacts<'_>,
    file_ctx: &FileContext,
    handler: &StmtFunctionDef,
    path: &str,
) -> bool {
    file_ctx.calls.iter().any(|call| {
        handler.range().contains_range(call.range())
            && is_os_remove_or_unlink(lambda, call)
            && nth_argument_or_keyword(&call.arguments, 0, "path")
                .and_then(|argument| string_value_of(lambda, argument))
                .is_some_and(|value| value == path)
    })
}

/// Whether the path name is passed as a direct call argument to anything
/// other than `open`, `os.remove`, or `os.unlink` — the callee may perform
/// the cleanup itself, so the reference stays silent.
fn is_path_passed_to_other_function(
    lambda: &AwsLambdaFacts<'_>,
    file_ctx: &FileContext,
    path_expr: &Expr,
) -> bool {
    let Expr::Name(path_name) = path_expr else {
        return true;
    };
    let NameResolution::Value(bound_value) = lambda
        .facts
        .resolve_name(path_name.id.as_str(), path_expr.range())
    else {
        return true;
    };
    file_ctx.calls.iter().any(|call| {
        if is_os_remove_or_unlink(lambda, call) || is_open_call(lambda, call) {
            return false;
        }
        call.arguments
            .args
            .iter()
            .chain(call.arguments.keywords.iter().map(|keyword| &keyword.value))
            .any(|argument| match argument {
                Expr::Name(usage) => {
                    usage.id.as_str() == path_name.id.as_str()
                        && matches!(
                            lambda.facts.resolve_name(usage.id.as_str(), usage.range()),
                            NameResolution::Value(value)
                                if value.range() == bound_value.range()
                        )
                }
                _ => false,
            })
    })
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S7620";

    #[test]
    fn s7620_flags_uncleaned_tmp_write_in_handler() {
        let source = "def lambda_handler(event, context):\n    file_path = '/tmp/temp_data.txt'\n    with open(file_path, 'w') as f:\n        f.write(\"Something\")\n";
        let report = scan(source);
        let found = findings(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Clean up this temporary file before the Lambda function completes."
        );
    }

    #[test]
    fn s7620_accepts_named_temporary_file() {
        let source = "import tempfile\n\ndef lambda_handler(event, context):\n    with tempfile.NamedTemporaryFile() as f:\n        f.write(\"Something\")\n";
        assert!(findings(&scan(source), KEY).is_empty());
    }

    #[test]
    fn s7620_accepts_explicit_remove() {
        let source = "import os\n\ndef lambda_handler(event, context):\n    file_path = '/tmp/temp_data.txt'\n    try:\n        with open(file_path, 'w') as f:\n            f.write(\"Something\")\n    finally:\n        os.remove(file_path)\n";
        assert!(findings(&scan(source), KEY).is_empty());
    }

    #[test]
    fn s7620_accepts_path_handled_elsewhere() {
        let source = "def lambda_handler(event, context):\n    file_path = '/tmp/temp_data.txt'\n    with open(file_path, 'w') as f:\n        f.write(\"Something\")\n    cleanup(file_path)\n";
        assert!(findings(&scan(source), KEY).is_empty());
    }

    #[test]
    fn s7620_ignores_non_tmp_paths_and_non_handlers() {
        let source = "def lambda_handler(event, context):\n    file_path = '/var/data.txt'\n    with open(file_path, 'w') as f:\n        f.write(\"Something\")\n";
        assert!(findings(&scan(source), KEY).is_empty());
        let other = "def fetch(name):\n    file_path = '/tmp/temp_data.txt'\n    with open(file_path, 'w') as f:\n        f.write(\"Something\")\n";
        assert!(findings(&scan(other), KEY).is_empty());
    }
}
