use crate::engine::file_context::FileContext;
use crate::support::innermost_function;
use crate::support::issue_at;
use crate::support::string_literal_text;
use crate::support::{AwsLambdaFacts, WebFrameworkFacts};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7617 — reserved Lambda environment variables ---------------------

const RULE_KEY: &str = "python:S7617";
const MESSAGE: &str = "Do not override reserved environment variable names in Lambda functions.";

/// Environment variable names reserved by the AWS Lambda runtime (Sonar's
/// `AWS_RESERVED_ENVIRONMENT_VARIABLES`).
const AWS_RESERVED_ENVIRONMENT_VARIABLES: &[&str] = &[
    "_HANDLER",
    "_X_AMZN_TRACE_ID",
    "AWS_DEFAULT_REGION",
    "AWS_REGION",
    "AWS_EXECUTION_ENV",
    "AWS_LAMBDA_FUNCTION_NAME",
    "AWS_LAMBDA_FUNCTION_MEMORY_SIZE",
    "AWS_LAMBDA_FUNCTION_VERSION",
    "AWS_LAMBDA_INITIALIZATION_TYPE",
    "AWS_LAMBDA_LOG_GROUP_NAME",
    "AWS_LAMBDA_LOG_STREAM_NAME",
    "AWS_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_LAMBDA_RUNTIME_API",
    "LAMBDA_TASK_ROOT",
    "LAMBDA_RUNTIME_DIR",
];

/// The reserved name written through `os.environ[...]`, when the subscript is
/// a string literal or a name singly assigned one (Sonar's
/// `getSubscriptString`).
fn reserved_subscript_name<'a>(
    facts: &WebFrameworkFacts<'a>,
    subscript: &'a Expr,
) -> Option<&'a Expr> {
    match subscript {
        Expr::StringLiteral(_) => Some(subscript),
        Expr::Name(name) => facts
            .strict_single_assignment(name.id.as_str(), name.range())
            .map(|(value, _)| value)
            .filter(|value| matches!(value, Expr::StringLiteral(_))),
        _ => None,
    }
}

/// python:S7617 — assignments to `os.environ[<reserved>]` inside a Lambda
/// handler (or a function transitively called from one) break the runtime's
/// tracing, auth, and execution bookkeeping. Sonar anchors the issue on the
/// whole assignment statement and only inspects the first target list.
pub(crate) fn check_s7617_lambda_reserved_env_vars(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let lambda = AwsLambdaFacts::build(file_ctx);
    if !lambda.has_handler() {
        return Vec::new();
    }
    let facts = &lambda.facts;
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::Assign(assign) = *stmt else {
            continue;
        };
        let Some(function) = innermost_function(file_ctx, stmt.range()) else {
            continue;
        };
        if !lambda.is_lambda_handler(function) {
            continue;
        }
        // Sonar inspects only `lhsExpressions().get(0)` — the first target
        // list — and each of its expressions.
        let Some(first_target) = assign.targets.first() else {
            continue;
        };
        let targets: &[Expr] = match first_target {
            Expr::Tuple(tuple) => &tuple.elts,
            other => std::slice::from_ref(other),
        };
        for target in targets {
            let Expr::Subscript(subscript) = target else {
                continue;
            };
            if facts.expr_fqn(&subscript.value).as_deref() != Some("os.environ") {
                continue;
            }
            let Some(key_expr) = reserved_subscript_name(facts, &subscript.slice) else {
                continue;
            };
            if string_literal_text(key_expr)
                .is_some_and(|text| AWS_RESERVED_ENVIRONMENT_VARIABLES.contains(&text.as_str()))
            {
                issues.push(issue_at(RULE_KEY, MESSAGE, assign.range(), index, source));
                break;
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S7617";

    #[test]
    fn s7617_flags_reserved_names_in_lambda_handlers() {
        let flagged = scan(concat!(
            "import os\n",
            "def lambda_handler(event, context):\n",
            "    os.environ['AWS_REGION'] = \"us-west-2\"\n",
            "    os.environ['_HANDLER'] = \"lambda_function.lambda_handler\"\n",
            "    os.environ['PATH'] = \"/path\"\n",
            "    os.another_array['AWS_REGION'] = \"us-east-1\"\n",
            "    return {\"statusCode\": 200}\n",
        ));
        let issues = findings(&flagged, KEY);
        assert_eq!(issues.len(), 2);
        assert_eq!(
            issues[0].message,
            "Do not override reserved environment variable names in Lambda functions."
        );
    }

    #[test]
    fn s7617_flags_from_import_and_multi_assignment() {
        let flagged = scan(concat!(
            "from os import environ\n",
            "def lambda_handler(event, context):\n",
            "    environ['AWS_REGION'] = \"us-west-2\"\n",
            "    smth, environ['AWS_REGION'] = 1, \"us-west-2\"\n",
        ));
        assert_eq!(findings(&flagged, KEY).len(), 2);
    }

    #[test]
    fn s7617_resolves_singly_assigned_subscript_names() {
        let flagged = scan(concat!(
            "import os\n",
            "def lambda_handler(event, context):\n",
            "    region_str = \"AWS_REGION\"\n",
            "    int_var = 42\n",
            "    os.environ[region_str] = \"us-west-2\"\n",
            "    os.environ[int_var] = \"smth\"\n",
            "    os.environ[42] = \"smth\"\n",
        ));
        assert_eq!(findings(&flagged, KEY).len(), 1);
    }

    #[test]
    fn s7617_flags_helpers_called_from_handlers() {
        let flagged = scan(concat!(
            "import os\n",
            "def helper():\n",
            "    os.environ['AWS_REGION'] = \"us-west-2\"\n",
            "def lambda_handler(event, context):\n",
            "    helper()\n",
            "def unrelated():\n",
            "    os.environ['AWS_REGION'] = \"us-west-2\"\n",
            "os.environ['AWS_REGION'] = \"us-west-2\"\n",
        ));
        assert_eq!(findings(&flagged, KEY).len(), 1);
    }

    #[test]
    fn s7617_spares_non_lambda_code() {
        let quiet = scan(concat!(
            "import os\n",
            "def not_a_handler():\n",
            "    os.environ['AWS_REGION'] = \"us-west-2\"\n",
            "os.environ['AWS_REGION'] = \"us-west-2\"\n",
        ));
        assert!(findings(&quiet, KEY).is_empty());
    }
}
