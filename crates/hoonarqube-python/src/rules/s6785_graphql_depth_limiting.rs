use crate::support::call_source_text;
use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6785 — GraphQL queries vulnerable to DoS ---------------------------
//
// Honest subset: GraphQL `Schema(...)` constructions (recognized through their
// `query`/`mutation` keyword arguments) that nowhere reference a depth-limiting
// extension such as `QueryDepthLimiter`.

pub(crate) fn check_s6785_graphql_depth_limiting(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if called_name(&call.func) != Some("Schema") {
            return;
        }
        let graphql_schema =
            has_keyword(&call.arguments, "query") || has_keyword(&call.arguments, "mutation");
        let depth_limited = call_source_text(call, source).contains("DepthLimiter");
        if graphql_schema && !depth_limited {
            issues.push(issue_at(
                "python:S6785",
                "Add depth limiting to this GraphQL schema construction.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
