use ruff_python_ast::{Expr, ExprCall};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::engine::file_context::FileContext;
use crate::support::{
    WebFrameworkFacts, is_add_middleware, is_cors_middleware, nth_or_keyword_argument,
};
use crate::support::{issue_at, to_pos};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8414";
const MESSAGE: &str = "Add CORSMiddleware last in the middleware chain.";

/// python:S8414 — `FastAPI` middleware wraps the application in reverse
/// order of `add_middleware` calls, so `CORSMiddleware` must be added last to
/// stay the outermost layer and cover every response. Sonar flags the
/// callee of a `FastAPI`|`Starlette` `add_middleware` call whose middleware
/// class is `CORSMiddleware` when the same receiver name is the receiver
/// of another `add_middleware` call on a later line in the same
/// function/lambda/module scope.
pub(crate) fn check_s8414_cors_middleware_ordering(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut additions: Vec<(String, Option<TextRange>, u32)> = Vec::new();
    for call in &file_ctx.calls {
        if !is_add_middleware_call(&facts, call) {
            continue;
        }
        if let Expr::Name(receiver) = receiver_of(call) {
            let line = to_pos(call.range().start(), index, source).line;
            let scope = facts.enclosing_scope(call.range());
            additions.push((receiver.id.as_str().to_string(), scope, line));
        }
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !is_add_middleware_call(&facts, call) || !is_cors_addition(&facts, call) {
            continue;
        }
        let Expr::Name(receiver) = receiver_of(call) else {
            continue;
        };
        let line = to_pos(call.range().start(), index, source).line;
        let scope = facts.enclosing_scope(call.range());
        if additions.iter().any(|(name, other_scope, other_line)| {
            *name == receiver.id.as_str() && *other_scope == scope && *other_line > line
        }) {
            issues.push(issue_at(
                RULE_KEY,
                MESSAGE,
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}

fn is_add_middleware_call(facts: &WebFrameworkFacts<'_>, call: &ExprCall) -> bool {
    facts
        .expr_fqn(&call.func)
        .is_some_and(|fqn| is_add_middleware(&fqn))
}

fn is_cors_addition(facts: &WebFrameworkFacts<'_>, call: &ExprCall) -> bool {
    nth_or_keyword_argument(call, 0, "middleware_class")
        .and_then(|expr| facts.expr_fqn(expr))
        .is_some_and(|fqn| is_cors_middleware(&fqn))
}

fn receiver_of(call: &ExprCall) -> &Expr {
    match call.func.as_ref() {
        Expr::Attribute(attribute) => attribute.value.as_ref(),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S8414")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s8414_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: GZipMiddleware is added after
        // CORSMiddleware — the `app.add_middleware` callee of the CORS call
        // anchors the finding (line 7, columns 0-18).
        let ranges = found(concat!(
            "from fastapi import FastAPI\n",
            "from fastapi.middleware.cors import CORSMiddleware\n",
            "from fastapi.middleware.gzip import GZipMiddleware\n",
            "\n",
            "app = FastAPI()\n",
            "\n",
            "app.add_middleware(\n",
            "    CORSMiddleware,\n",
            "    allow_origins=[\"*\"],\n",
            "    allow_credentials=True,\n",
            "    allow_methods=[\"*\"],\n",
            "    allow_headers=[\"*\"],\n",
            ")\n",
            "app.add_middleware(GZipMiddleware)\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(7, 0));
        assert_eq!(ranges[0].end, pos(7, 18));
    }

    #[test]
    fn s8414_accepts_the_sonar_compliant_example() {
        assert!(
            found(concat!(
                "from fastapi import FastAPI\n",
                "from fastapi.middleware.cors import CORSMiddleware\n",
                "from fastapi.middleware.gzip import GZipMiddleware\n",
                "\n",
                "app = FastAPI()\n",
                "\n",
                "app.add_middleware(GZipMiddleware)\n",
                "app.add_middleware(\n",
                "    CORSMiddleware,\n",
                "    allow_origins=[\"*\"],\n",
                "    allow_credentials=True,\n",
                "    allow_methods=[\"*\"],\n",
                "    allow_headers=[\"*\"],\n",
                ")\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8414_ignores_cors_on_a_different_receiver() {
        // Middleware added to another app after the CORS call does not
        // reorder this app's chain.
        assert!(
            found(concat!(
                "from fastapi import FastAPI\n",
                "from fastapi.middleware.cors import CORSMiddleware\n",
                "from fastapi.middleware.gzip import GZipMiddleware\n",
                "\n",
                "app = FastAPI()\n",
                "other = FastAPI()\n",
                "app.add_middleware(CORSMiddleware)\n",
                "other.add_middleware(GZipMiddleware)\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8414_ignores_non_cors_and_unbound_calls() {
        // A non-CORS middleware followed by another middleware is fine, and
        // `add_middleware` on an unbound receiver stays silent.
        assert!(
            found(concat!(
                "from fastapi.middleware.gzip import GZipMiddleware\n",
                "from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware\n",
                "\n",
                "app = object()\n",
                "app.add_middleware(GZipMiddleware)\n",
                "app.add_middleware(HTTPSRedirectMiddleware)\n",
            ))
            .is_empty()
        );
    }
}
