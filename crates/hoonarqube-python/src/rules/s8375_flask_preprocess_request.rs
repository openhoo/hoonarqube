use crate::engine::file_context::FileContext;
use crate::support::{WebBinding, expr_in, issue_at, scope_maps, visit_scoped_stmts};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const RULE_KEY: &str = "python:S8375";
const MESSAGE: &str = "Handle the return value of \"preprocess_request()\" to ensure before-request handlers' responses are not ignored.";

/// python:S8375 — `Flask.preprocess_request()` returns a response when a
/// before-request handler short-circuits (auth redirect, 403, 429, 503);
/// discarding it silently bypasses the handler's decision. The reference
/// check (`FlaskPreprocessRequestCheck`) flags a `preprocess_request()` call
/// on a Flask application instance only when it is a bare expression
/// statement; assigning, returning, or testing the result stays silent. The
/// finding anchors on the callee expression.
pub(crate) fn check_s8375_flask_preprocess_request(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_scoped_stmts(
        file_ctx.module_body,
        file_ctx.web_bindings.module_scope(),
        &mut |stmt, scopes| {
            let Stmt::Expr(expression) = stmt else {
                return;
            };
            let Expr::Call(call) = expression.value.as_ref() else {
                return;
            };
            let maps = scope_maps(scopes);
            if expr_in(&call.func, &maps) == WebBinding::FlaskPreprocessRequest {
                issues.push(issue_at(
                    RULE_KEY,
                    MESSAGE,
                    call.func.range(),
                    index,
                    source,
                ));
            }
        },
    );
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S8375")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s8375_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: the bare call anchors on the callee
        // `app.preprocess_request`.
        let ranges = found(concat!(
            "from flask import Flask\n",
            "app = Flask(__name__)\n",
            "\n",
            "app.preprocess_request()\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(4, 0));
        assert_eq!(ranges[0].end, pos(4, 22));
    }

    #[test]
    fn s8375_accepts_the_sonar_compliant_example() {
        // Sonar's Compliant example: the return value is captured and
        // checked, so the call is not a bare statement.
        assert!(
            found(concat!(
                "from flask import Flask\n",
                "app = Flask(__name__)\n",
                "\n",
                "def dispatch():\n",
                "    response = app.preprocess_request()\n",
                "    if response is not None:\n",
                "        return response\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8375_ignores_used_and_non_flask_calls() {
        // Calls whose result is returned, tested, or passed along are not
        // bare statements; a `preprocess_request` on a non-Flask object is
        // not a finding either.
        assert!(
            found(concat!(
                "from flask import Flask\n",
                "app = Flask(__name__)\n",
                "\n",
                "def dispatch():\n",
                "    if app.preprocess_request() is not None:\n",
                "        return app.preprocess_request()\n",
                "    log(app.preprocess_request())\n",
                "\n",
                "class App:\n",
                "    def preprocess_request(self):\n",
                "        return None\n",
                "other = App()\n",
                "other.preprocess_request()\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8375_flags_calls_inside_functions_and_methods() {
        // A bare call inside a function or method flags the same as a
        // module-level one; the app resolves through the lexical chain.
        let ranges = found(concat!(
            "from flask import Flask\n",
            "app = Flask(__name__)\n",
            "\n",
            "def handle():\n",
            "    app.preprocess_request()\n",
            "    return 'done'\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(5, 4));
        assert_eq!(ranges[0].end, pos(5, 26));
    }
}
