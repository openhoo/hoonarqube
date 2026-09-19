use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::{WebFrameworkFacts, has_dict_unpacking, is_flask_route, keyword_argument};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S6965";
const MESSAGE: &str = "Specify the HTTP methods this route should accept.";

/// python:S6965 — Flask routes accept only GET requests unless the
/// decorator's `methods` parameter says otherwise, so a handler that
/// checks `request.method` for other verbs still answers 405. Sonar flags
/// the whole `@app.route(...)`/`@blueprint.route(...)` decorator on a
/// `Flask` or `Blueprint` receiver when no `methods` keyword is present
/// (a `**kwargs` unpacking counts as potentially providing it).
pub(crate) fn check_s6965_flask_route_methods(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for function in &file_ctx.functions {
        for decorator in &function.decorator_list {
            let Expr::Call(call) = &decorator.expression else {
                continue;
            };
            if !facts
                .expr_fqn(&call.func)
                .is_some_and(|fqn| is_flask_route(&fqn))
            {
                continue;
            }
            if keyword_argument(call, "methods").is_some() || has_dict_unpacking(call) {
                continue;
            }
            issues.push(issue_at(
                RULE_KEY,
                MESSAGE,
                decorator.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S6965")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s6965_flags_the_sonar_noncompliant_examples() {
        // Sonar's Noncompliant examples: a route whose handler checks
        // `request.method` and a plain GET route — the whole decorator
        // (including `@`) anchors each finding.
        let ranges = found(concat!(
            "from flask import Flask, request\n",
            "\n",
            "app = Flask(__name__)\n",
            "\n",
            "@app.route('/api/users')\n",
            "def handle_users():\n",
            "    if request.method == 'POST':\n",
            "        return create_user()\n",
            "    return get_users()\n",
            "\n",
            "@app.route('/dashboard')\n",
            "def dashboard():\n",
            "    return render_template('dashboard.html')\n",
        ));
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, pos(5, 0));
        assert_eq!(ranges[0].end, pos(5, 24));
        assert_eq!(ranges[1].start, pos(11, 0));
        assert_eq!(ranges[1].end, pos(11, 24));
    }

    #[test]
    fn s6965_accepts_the_sonar_compliant_examples() {
        assert!(
            found(concat!(
                "from flask import Flask, request\n",
                "\n",
                "app = Flask(__name__)\n",
                "\n",
                "@app.route('/api/users', methods=['GET', 'POST'])\n",
                "def handle_users():\n",
                "    if request.method == 'POST':\n",
                "        return create_user()\n",
                "    return get_users()\n",
                "\n",
                "@app.route('/dashboard', methods=['GET'])\n",
                "def dashboard():\n",
                "    return render_template('dashboard.html')\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s6965_flags_blueprint_routes() {
        // `flask.blueprints.Blueprint.route` is in Sonar's matcher.
        let ranges = found(concat!(
            "from flask import Blueprint\n",
            "\n",
            "bp = Blueprint('api', __name__)\n",
            "\n",
            "@bp.route('/items')\n",
            "def items():\n",
            "    return []\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(5, 0));
    }

    #[test]
    fn s6965_ignores_unpacking_and_non_flask_receivers() {
        // `**options` may carry `methods`, and `route` on a FastAPI app is
        // a different rule's concern.
        assert!(
            found(concat!(
                "from fastapi import FastAPI\n",
                "from flask import Flask\n",
                "\n",
                "app = Flask(__name__)\n",
                "api = FastAPI()\n",
                "options = {\"methods\": [\"GET\"]}\n",
                "\n",
                "@app.route('/a', **options)\n",
                "def a():\n",
                "    return {}\n",
                "\n",
                "@api.route('/b', methods=[\"GET\"])\n",
                "def b():\n",
                "    return {}\n",
            ))
            .is_empty()
        );
    }
}
