use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{WebFrameworkFacts, issue_at, keyword_argument, nth_or_keyword_argument};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8392";
const MESSAGE: &str = "Avoid binding the application to all network interfaces.";
const ALL_NETWORK_INTERFACES: &str = "0.0.0.0";

/// python:S8392 — binding a web server to `0.0.0.0` exposes it on every
/// network interface of the host, violating least privilege. The
/// reference flags the callee of `uvicorn.run(...)` and
/// `flask.app.Flask.run(...)` calls whose `host` is the literal
/// `"0.0.0.0"`. For `uvicorn.run` only the `host` keyword is inspected;
/// for `Flask.run` the first positional argument doubles as `host`. A
/// `host` name bound once to the literal resolves to it (the reference's
/// `extractStringLiteral` single-assignment hop); other addresses,
/// `localhost`, empty strings, `None`, unresolvable names, and receivers
/// that are not a Flask app or the uvicorn module stay silent.
pub(crate) fn check_s8392_bind_all_network_interfaces(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Some(fqn) = facts.expr_fqn(&call.func) else {
            continue;
        };
        let host = match fqn.as_str() {
            "uvicorn.run" => keyword_argument(call, "host"),
            "flask.app.Flask.run" => nth_or_keyword_argument(call, 0, "host"),
            _ => None,
        };
        if let Some(host) = host
            && host_is_all_interfaces(host, &facts)
        {
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

/// Whether `expr` is the `"0.0.0.0"` string literal, or a name whose
/// single assignment bound it to that literal (one hop, matching the
/// reference's `extractStringLiteral`).
fn host_is_all_interfaces(expr: &Expr, facts: &WebFrameworkFacts) -> bool {
    string_literal_value(expr).is_some_and(|value| value == ALL_NETWORK_INTERFACES)
        || matches!(expr, Expr::Name(name)
            if facts
                .single_assigned_value(name.id.as_str(), name.range())
                .and_then(string_literal_value)
                .is_some_and(|value| value == ALL_NETWORK_INTERFACES))
}

fn string_literal_value(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::StringLiteral(literal) => Some(literal.value.to_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8392")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8392_flags_the_sonar_noncompliant_examples() {
        let flagged = found(concat!(
            "import uvicorn\n",
            "from fastapi import FastAPI\n",
            "from flask import Flask\n",
            "\n",
            "app_fastapi = FastAPI()\n",
            "uvicorn.run(app_fastapi, host=\"0.0.0.0\", port=8000)\n",
            "\n",
            "app_flask = Flask(__name__)\n",
            "app_flask.run(host='0.0.0.0', debug=True)\n",
            "app_flask.run('0.0.0.0', 5000, True)\n",
        ));
        assert_eq!(flagged.len(), 3);
        // The issue anchors on the callee: `uvicorn.run` (line 6,
        // columns 0-11) and `app_flask.run` (line 9, columns 0-13).
        assert_eq!(flagged[0].range.start, pos(6, 0));
        assert_eq!(flagged[0].range.end, pos(6, 11));
        assert_eq!(flagged[1].range.start, pos(9, 0));
        assert_eq!(flagged[1].range.end, pos(9, 13));
        assert_eq!(
            flagged[0].message,
            "Avoid binding the application to all network interfaces."
        );
    }

    #[test]
    fn s8392_flags_host_bound_through_a_single_assignment() {
        let flagged = found(concat!(
            "import uvicorn\n",
            "from flask import Flask\n",
            "\n",
            "host_config = \"0.0.0.0\"\n",
            "uvicorn.run(app, host=host_config, port=8000)\n",
            "\n",
            "app_flask = Flask(__name__)\n",
            "host = '0.0.0.0'\n",
            "app_flask.run(host=host, debug=True)\n",
        ));
        assert_eq!(flagged.len(), 2);
    }

    #[test]
    fn s8392_accepts_localhost_and_unresolvable_hosts() {
        assert!(
            found(concat!(
                "import uvicorn\n",
                "from flask import Flask\n",
                "from somewhere import my_host_name\n",
                "\n",
                "uvicorn.run(app, host=\"127.0.0.1\")\n",
                "uvicorn.run(app, port=8000)\n",
                "uvicorn.run(app, host=\"localhost\", port=8000)\n",
                "uvicorn.run(app, host=\"192.168.1.100\", port=8000)\n",
                "uvicorn.run(app, host=my_host_name, port=8000)\n",
                "\n",
                "app_flask = Flask(__name__)\n",
                "app_flask.run(host='127.0.0.1', debug=True)\n",
                "app_flask.run(host='', debug=True)\n",
                "app_flask.run('', debug=True)\n",
                "app_flask.run(None, debug=True)\n",
                "other_host = '12'\n",
                "app_flask.run(other_host, debug=True)\n",
                "reassigned = '0.0.0.0'\n",
                "app_flask.run(reassigned, debug=True)\n",
                "reassigned = '0.0.0.0'\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8392_accepts_non_framework_run_calls() {
        // A `run` method on an unrelated receiver and a `run` function
        // that is not `uvicorn.run` stay silent.
        assert!(
            found(concat!(
                "class Server:\n",
                "    def run(self, host=None):\n",
                "        pass\n",
                "\n",
                "server = Server()\n",
                "server.run(host='0.0.0.0')\n",
                "\n",
                "def run(host=None):\n",
                "    pass\n",
                "run(host='0.0.0.0')\n",
            ))
            .is_empty()
        );
    }
}
