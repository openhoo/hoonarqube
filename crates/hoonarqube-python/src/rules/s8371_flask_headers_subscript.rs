use crate::engine::file_context::FileContext;
use crate::support::{
    WebBinding, expr_in, for_each_expr, issue_at, scope_maps, stmt_exprs, visit_scoped_stmts,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};
use std::collections::HashSet;

const RULE_KEY: &str = "python:S8371";
const MESSAGE: &str = "Use \".get()\" method to safely access this header.";

/// python:S8371 — HTTP headers are optional, so `request.headers['X']`
/// raises `KeyError` when the client omits the header; `.get()` returns
/// `None` instead. The reference check (`FlaskHeadersDictAccessCheck`)
/// flags every subscript whose object is a `werkzeug.datastructures.Headers`
/// instance — `request.headers` and the `.headers` of Flask responses —
/// unless the subscript is the target of a plain assignment statement.
/// Reads inside `del`, augmented/annotated assignments, `for` targets, and
/// guards still flag, matching the reference's "even when guards appear to
/// protect the access" contract.
pub(crate) fn check_s8371_flask_headers_subscript(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_scoped_stmts(
        file_ctx.module_body,
        file_ctx.web_bindings.module_scope(),
        &mut |stmt, scopes| {
            let maps = scope_maps(scopes);
            let assign_targets = assign_target_subscripts(stmt);
            for expr in stmt_exprs(stmt) {
                for_each_expr(expr, &mut |expr| {
                    let Expr::Subscript(subscript) = expr else {
                        return;
                    };
                    if assign_targets.contains(&subscript.range()) {
                        return;
                    }
                    if expr_in(&subscript.value, &maps) == WebBinding::WerkzeugHeaders {
                        issues.push(issue_at(RULE_KEY, MESSAGE, expr.range(), index, source));
                    }
                });
            }
        },
    );
    issues
}

/// Ranges of subscripts that are (part of) a plain assignment's targets —
/// the reference's `isAssignmentTarget` exemption. Tuple/list/starred
/// targets contribute their element subscripts.
fn assign_target_subscripts(stmt: &Stmt) -> HashSet<TextRange> {
    let mut ranges = HashSet::new();
    let Stmt::Assign(assign) = stmt else {
        return ranges;
    };
    for target in &assign.targets {
        collect_subscripts(target, &mut ranges);
    }
    ranges
}

fn collect_subscripts(expr: &Expr, ranges: &mut HashSet<TextRange>) {
    match expr {
        Expr::Subscript(subscript) => {
            ranges.insert(subscript.range());
        }
        Expr::Tuple(tuple) => {
            for element in &tuple.elts {
                collect_subscripts(element, ranges);
            }
        }
        Expr::List(list) => {
            for element in &list.elts {
                collect_subscripts(element, ranges);
            }
        }
        Expr::Starred(starred) => collect_subscripts(&starred.value, ranges),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S8371")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s8371_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: both dictionary-style header reads
        // anchor on the whole subscript.
        let ranges = found(concat!(
            "from flask import Flask, request\n",
            "app = Flask(__name__)\n",
            "\n",
            "@app.route('/api')\n",
            "def api_endpoint():\n",
            "    auth_header = request.headers['Authorization']\n",
            "    user_agent = request.headers['User-Agent']\n",
            "    return process_request(auth_header, user_agent)\n",
        ));
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, pos(6, 18));
        assert_eq!(ranges[0].end, pos(6, 50));
        assert_eq!(ranges[1].start, pos(7, 17));
        assert_eq!(ranges[1].end, pos(7, 46));
    }

    #[test]
    fn s8371_accepts_the_sonar_compliant_example() {
        // Sonar's Compliant example: `.get()` access is safe.
        assert!(
            found(concat!(
                "from flask import Flask, request\n",
                "app = Flask(__name__)\n",
                "\n",
                "@app.route('/api')\n",
                "def api_endpoint():\n",
                "    auth_header = request.headers.get('Authorization')\n",
                "    user_agent = request.headers.get('User-Agent', 'Unknown')\n",
                "    if not auth_header:\n",
                "        return 'Authorization required', 401\n",
                "    return process_request(auth_header, user_agent)\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8371_flags_guarded_reads_and_response_headers() {
        // Reads under a membership guard still flag (the reference does not
        // exempt them), and a response object's `.headers` subscript flags
        // the same way.
        let ranges = found(concat!(
            "from flask import Flask, request, make_response\n",
            "app = Flask(__name__)\n",
            "\n",
            "@app.route('/api')\n",
            "def api_endpoint():\n",
            "    if 'Authorization' in request.headers:\n",
            "        token = request.headers['Authorization']\n",
            "    resp = make_response('ok')\n",
            "    seen = resp.headers['X-Seen']\n",
            "    return resp\n",
        ));
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, pos(7, 16));
        assert_eq!(ranges[1].start, pos(9, 11));
    }

    #[test]
    fn s8371_ignores_writes_and_non_flask_mappings() {
        // Assigning a header is not a read, and subscripts on ordinary
        // mappings or a shadowed `request` name stay silent.
        assert!(
            found(concat!(
                "from flask import Flask, request\n",
                "app = Flask(__name__)\n",
                "\n",
                "@app.route('/api')\n",
                "def api_endpoint():\n",
                "    request.headers['X-Tag'] = '1'\n",
                "    plain = {}\n",
                "    return plain['missing']\n",
                "\n",
                "def shadowed(request):\n",
                "    return request.headers['X']\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8371_flags_augmented_and_deleted_reads() {
        // Augmented assignment and `del` are not plain assignment targets in
        // the reference, so both still flag.
        let ranges = found(concat!(
            "from flask import Flask, request\n",
            "app = Flask(__name__)\n",
            "\n",
            "@app.route('/api')\n",
            "def api_endpoint():\n",
            "    request.headers['X-Count'] += '1'\n",
            "    del request.headers['X-Gone']\n",
            "    return 'ok'\n",
        ));
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, pos(6, 4));
        assert_eq!(ranges[1].start, pos(7, 8));
    }
}
