use crate::engine::file_context::FileContext;
use crate::support::{
    WebBinding, expr_in, issue_at, keyword_value, nth_argument_or_keyword, scope_maps,
    visit_scoped_stmts,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const RULE_KEY: &str = "python:S8385";
const MESSAGE: &str =
    "Provide \"mimetype\" or \"download_name\" when calling \"send_file\" with a file-like object.";

/// python:S8385 — `flask.send_file` cannot infer a content type for
/// file-like objects (open handles, `BytesIO`, `StringIO`, temporary
/// files), so it raises `ValueError` unless `mimetype` or `download_name`
/// (or the pre-2.0 `attachment_filename`) is given. The reference check
/// (`FlaskSendFileMimeTypeCheck`) flags a `send_file` call whose
/// `path_or_file` argument (first positional or keyword) is a `typing.IO`
/// instance and none of those keywords is present, anchoring on the callee.
/// Path strings and `pathlib.Path` objects stay silent because Flask can
/// infer the type from the filename.
pub(crate) fn check_s8385_flask_send_file_mimetype(
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
            for expr in crate::support::stmt_exprs(stmt) {
                crate::support::for_each_expr(expr, &mut |expr| {
                    let Expr::Call(call) = expr else {
                        return;
                    };
                    if is_problematic_send_file(call, &maps) {
                        issues.push(issue_at(
                            RULE_KEY,
                            MESSAGE,
                            call.func.range(),
                            index,
                            source,
                        ));
                    }
                });
            }
        },
    );
    issues
}

/// `send_file(<file-like>)` without `mimetype`, `download_name`, or
/// `attachment_filename`.
fn is_problematic_send_file(
    call: &ruff_python_ast::ExprCall,
    scopes: &[&std::collections::HashMap<String, WebBinding>],
) -> bool {
    if expr_in(&call.func, scopes) != WebBinding::FlaskSendFile {
        return false;
    }
    let Some(path_or_file) = nth_argument_or_keyword(&call.arguments, 0, "path_or_file") else {
        return false;
    };
    if expr_in(path_or_file, scopes) != WebBinding::FileLikeObject {
        return false;
    }
    keyword_value(&call.arguments, "mimetype").is_none()
        && keyword_value(&call.arguments, "download_name").is_none()
        && keyword_value(&call.arguments, "attachment_filename").is_none()
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S8385")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s8385_flags_the_sonar_noncompliant_examples() {
        // Sonar's Noncompliant examples: open handles, BytesIO, and StringIO
        // objects without mimetype/download_name anchor on `send_file`.
        let ranges = found(concat!(
            "from flask import send_file\n",
            "from io import BytesIO, StringIO\n",
            "\n",
            "def download_file():\n",
            "    file_obj = open('data.txt', 'rb')\n",
            "    return send_file(file_obj)\n",
            "\n",
            "def download_csv():\n",
            "    csv_data = BytesIO(b'name,age\\nJohn,30')\n",
            "    return send_file(csv_data)\n",
            "\n",
            "def download_log():\n",
            "    log_data = StringIO('INFO: Application started')\n",
            "    return send_file(log_data)\n",
        ));
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0].start, pos(6, 11));
        assert_eq!(ranges[0].end, pos(6, 20));
        assert_eq!(ranges[1].start, pos(10, 11));
        assert_eq!(ranges[2].start, pos(14, 11));
    }

    #[test]
    fn s8385_accepts_the_sonar_compliant_examples() {
        // Sonar's Compliant examples: mimetype, download_name, or both make
        // the calls safe.
        assert!(
            found(concat!(
                "from flask import send_file\n",
                "from io import BytesIO\n",
                "\n",
                "def download_file():\n",
                "    file_obj = open('data.txt', 'rb')\n",
                "    return send_file(file_obj, mimetype='text/plain')\n",
                "\n",
                "def download_csv():\n",
                "    csv_data = BytesIO(b'name,age\\nJohn,30')\n",
                "    return send_file(csv_data, download_name='data.csv', as_attachment=True)\n",
                "\n",
                "def download_log():\n",
                "    from io import StringIO\n",
                "    log_data = StringIO('INFO: Application started')\n",
                "    return send_file(log_data, mimetype='text/plain', download_name='app.log')\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8385_ignores_paths_and_attachment_filename() {
        // Path strings and Path objects let Flask infer the type, and the
        // legacy attachment_filename keyword satisfies the rule.
        assert!(
            found(concat!(
                "from flask import send_file\n",
                "from pathlib import Path\n",
                "\n",
                "def by_path():\n",
                "    return send_file('data.txt')\n",
                "\n",
                "def by_pathlib():\n",
                "    return send_file(Path('data.txt'))\n",
                "\n",
                "def legacy():\n",
                "    return send_file(open('data.txt', 'rb'), attachment_filename='data.txt')\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8385_flags_inline_and_tempfile_objects() {
        // Inline open() calls, io.* constructors, and tempfile factories
        // count as file-like objects too.
        let ranges = found(concat!(
            "import io\n",
            "import tempfile\n",
            "from flask import send_file\n",
            "\n",
            "def inline():\n",
            "    return send_file(open('data.txt', 'rb'))\n",
            "\n",
            "def buffered():\n",
            "    return send_file(io.BytesIO(b'x'))\n",
            "\n",
            "def temp():\n",
            "    return send_file(tempfile.TemporaryFile())\n",
        ));
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0].start, pos(6, 11));
        assert_eq!(ranges[1].start, pos(9, 11));
        assert_eq!(ranges[2].start, pos(12, 11));
    }

    #[test]
    fn s8385_ignores_non_flask_send_file() {
        // A same-named function that is not flask.send_file is not a
        // finding.
        assert!(
            found(concat!(
                "def send_file(obj):\n",
                "    return obj\n",
                "\n",
                "def caller():\n",
                "    return send_file(open('data.txt', 'rb'))\n",
            ))
            .is_empty()
        );
    }
}
