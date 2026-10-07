use crate::engine::bindings::{CookieApi, KnownBinding};
use crate::engine::file_context::FileContext;
use crate::support::cookie_flag_missing;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_cookie_flag(
    index: &LineIndex,
    source: &str,
    rule_key: &str,
    message: &str,
    flag: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        // A CookieJar accepts complete cookie objects; only web responses
        // expose the secure/httponly flag arguments checked by these rules.
        let Expr::Attribute(method) = call.func.as_ref() else {
            continue;
        };
        let KnownBinding::CookieResponse(api) =
            file_ctx.known_bindings.resolve_expr_identity(&method.value)
        else {
            continue;
        };
        if call
            .arguments
            .args
            .iter()
            .any(|arg| matches!(arg, Expr::Starred(_)))
            || call
                .arguments
                .keywords
                .iter()
                .any(|keyword| keyword.arg.is_none())
        {
            continue;
        }
        let position = match (api, flag) {
            (CookieApi::Starlette, _) => None,
            (CookieApi::WerkzeugSansio, "secure") | (_, "httponly") => Some(7),
            (_, "secure") => Some(6),
            _ => None,
        };
        if cookie_flag_missing(call, flag, position) {
            issues.push(issue_at(
                rule_key,
                message,
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s3330_accepts_non_literal_httponly_argument_and_reports_false() {
        // Issue #618 and PR #719 prove the dynamic Django flag expression
        // must stay clean. Their added False clean control overgeneralized
        // that evidence: Sonar 26.9 live/cookie-controls flags False while
        // preserving dynamic values, so both cases are pinned separately.
        let clean = concat!(
            "from flask import Response\nresp = Response()\n",
            "resp.set_cookie(\"k\", \"v\", httponly=settings.SESSION_COOKIE_HTTPONLY or None)\n",
            "resp.set_cookie(\"k\", \"v\", httponly=True)\n",
        );
        assert!(findings(&scan(clean), "python:S3330").is_empty());

        // Only a missing httponly argument reports.
        let flagged =
            "from flask import Response\nresp = Response()\nresp.set_cookie(\"k\", \"v\")\n";
        let report = scan(flagged);
        let found = findings(&report, "python:S3330");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
        assert_eq!(found[0].range.start.column, 0);
    }
}

#[cfg(test)]
mod provenance_tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn cookie_flags_preserve_requests_cookiejar_and_unrelated_receivers() {
        // requests 2.32.5 cookies.py:247,389,397,490,599,623:
        // CookieJar.set_cookie receives an already-created Cookie object.
        // It is not a response API accepting secure/httponly keyword flags.
        let source = concat!(
            "from requests.cookies import RequestsCookieJar\n",
            "import copy\n",
            "jar = RequestsCookieJar()\n",
            "jar.set_cookie(copy.copy(cookie))\n",
            "class Other:\n",
            "    def set_cookie(self, cookie):\n        return cookie\n",
            "other = Other()\nother.set_cookie(cookie)\n",
        );
        let report = scan(source);
        assert!(findings(&report, "python:S2092").is_empty());
        assert!(findings(&report, "python:S3330").is_empty());
    }

    #[test]
    fn cookie_flags_resolve_frameworks_positions_and_rebindings() {
        let source = concat!(
            "from django.http import HttpResponse\n",
            "from werkzeug.wrappers import Response as WerkzeugResponse\n",
            "from starlette.responses import JSONResponse\n",
            "django = HttpResponse()\n",
            "werkzeug = WerkzeugResponse()\n",
            "starlette = JSONResponse({})\n",
            "django.set_cookie('k', 'v', None, None, '/', None, True, True)\n",
            "werkzeug.set_cookie('k', 'v', None, None, '/', None, True, True)\n",
            "starlette.set_cookie('k', 'v', secure=True, httponly=True)\n",
            "django.set_cookie('k', 'v')\n",
            "werkzeug.set_cookie('k', 'v')\n",
            "starlette.set_cookie('k', 'v')\n",
            "def configure(werkzeug):\n    werkzeug.set_cookie(cookie)\n",
            "django = object()\ndjango.set_cookie(cookie)\n",
        );
        let report = scan(source);
        for rule in ["python:S2092", "python:S3330"] {
            let found = findings(&report, rule);
            assert_eq!(found.len(), 3);
            assert_eq!(
                found
                    .iter()
                    .map(|issue| issue.range.start.line)
                    .collect::<Vec<_>>(),
                vec![10, 11, 12]
            );
        }
    }

    #[test]
    fn cookie_flags_skip_unpacking_and_preserve_imported_responses() {
        let source = concat!(
            "from flask import Response as Reply\n",
            "resp = Reply()\n",
            "resp.set_cookie('k', 'v', **options)\n",
            "resp.set_cookie(*cookie_args)\n",
            "resp.set_cookie('k', 'v')\n",
        );
        let report = scan(source);
        for rule in ["python:S2092", "python:S3330"] {
            let found = findings(&report, rule);
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].range.start.line, 5);
        }
    }
}

#[cfg(test)]
mod literal_tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn cookie_flags_report_explicit_false_for_both_flags() {
        let source = "from flask import Response\nresp = Response()\nresp.set_cookie('k', 'v', secure=False, httponly=False)\n";
        let report = scan(source);
        assert_eq!(findings(&report, "python:S2092").len(), 1);
        assert_eq!(findings(&report, "python:S3330").len(), 1);
    }
}
