use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{NameResolution, WebFrameworkFacts, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8405";
const MESSAGE: &str = "Use \"content\" parameter instead of \"data\" for bytes or text.";

const TEST_CLIENT_FQNS: [&str; 2] = [
    "starlette.testclient.TestClient",
    "fastapi.testclient.TestClient",
];

const HTTP_METHODS: [&str; 8] = [
    "get", "post", "put", "delete", "patch", "head", "options", "request",
];

/// python:S8405 — `Starlette`'s `TestClient` (re-exported by `FastAPI`) is
/// backed by httpx, where `data=` only accepts form dictionaries; raw
/// bytes and text must go through `content=`. Sonar flags the `data`
/// keyword of `client.<method>(..., data=<bytes-or-str>)` calls on a
/// `TestClient` receiver, including names bound to a bytes/str literal
/// and f-strings; dictionaries, `None`, and values of unknown type stay
/// silent.
pub(crate) fn check_s8405_test_client_content_parameter(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Expr::Attribute(attribute) = call.func.as_ref() else {
            continue;
        };
        if !HTTP_METHODS.contains(&attribute.attr.as_str()) {
            continue;
        }
        if !facts
            .expr_fqn(&attribute.value)
            .is_some_and(|fqn| TEST_CLIENT_FQNS.contains(&fqn.as_str()))
        {
            continue;
        }
        for keyword in &call.arguments.keywords {
            if keyword.arg.as_deref() != Some("data") {
                continue;
            }
            if is_str_or_bytes(&facts, &keyword.value) {
                let Some(name) = keyword.arg.as_ref() else {
                    continue;
                };
                issues.push(issue_at(RULE_KEY, MESSAGE, name.range(), index, source));
            }
        }
    }
    issues
}

/// Whether `expr` produces `str`/`bytes` — literals (including
/// f-strings), `str(...)`/`bytes(...)`/`json.dumps(...)` calls, `+`
/// concatenation of two such values, or a name bound to exactly one such
/// value. Sonar decides via `isObjectOfType(str|bytes)` type inference.
fn is_str_or_bytes(facts: &WebFrameworkFacts<'_>, expr: &Expr) -> bool {
    match expr {
        Expr::StringLiteral(_) | Expr::BytesLiteral(_) | Expr::FString(_) => true,
        Expr::Name(name) => match facts.resolve_name(name.id.as_str(), expr.range()) {
            NameResolution::Value(value) => is_str_or_bytes(facts, value),
            _ => false,
        },
        Expr::Call(call) => {
            if let Some(fqn) = facts.expr_fqn(&call.func) {
                fqn == "json.dumps"
            } else {
                // Builtin constructors: bare `str`/`bytes` not shadowed.
                matches!(
                    call.func.as_ref(),
                    Expr::Name(name)
                        if matches!(name.id.as_str(), "str" | "bytes")
                            && matches!(
                                facts.resolve_name(name.id.as_str(), expr.range()),
                                NameResolution::Unbound
                            )
                )
            }
        }
        Expr::BinOp(binary) if matches!(binary.op, ruff_python_ast::Operator::Add) => {
            is_str_or_bytes(facts, &binary.left) && is_str_or_bytes(facts, &binary.right)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S8405")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s8405_flags_the_sonar_noncompliant_examples() {
        // Sonar's Noncompliant examples: `data=` with bytes, text,
        // f-strings, and names bound to str/bytes on every TestClient
        // method, on aliased imports, and on inline TestClient(app).
        let ranges = found(concat!(
            "from starlette.testclient import TestClient\n",
            "from starlette.applications import Starlette\n",
            "\n",
            "strVar = \"\"\n",
            "bytesVar = b\"\"\n",
            "intVar = 1\n",
            "\n",
            "app = Starlette()\n",
            "client = TestClient(app)\n",
            "\n",
            "response = client.post('/api', data=b'raw bytes')\n",
            "response = client.put('/api', data='text content')\n",
            "response = client.get('/api', data=b'bytes')\n",
            "response = client.delete('/api', data=b'bytes')\n",
            "response = client.patch('/api', data=b'bytes')\n",
            "response = client.request('POST', '/api', data=b'bytes')\n",
            "response = client.post('/api', data=strVar)\n",
            "response = client.post('/api', data=bytesVar)\n",
            "response = TestClient(app).post('/api', data=b'bytes')\n",
            "name = \"world\"\n",
            "response = client.post('/api', data=f'hello {name}')\n",
            "response = client.post('/api', headers={'X': 'v'}, data=b'bytes')\n",
        ));
        assert_eq!(ranges.len(), 11);
        // `data` on line 11: columns 31–35.
        assert_eq!(ranges[0].start, pos(11, 31));
        assert_eq!(ranges[0].end, pos(11, 35));
    }

    #[test]
    fn s8405_flags_fastapi_testclient_alias() {
        let ranges = found(concat!(
            "from fastapi import FastAPI\n",
            "from fastapi.testclient import TestClient as FastAPITestClient\n",
            "\n",
            "fastapi_app = FastAPI()\n",
            "fastapi_client = FastAPITestClient(fastapi_app)\n",
            "\n",
            "response = fastapi_client.post('/upload', data=b'\\x89PNG\\r\\n')\n",
            "response = fastapi_client.put('/api', data='text')\n",
        ));
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn s8405_accepts_the_sonar_compliant_examples() {
        assert!(
            found(concat!(
                "from starlette.testclient import TestClient\n",
                "from starlette.applications import Starlette\n",
                "import requests\n",
                "\n",
                "intVar = 1\n",
                "app = Starlette()\n",
                "client = TestClient(app)\n",
                "\n",
                "response = client.post('/api', content=b'raw bytes')\n",
                "response = client.put('/api', content='text content')\n",
                "response = client.post('/api', data={'field': 'value'})\n",
                "response = client.post('/api', json={'key': 'value'})\n",
                "response = client.get('/api')\n",
                "response = client.post('/api', data=None)\n",
                "response = client.post('/api', data=intVar)\n",
                "response = requests.post('/api', data=b'bytes')\n",
                "form_data = {'field': 'value'}\n",
                "response = client.post('/api', data=form_data)\n",
                "def get_some_data():\n",
                "    return {}\n",
                "unknown_variable = get_some_data()\n",
                "response = client.post('/api', data=unknown_variable)\n",
            ))
            .is_empty()
        );
    }
}
