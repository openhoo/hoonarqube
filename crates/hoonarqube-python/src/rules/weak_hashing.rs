use crate::engine::bindings::KnownBinding;
use crate::engine::file_context::FileContext;
use crate::support::is_false_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_weak_hashing(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let bounded = bounded_digest_calls(file_ctx);
    let callees: std::collections::HashMap<_, _> = file_ctx
        .calls
        .iter()
        .map(|call| (call.func.range(), *call))
        .collect();
    for expr in &file_ctx.exprs {
        if !matches!(expr, Expr::Name(_) | Expr::Attribute(_)) {
            continue;
        }
        // Hashlib's imported function symbol itself is the reference site:
        // assigning it to a new variable reports the RHS, while the new
        // variable's later calls have no imported FQN and stay conservative.
        let identity = file_ctx.known_bindings.resolve_expr_identity(expr);
        let call = callees.get(&expr.range()).copied();
        let weak_direct = identity == KnownBinding::HashlibWeakHash;
        let weak_named_new = identity == KnownBinding::HashlibNew
            && call.is_some_and(|call| {
                call.arguments
                    .args
                    .first()
                    .or_else(|| keyword_value(&call.arguments, "name"))
                    .and_then(string_literal_text)
                    .is_some_and(|name| matches!(name.as_str(), "md5" | "sha1" | "sha224"))
            });
        if !(weak_direct || weak_named_new)
            || call.is_some_and(|call| {
                hash_call_is_exempt(call) || (weak_direct && bounded.contains(&call.range()))
            })
        {
            continue;
        }
        let range = if weak_direct {
            match expr {
                Expr::Attribute(attribute) => attribute.attr.range,
                _ => expr.range(),
            }
        } else {
            expr.range()
        };
        issues.push(issue_at(
            "python:S4790",
            "Make sure that hashing data is safe here.",
            range,
            index,
            source,
        ));
    }
    issues
}

/// Keep the reference's short fingerprint exemption distinct from full
/// digests. Only an immediately consumed, statically bounded slice qualifies;
/// unknown bounds and full MD5/SHA1 hex digests remain findings. The bound
/// and optional digest forms follow `SonarSource` sonar-python f4ab8a54,
/// HashingDataCheck.isBoundedSlice / isHashlibCallConsumedByBoundedSlice.
fn bounded_digest_calls(
    file_ctx: &FileContext,
) -> std::collections::HashSet<ruff_text_size::TextRange> {
    let mut calls = std::collections::HashSet::new();
    for expr in &file_ctx.exprs {
        let Expr::Subscript(subscript) = expr else {
            continue;
        };
        let Expr::Slice(slice) = subscript.slice.as_ref() else {
            continue;
        };
        let bounded = slice.upper.as_deref().is_some_and(small_positive_integer)
            || (slice.upper.is_none() && slice.step.is_none()
                && slice.lower.as_deref().is_some_and(|lower| {
                    matches!(lower, Expr::UnaryOp(unary) if unary.op == ruff_python_ast::UnaryOp::USub && small_positive_integer(&unary.operand))
                }));
        if !bounded {
            continue;
        }
        let Expr::Call(call) = subscript.value.as_ref() else {
            continue;
        };
        let hash = match call.func.as_ref() {
            Expr::Attribute(method) if matches!(method.attr.as_str(), "digest" | "hexdigest") => {
                let Expr::Call(hash) = method.value.as_ref() else {
                    continue;
                };
                hash
            }
            _ => call,
        };
        calls.insert(hash.range());
    }
    calls
}

fn small_positive_integer(expr: &Expr) -> bool {
    matches!(expr, Expr::NumberLiteral(number)
        if matches!(&number.value, ruff_python_ast::Number::Int(value)
            if value.as_i64().is_some_and(|value| (1..=16).contains(&value))))
}

// --- python:S4790 — weak hashing algorithms -----------------------------------

fn hash_call_is_exempt(call: &ruff_python_ast::ExprCall) -> bool {
    keyword_value(&call.arguments, "usedforsecurity").is_some_and(is_false_literal)
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s4790_resolves_import_aliases_and_reports_callable_references() {
        let source = concat!(
            "import hashlib as hashes\n",
            "from hashlib import md5 as digest, new as build_hash\n",
            "alias = digest\n",
            "hashes.sha1(b'data')\n",
            "digest(b'data')\n",
            "alias(b'data')\n",
            "build_hash('sha224')\n",
        );
        let report = scan(source);
        let found = findings(&report, "python:S4790");
        assert_eq!(found.len(), 4);
        assert_eq!(
            found
                .iter()
                .map(|issue| issue.range.start.line)
                .collect::<Vec<_>>(),
            vec![3, 4, 5, 7]
        );
    }

    #[test]
    fn s4790_preserves_shadowed_and_unrelated_hash_names() {
        let source = concat!(
            "def md5(value):\n    return value\n",
            "def new(value):\n    return value\n",
            "md5(b'data')\nnew('md5')\n",
            "import hashlib\n",
            "def calculate(hashlib):\n    return hashlib.md5(b'data')\n",
            "hashlib = object()\nhashlib.sha1(b'data')\n",
        );
        assert!(findings(&scan(source), "python:S4790").is_empty());
    }

    #[test]
    fn s4790_resolves_keyword_algorithm_and_preserves_exact_reference_names() {
        let source = concat!(
            "import hashlib\n",
            "hashlib.new(name='md5')\n",
            "hashlib.new('SHA224')\n",
            "hashlib.new('sha')\n",
            "hashlib.new('sha512')\n",
        );
        let report = scan(source);
        let found = findings(&report, "python:S4790");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
        assert_eq!(found[0].range.start.column, 0);
    }

    #[test]
    fn s4790_matches_werkzeug_bounded_digest_exemption() {
        // Werkzeug 3.1.3, debug/__init__.py:45: the real Sonar analyzer
        // excludes the 12-character SHA1 fingerprint but reports the full
        // digest at debug/__init__.py:196 and ETag at http.py:981.
        let source = concat!(
            "import hashlib\n",
            "hashlib.sha1(b'pin added salt').hexdigest()[:12]\n",
            "hashlib.md5(b'data').digest()[-8:]\n",
            "hashlib.sha224(b'data')[:16]\n",
            "hashlib.sha1(b'data').hexdigest()\n",
            "hashlib.md5(b'data').hexdigest()[:32]\n",
            "hashlib.sha1(b'data').hexdigest()[:limit]\n",
        );
        let report = scan(source);
        let found = findings(&report, "python:S4790");
        assert_eq!(found.len(), 3);
        assert_eq!(
            found
                .iter()
                .map(|issue| issue.range.start.line)
                .collect::<Vec<_>>(),
            vec![5, 6, 7]
        );
    }

    #[test]
    fn s4790_keeps_alias_security_exemptions_and_strong_algorithms() {
        let source = concat!(
            "import hashlib as hashes\n",
            "from hashlib import md5 as digest, new as build_hash\n",
            "digest(b'data', usedforsecurity=False)\n",
            "hashes.sha1(b'data', usedforsecurity=False)\n",
            "hashes.sha256(b'data')\n",
            "build_hash('sha512')\n",
        );
        assert!(findings(&scan(source), "python:S4790").is_empty());
    }
}
