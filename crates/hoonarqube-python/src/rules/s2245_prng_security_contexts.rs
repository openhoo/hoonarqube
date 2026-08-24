use crate::support::PRNG_FUNCTIONS;
use crate::support::SECURITY_CONTEXT_WORDS;
use crate::support::called_name;
use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s2245_prng_security_contexts(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt {
            let security_named = function
                .name
                .as_str()
                .to_lowercase()
                .split('_')
                .any(|word| SECURITY_CONTEXT_WORDS.contains(&word));
            if !security_named {
                return;
            }
            for_each_call(function.body.as_slice(), &mut |call| {
                let uses_prng = PRNG_FUNCTIONS
                    .contains(&called_name(&call.func).unwrap_or_default())
                    || dotted_name(&call.func).is_some_and(|path| path.starts_with("random."));
                if uses_prng {
                    issues.push(issue_at(
                        "python:S2245",
                        "Use a cryptographically secure random generator in this security context.",
                        call.range(),
                        index,
                        source,
                    ));
                }
            });
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s2245_flags_prng_in_security_named_functions() {
        let flagged = concat!(
            "def make_token(user):\n",
            "    return random.randint(0, 999999)\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S2245").len(), 1);
        let clean = concat!(
            "def make_token(user):\n",
            "    return secrets.token_hex(32)\n",
            "def stats(sample):\n",
            "    return random.randint(0, 10)\n"
        );
        assert!(findings(&scan(clean), "python:S2245").is_empty());
    }
}
