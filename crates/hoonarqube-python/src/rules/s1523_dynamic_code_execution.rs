use crate::engine::bindings::KnownBinding;
use crate::engine::file_context::FileContext;
use crate::support::is_static_text_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1523 — dynamic code execution with user-controlled data -----------

pub(crate) fn check_s1523_dynamic_code_execution(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let dynamic_exec = matches!(
            file_ctx.known_bindings.resolve_call(call),
            KnownBinding::BuiltinEval | KnownBinding::BuiltinExec
        ) && !call
            .arguments
            .args
            .first()
            .is_some_and(is_static_text_literal);
        if dynamic_exec {
            issues.push(issue_at(
                "python:S1523",
                "Make sure that this dynamic injection or execution of code is safe.",
                call.range(),
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
    fn s1523_flags_dynamic_code_execution_on_variables() {
        let flagged = "result = eval(user_input)\nexec(code_var)\n";
        assert_eq!(findings(&scan(flagged), "python:S1523").len(), 2);
        assert!(findings(&scan("value = eval(\"2 + 2\")\n"), "python:S1523").is_empty());
    }
    #[test]
    fn s1523_resolves_builtin_identity_without_method_name_guessing() {
        let flagged = concat!(
            "from builtins import eval as evaluate\n",
            "evaluate(user_input)\n",
            "eval(user_input)\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S1523").len(), 2);
        let clean = concat!(
            "class Calculator:\n",
            "    def eval(self, value):\n",
            "        return value\n",
            "Calculator().eval(user_input)\n",
            "def eval(value):\n",
            "    return value\n",
            "eval(user_input)\n",
            "import ast\n",
            "ast.literal_eval(user_input)\n"
        );
        assert!(findings(&scan(clean), "python:S1523").is_empty());
        let deferred_body = "def eval(value):\n    return eval(value)\n";
        assert!(findings(&scan(deferred_body), "python:S1523").is_empty());
        let default_expression = "def eval(value=eval(source)):\n    return value\n";
        assert_eq!(findings(&scan(default_expression), "python:S1523").len(), 1);
    }
}
