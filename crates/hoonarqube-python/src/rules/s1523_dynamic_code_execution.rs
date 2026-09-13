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
    #[test]
    fn s1523_finds_dynamic_exec_in_every_executable_position() {
        // Issue #134: the shared expression inventory previously reported only
        // the direct call while silently dropping the identical call from an
        // assert message, an except selector, an f-string interpolation, and a
        // nested format spec, even though Python executes all five.
        let flagged = concat!(
            "value = 2\n",
            "eval(user_input)\n",
            "assert value, eval(user_input)\n",
            "try:\n",
            "    pass\n",
            "except eval(user_input):\n",
            "    pass\n",
            "first = f\"{eval(user_input)}\"\n",
            "second = f\"{first:{eval(user_input)}}\"\n",
        );
        assert_eq!(findings(&scan(flagged), "python:S1523").len(), 5);
    }

    #[test]
    fn s1523_keeps_non_executable_string_segments_opaque() {
        // Control: the literal text of the same call in assert messages and
        // f-strings is a value, not executable code, and stays unreported.
        let clean = concat!(
            "assert value, \"eval(user_input)\"\n",
            "first = f\"eval(user_input)\"\n",
            "try:\n",
            "    pass\n",
            "except ValueError:\n",
            "    pass\n",
        );
        assert!(findings(&scan(clean), "python:S1523").is_empty());
    }

    #[test]
    fn s1523_clears_imported_eval_identity_after_local_rebinding() {
        // Issue #135: exception aliases, walrus assignments, and match
        // captures rebind an imported eval alias to a user callable. Calls
        // before the rebinding keep the imported identity (exactly one
        // finding); calls after it resolve to the harmless rebinding.
        let exception_rebind = concat!(
            "from builtins import eval as run\n",
            "class Handler(Exception):\n",
            "    def __call__(self, value):\n",
            "        return value\n",
            "run(user_input)\n",
            "try:\n",
            "    raise Handler()\n",
            "except Handler as run:\n",
            "    run(user_input)\n",
        );
        assert_eq!(findings(&scan(exception_rebind), "python:S1523").len(), 1);

        let walrus_rebind = concat!(
            "from builtins import eval as execute\n",
            "execute(user_input)\n",
            "(execute := lambda value: value)\n",
            "execute(user_input)\n",
        );
        assert_eq!(findings(&scan(walrus_rebind), "python:S1523").len(), 1);

        let match_rebind = concat!(
            "from builtins import eval as evaluate\n",
            "evaluate(user_input)\n",
            "match probe():\n",
            "    case evaluate:\n",
            "        evaluate(user_input)\n",
        );
        assert_eq!(findings(&scan(match_rebind), "python:S1523").len(), 1);
    }

    #[test]
    fn s1523_keeps_imported_identity_without_local_rebinding() {
        // Controls: an untouched from-import alias keeps its API identity, and
        // a plain assignment rebinding (already modeled) clears it.
        let untouched = concat!("from builtins import eval as run\n", "run(user_input)\n",);
        assert_eq!(findings(&scan(untouched), "python:S1523").len(), 1);

        let plain_assign_rebind = concat!(
            "from builtins import eval as run\n",
            "run(user_input)\n",
            "run = lambda value: value\n",
            "run(user_input)\n",
        );
        assert_eq!(
            findings(&scan(plain_assign_rebind), "python:S1523").len(),
            1
        );

        let genuine_builtin = "eval(user_input)\n";
        assert_eq!(findings(&scan(genuine_builtin), "python:S1523").len(), 1);
    }
}
