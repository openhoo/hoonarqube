use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::is_static_text_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1523 — dynamic code execution with user-controlled data -----------

pub(crate) fn check_s1523_dynamic_code_execution(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let dynamic_exec = matches!(called_name(&call.func), Some("eval" | "exec"))
            && !call
                .arguments
                .args
                .first()
                .is_some_and(is_static_text_literal);
        if dynamic_exec {
            issues.push(issue_at(
                "python:S1523",
                "Make sure that this dynamically executed code cannot be attacker-controlled.",
                call.range(),
                index,
                source,
            ));
        }
    });
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
}
