use crate::support::for_each_stmt;
use crate::support::for_each_stmt_in_scope;
use crate::support::is_none_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2734 — `__init__` returning a value ------------------------------

pub(crate) fn check_init_return_values(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && function.name.as_str() == "__init__"
        {
            for_each_stmt_in_scope(&function.body, &mut |inner| {
                if let Stmt::Return(returned) = inner
                    && let Some(value) = returned.value.as_deref()
                    && !is_none_literal(value)
                {
                    issues.push(issue_at(
                        "python:S2734",
                        "Remove this 'return'; '__init__' cannot return a value.",
                        returned.range(),
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
    fn s2734_flags_init_returning_value() {
        let flagged =
            scan("class C:\n    def __init__(self):\n        self.x = 1\n        return 5\n");
        let found = findings(&flagged, "python:S2734");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 4);
        let clean = "class C:\n    def __init__(self):\n        self.x = 1\n        return None\n";
        assert!(findings(&scan(clean), "python:S2734").is_empty());
    }
}
