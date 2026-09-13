use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::issue_at;
use crate::support::pep695_aliases_present;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_redundant_typevars(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    if !pep695_aliases_present(parsed) {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::Assign(assign) = stmt
            && let Expr::Call(call) = assign.value.as_ref()
            && called_name(&call.func) == Some("TypeVar")
        {
            issues.push(issue_at(
                "python:S6795",
                "PEP 695 syntax makes this TypeVar redundant.",
                assign.value.range(),
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
    fn s6795_flags_typevars_alongside_pep695_syntax() {
        let flagged = scan("T = TypeVar(\"T\")\ntype PairOf[T] = tuple[T, T]\n");
        assert_eq!(findings(&flagged, "python:S6795").len(), 1);
    }

    #[test]
    fn s6795_local_variable_named_type_does_not_activate_the_alias_gate() {
        // Issue #118: `type = "file"` binds an ordinary local; it is not a
        // PEP 695 alias declaration and must not enable the TypeVar gate.
        let clean = scan(concat!(
            "from typing import TypeVar\n",
            "T = TypeVar(\"T\")\n",
            "def kind():\n",
            "    type = \"file\"\n",
            "    return type\n",
            "assert kind() == \"file\"\n",
        ));
        assert!(findings(&clean, "python:S6795").is_empty());
    }

    #[test]
    fn s6795_real_alias_still_flags_typevars_despite_local_named_type() {
        let flagged = scan(concat!(
            "from typing import TypeVar\n",
            "T = TypeVar(\"T\")\n",
            "type Alias = int\n",
            "def kind():\n",
            "    type = \"file\"\n",
            "    return type\n",
        ));
        assert_eq!(findings(&flagged, "python:S6795").len(), 1);
    }
}
