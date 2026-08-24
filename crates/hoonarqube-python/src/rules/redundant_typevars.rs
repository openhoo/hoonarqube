use crate::support::called_name;
use crate::support::for_each_stmt;
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
) -> Vec<Issue> {
    if !pep695_aliases_present(parsed, source) {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
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
    });
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
}
