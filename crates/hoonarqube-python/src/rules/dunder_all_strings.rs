use crate::support::is_dunder_all_target;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_dunder_all_strings(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in parsed.syntax().body.as_slice() {
        let assigned: Option<&Expr> = match stmt {
            Stmt::Assign(assign) => assign
                .targets
                .iter()
                .any(is_dunder_all_target)
                .then(|| assign.value.as_ref()),
            Stmt::AugAssign(assign) => {
                is_dunder_all_target(&assign.target).then(|| assign.value.as_ref())
            }
            _ => None,
        };
        let elements = match assigned {
            Some(Expr::List(list)) => &list.elts,
            Some(Expr::Set(set)) => &set.elts,
            Some(Expr::Tuple(tuple)) => &tuple.elts,
            _ => continue,
        };
        for element in elements {
            if !matches!(element, Expr::StringLiteral(_)) {
                issues.push(issue_at(
                    "python:S2823",
                    "Only string literals are allowed in '__all__'.",
                    element.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s2823_requires_string_literals_in_dunder_all() {
        let flagged = scan("__all__ = [\"a\", b]\n");
        let found = findings(&flagged, "python:S2823");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 1);
        for clean in ["__all__ = [\"a\", \"b\"]\n", "__all__ += [\"c\"]\n"] {
            assert!(findings(&scan(clean), "python:S2823").is_empty(), "{clean}");
        }
    }
}
