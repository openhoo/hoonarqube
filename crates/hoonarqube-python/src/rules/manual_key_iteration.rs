use crate::support::expr_normalized_text;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7517 — manual key/value iteration ------------------------------------

pub(crate) fn check_manual_key_iteration(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::For(for_stmt) = stmt else { return };
        let Expr::Name(key) = for_stmt.target.as_ref() else {
            return;
        };
        let dict_text = expr_normalized_text(&for_stmt.iter, source);
        for_each_stmt_expr(&for_stmt.body, &mut |expr| {
            if let Expr::Subscript(subscript) = expr
                && expr_normalized_text(&subscript.value, source) == dict_text
                && matches!(subscript.slice.as_ref(), Expr::Name(lookup) if lookup.id.as_str() == key.id.as_str())
            {
                issues.push(issue_at(
                    "python:S7517",
                    "Use '.items()' instead of indexing with the loop variable.",
                    subscript.range(),
                    index,
                    source,
                ));
            }
        });
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s7517_flags_indexing_with_the_loop_key() {
        let flagged = scan("for key in settings:\n    print(settings[key])\n");
        let found = findings(&flagged, "python:S7517");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);

        // Every lookup through the loop key is reported individually.
        let repeated = scan("for key in stock:\n    total += stock[key]\n    audit(stock[key])\n");
        assert_eq!(findings(&repeated, "python:S7517").len(), 2);
    }

    #[test]
    fn s7517_stays_clean_outside_the_pattern() {
        for clean in [
            "for key, value in settings.items():\n    print(value)\n",
            "for key in settings:\n    print(cache[key])\n",
            "for key in settings:\n    print(settings.get(key))\n",
            "for key, value in pairs:\n    print(pairs[key])\n",
        ] {
            assert!(findings(&scan(clean), "python:S7517").is_empty(), "{clean}");
        }
    }
}
