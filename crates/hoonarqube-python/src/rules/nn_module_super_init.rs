use crate::support::class_base_paths;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_in_scope;
use crate::support::is_super_init_call;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6978 — nn.Module initializer contract -----------------------------------

pub(crate) fn check_nn_module_super_init(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::ClassDef(class) = stmt {
            let module_subclass = class_base_paths(class)
                .iter()
                .any(|base| matches!(base.as_str(), "nn.Module" | "torch.nn.Module" | "Module"));
            let init = class.body.iter().find_map(|stmt| match stmt {
                Stmt::FunctionDef(function) if function.name.as_str() == "__init__" => {
                    Some(function)
                }
                _ => None,
            });
            let super_called = init.is_some_and(|function| {
                let mut found = false;
                for_each_stmt_in_scope(function.body.as_slice(), &mut |stmt| {
                    for expr in stmt_exprs(stmt) {
                        found |= is_super_init_call(expr);
                    }
                });
                found
            });
            if module_subclass && init.is_some() && !super_called {
                issues.push(issue_at(
                    "python:S6978",
                    "Call super().__init__() from this nn.Module subclass.",
                    class.name.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6978_requires_super_init_in_module_subclasses() {
        let flagged = scan(concat!(
            "class M(nn.Module):\n",
            "    def __init__(self):\n",
            "        self.layer = 1\n",
            "class Ok(nn.Module):\n",
            "    def __init__(self):\n",
            "        super().__init__()\n"
        ));
        assert_eq!(findings(&flagged, "python:S6978").len(), 1);
    }
}
