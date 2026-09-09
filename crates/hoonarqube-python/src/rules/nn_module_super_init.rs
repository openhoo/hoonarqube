use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::dotted_name;
use crate::support::for_each_stmt_in_scope;
use crate::support::is_super_init_call;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6978 — nn.Module initializer contract -----------------------------------

pub(crate) fn check_nn_module_super_init(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::ClassDef(class) = stmt {
            let module_subclass = class_inherits_torch_module(class, file_ctx);
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
    }
    issues
}

fn class_inherits_torch_module(
    class: &ruff_python_ast::StmtClassDef,
    file_ctx: &FileContext<'_>,
) -> bool {
    class.bases().iter().any(|base| {
        let Some(path) = dotted_name(base) else {
            return false;
        };
        file_ctx.imports.iter().any(|entry| match entry {
            AnyImport::Plain(import) => import.names.iter().any(|alias| {
                let local = alias.asname.as_ref().map_or_else(
                    || alias.name.as_str().split('.').next().unwrap_or(""),
                    ruff_python_ast::Identifier::as_str,
                );
                alias.range().end() <= class.range().start()
                    && ((alias.name.as_str() == "torch"
                        && (path == format!("{local}.nn.Module")
                            || path == format!("{local}.nn.modules.module.Module")))
                        || (alias.name.as_str() == "torch.nn"
                            && if alias.asname.is_some() {
                                path == format!("{local}.Module")
                            } else {
                                path == "torch.nn.Module"
                                    || path == "torch.nn.modules.module.Module"
                            })
                        || (alias.name.as_str() == "torch.nn.modules.module"
                            && path == format!("{local}.Module")))
            }),
            AnyImport::From(import) => {
                let module = import
                    .module
                    .as_ref()
                    .map(ruff_python_ast::Identifier::as_str);
                import.names.iter().any(|alias| {
                    let local = alias
                        .asname
                        .as_ref()
                        .map_or_else(|| alias.name.as_str(), ruff_python_ast::Identifier::as_str);
                    alias.range().end() <= class.range().start()
                        && ((module == Some("torch")
                            && alias.name.as_str() == "nn"
                            && path == format!("{local}.Module"))
                            || (matches!(module, Some("torch.nn" | "torch.nn.modules.module"))
                                && alias.name.as_str() == "Module"
                                && path == local))
                })
            }
        })
    })
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6978_requires_super_init_in_module_subclasses() {
        let flagged = scan(concat!(
            "import torch.nn as nn\n",
            "class M(nn.Module):\n",
            "    def __init__(self):\n",
            "        self.layer = 1\n",
            "class Ok(nn.Module):\n",
            "    def __init__(self):\n",
            "        super().__init__()\n"
        ));
        assert_eq!(findings(&flagged, "python:S6978").len(), 1);
        assert!(
            findings(
                &scan("class Unknown(nn.Module):\n    def __init__(self):\n        pass\n"),
                "python:S6978"
            )
            .is_empty()
        );
    }
}
