use crate::engine::file_context::FileContext;
use crate::support::exprs_textually_equal;
use crate::support::is_assignable_shape;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1656 — self-assignment ------------------------------------------

pub(crate) fn check_self_assignment(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        // Sonar exempts class-body assignments (the `Database = Database`
        // re-export idiom) and self-assignments of imported or builtin
        // names.
        if in_class_body(stmt, file_ctx) {
            continue;
        }
        match stmt {
            Stmt::Assign(assign) => {
                if assign.targets.iter().any(|target| {
                    is_assignable_shape(target)
                        && exprs_textually_equal(target, &assign.value, source)
                        && !is_exempt_name(target, file_ctx)
                }) {
                    let operator_start = assign
                        .targets
                        .last()
                        .map_or(assign.start(), ruff_text_size::Ranged::end);
                    let between = &source
                        [ruff_text_size::TextRange::new(operator_start, assign.value.start())];
                    let Some(relative) = between.find('=') else {
                        continue;
                    };
                    let equals = operator_start
                        + ruff_text_size::TextSize::from(crate::support::to_u32(relative));
                    issues.push(issue_at(
                        "python:S1656",
                        "Remove or correct this useless self-assignment.",
                        ruff_text_size::TextRange::new(
                            equals,
                            equals + ruff_text_size::TextSize::new(1),
                        ),
                        index,
                        source,
                    ));
                }
            }
            Stmt::AnnAssign(annotated) => {
                if let Some(value) = annotated.value.as_deref()
                    && is_assignable_shape(&annotated.target)
                    && exprs_textually_equal(&annotated.target, value, source)
                    && !is_exempt_name(&annotated.target, file_ctx)
                {
                    issues.push(issue_at(
                        "python:S1656",
                        "Remove or correct this useless self-assignment.",
                        annotated.range(),
                        index,
                        source,
                    ));
                }
            }
            _ => {}
        }
    }

    issues
}

/// Whether `stmt` sits directly inside a class body.
fn in_class_body(stmt: &Stmt, file_ctx: &FileContext) -> bool {
    file_ctx
        .classes
        .iter()
        .any(|class| class.body.iter().any(|member| std::ptr::eq(member, stmt)))
}

/// Self-assignment of a name bound by an import or naming a builtin is the
/// re-export idiom, not a defect.
fn is_exempt_name(target: &ruff_python_ast::Expr, file_ctx: &FileContext) -> bool {
    let ruff_python_ast::Expr::Name(name) = target else {
        return false;
    };
    if crate::support::is_builtin_name(name.id.as_str()) {
        return true;
    }
    file_ctx.imports.iter().any(|entry| match entry {
        crate::engine::file_context::AnyImport::Plain(import) => import.names.iter().any(|alias| {
            alias
                .asname
                .as_ref()
                .map_or_else(|| alias.name.as_str(), |asname| asname.as_str())
                == name.id.as_str()
        }),
        crate::engine::file_context::AnyImport::From(import) => import.names.iter().any(|alias| {
            alias
                .asname
                .as_ref()
                .map_or_else(|| alias.name.as_str(), |asname| asname.as_str())
                == name.id.as_str()
        }),
    })
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s1656_flags_self_assignment() {
        assert_eq!(findings(&scan("x = x\n"), "python:S1656").len(), 1);
        assert_eq!(findings(&scan("x.y = x.y\n"), "python:S1656").len(), 1);
        assert!(findings(&scan("x = y\n"), "python:S1656").is_empty());
    }

    #[test]
    fn s1656_exempts_class_body_and_imported_or_builtin_names() {
        // Issue #628: Sonar exempts self-assignments directly inside a class
        // body (the `Database = Database` re-export idiom) and self-assignments
        // of imported or builtin names; genuine self-assignments stay flagged.
        let report = scan(concat!(
            "import sqlite3 as Database\n",
            "\n",
            "class DatabaseWrapper:\n",
            "    Database = Database\n",
            "\n",
            "def f(field):\n",
            "    if field:\n",
            "        field = field.clone()\n",
            "    else:\n",
            "        field = field\n",
        ));
        let found = findings(&report, "python:S1656");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 10);
        assert_eq!(found[0].range.start.column, 14);

        // Class-body self-assignment is exempt even for unimported names.
        assert!(findings(&scan("class C:\n    x = x\n"), "python:S1656").is_empty());
        // Module-level self-assignment of an imported name is exempt.
        assert!(findings(&scan("import os\nos = os\n"), "python:S1656").is_empty());
        assert!(
            findings(
                &scan("from m import thing\nthing = thing\n"),
                "python:S1656"
            )
            .is_empty()
        );
        // ... and of a builtin name.
        assert!(findings(&scan("len = len\n"), "python:S1656").is_empty());
        // Annotated self-assignment of an imported name is exempt too.
        assert!(findings(&scan("import os\nos: int = os\n"), "python:S1656").is_empty());
        // Module-level self-assignment of an ordinary name stays flagged.
        assert_eq!(findings(&scan("x = x\n"), "python:S1656").len(), 1);
        // Self-assignment inside a method is not a class-body statement.
        assert_eq!(
            findings(
                &scan("class C:\n    def m(self, x):\n        x = x\n"),
                "python:S1656"
            )
            .len(),
            1
        );
    }
}
