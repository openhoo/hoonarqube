use crate::engine::file_context::FileContext;
use crate::support::base_tail_is;
use crate::support::class_base_paths;
use crate::support::class_defines_method;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_django_model_str(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::ClassDef(class) = stmt {
            let django_model = class_base_paths(class)
                .iter()
                .any(|base| base.as_str() == "models.Model" || base_tail_is(base, "Model"));
            // Sonar's DjangoModelStrMethodCheck skips abstract models via
            // getMetaClass — `class Meta: abstract = True` is exempt.
            let is_abstract = class.body.iter().any(|member| {
                let Stmt::ClassDef(meta) = member else {
                    return false;
                };
                if meta.name.as_str() != "Meta" {
                    return false;
                }
                meta.body.iter().any(|m| {
                    let Stmt::Assign(assign) = m else {
                        return false;
                    };
                    assign.targets.iter().any(|t| {
                        matches!(t, ruff_python_ast::Expr::Name(n) if n.id.as_str() == "abstract")
                    }) && matches!(assign.value.as_ref(), ruff_python_ast::Expr::BooleanLiteral(b) if b.value)
                })
            });
            if django_model && !is_abstract && !class_defines_method(class, "__str__") {
                issues.push(issue_at(
                    "python:S6554",
                    "Define __str__ on this Django model.",
                    class.name.range(),
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
    fn s6554_requires_str_on_django_models() {
        let flagged = scan(concat!(
            "class Book(models.Model):\n",
            "    title = models.CharField(max_length=5)\n",
            "class Shelf(models.Model):\n",
            "    def __str__(self):\n",
            "        return \"s\"\n"
        ));
        assert_eq!(findings(&flagged, "python:S6554").len(), 1);
    }
}
