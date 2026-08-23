use crate::support::base_tail_is;
use crate::support::class_base_paths;
use crate::support::class_defines_method;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_django_model_str(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::ClassDef(class) = stmt {
            let django_model = class_base_paths(class)
                .iter()
                .any(|base| base.as_str() == "models.Model" || base_tail_is(base, "Model"));
            if django_model && !class_defines_method(class, "__str__") {
                issues.push(issue_at(
                    "python:S6554",
                    "Define __str__ on this Django model.",
                    class.name.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}
