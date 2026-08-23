use crate::support::base_tail_is;
use crate::support::class_base_paths;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::meta_declares_fields;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_modelform_meta_fields(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::ClassDef(class) = stmt {
            let modelform = class_base_paths(class)
                .iter()
                .any(|base| base.as_str() == "forms.ModelForm" || base_tail_is(base, "ModelForm"));
            let meta_ok = class.body.iter().any(|inner| {
                matches!(inner, Stmt::ClassDef(meta) if meta.name.as_str() == "Meta")
                    && matches!(inner, Stmt::ClassDef(meta) if meta_declares_fields(meta))
            });
            if modelform && !meta_ok {
                issues.push(issue_at(
                    "python:S6559",
                    "Declare fields or exclude on this ModelForm Meta.",
                    class.name.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}
