use crate::engine::file_context::FileContext;
use crate::support::base_tail_is;
use crate::support::class_base_paths;
use crate::support::issue_at;
use crate::support::meta_declares_fields;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_modelform_meta_fields(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
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
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6559_requires_meta_field_declarations() {
        let flagged = scan(concat!(
            "class FormF(forms.ModelForm):\n",
            "    class Meta:\n",
            "        model = M\n",
            "class Good(forms.ModelForm):\n",
            "    class Meta:\n",
            "        fields = [\"a\"]\n"
        ));
        assert_eq!(findings(&flagged, "python:S6559").len(), 1);
    }
}
