use crate::engine::file_context::FileContext;
use crate::support::base_tail_is;
use crate::support::class_base_paths;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
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
            if !modelform {
                continue;
            }
            // The reference flags `exclude = ...` unconditionally and
            // `fields = "__all__"`; a missing Meta or missing fields is not
            // reported by this rule.
            let Some(meta) = class.body.iter().find_map(|inner| match inner {
                Stmt::ClassDef(meta) if meta.name.as_str() == "Meta" => Some(meta),
                _ => None,
            }) else {
                continue;
            };
            for inner in &meta.body {
                let Stmt::Assign(assign) = inner else {
                    continue;
                };
                let Some(Expr::Name(target)) = assign.targets.first() else {
                    continue;
                };
                let message = match target.id.as_str() {
                    "exclude" => Some(
                        r#"Set the fields of this form explicitly instead of using "exclude"."#,
                    ),
                    "fields" => matches!(
                        assign.value.as_ref(),
                        Expr::StringLiteral(literal)
                            if literal.value.to_str() == "__all__"
                    )
                    .then_some(
                        r#"Set the fields of this form explicitly instead of using "__all__"."#,
                    ),
                    _ => None,
                };
                if let Some(message) = message {
                    issues.push(issue_at(
                        "python:S6559",
                        message,
                        assign.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6559_flags_all_fields_and_exclude() {
        // `fields = "__all__"` and any `exclude` assignment are flagged; a
        // Meta without either, or no Meta at all, is not this rule's scope.
        let flagged = scan(concat!(
            "class FormF(forms.ModelForm):\n",
            "    class Meta:\n",
            "        model = M\n",
            "        fields = \"__all__\"\n",
            "class FormG(forms.ModelForm):\n",
            "    class Meta:\n",
            "        exclude = [\"secret\"]\n"
        ));
        assert_eq!(findings(&flagged, "python:S6559").len(), 2);
        let clean = scan(concat!(
            "class FormF(forms.ModelForm):\n",
            "    class Meta:\n",
            "        model = M\n",
            "class Good(forms.ModelForm):\n",
            "    class Meta:\n",
            "        fields = [\"a\"]\n",
            "class NoMeta(forms.ModelForm):\n",
            "    pass\n"
        ));
        assert!(findings(&clean, "python:S6559").is_empty());
    }
}
