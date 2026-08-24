use crate::support::DJANGO_STRING_FIELDS;
use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::is_true_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_django_string_field_null(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if called_name(&call.func).is_some_and(|n| DJANGO_STRING_FIELDS.contains(&n))
            && keyword_value(&call.arguments, "null").is_some_and(is_true_literal)
        {
            issues.push(issue_at(
                "python:S6553",
                "String-based fields should use blank=True rather than null=True.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6553_rejects_null_on_string_fields() {
        let flagged = scan(
            "CharField(max_length=10, null=True)\nCharField(max_length=10)\nIntegerField(null=True)\n",
        );
        assert_eq!(findings(&flagged, "python:S6553").len(), 1);
    }
}
