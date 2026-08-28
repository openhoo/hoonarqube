use crate::support::for_each_method;
use crate::support::has_decorator;
use crate::support::issue_at;
use crate::support::positional_parameters;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2710 — classmethod first argument naming --------------------------

pub(crate) fn check_classmethod_parameter_names(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_method(parsed.syntax().body.as_slice(), &mut |_class, function| {
        if !has_decorator(function, "classmethod") {
            return;
        }
        if let Some(first) = positional_parameters(&function.parameters).first()
            && !matches!(first.name.as_str(), "cls" | "mcs" | "metacls")
        {
            issues.push(issue_at(
                "python:S2710",
                &format!(
                    "Rename \"{}\" to a valid class parameter name or add the missing class parameter.",
                    first.name
                ),
                first.name.range(),
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
    fn s2710_requires_cls_naming_for_classmethods() {
        let flagged =
            scan("class C:\n    @classmethod\n    def make(other):\n        return other\n");
        assert_eq!(findings(&flagged, "python:S2710").len(), 1);
        let clean = "class C:\n    @classmethod\n    def make(cls):\n        return cls\n";
        assert!(findings(&scan(clean), "python:S2710").is_empty());
    }
}
