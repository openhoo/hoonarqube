use crate::support::for_each_method;
use crate::support::has_decorator;
use crate::support::issue_at;
use crate::support::positional_parameters;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5720 — `self` must be the first instance-method parameter --------

const EXEMPT_DUNDERS: [&str; 3] = ["__new__", "__init_subclass__", "__class_getitem__"];

pub(crate) fn check_instance_self_parameters(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_method(parsed.syntax().body.as_slice(), &mut |_class, function| {
        if has_decorator(function, "staticmethod") || has_decorator(function, "classmethod") {
            return;
        }
        // Dunder methods that conventionally take `cls` or no first param.
        if EXEMPT_DUNDERS.contains(&function.name.id.as_str()) {
            return;
        }
        if let Some(first) = positional_parameters(&function.parameters).first()
            && first.name.as_str() != "self"
        {
            issues.push(issue_at(
                "python:S5720",
                "Rename this first parameter to 'self'.",
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
    fn s5720_requires_self_first_for_instance_methods() {
        let flagged = scan("class C:\n    def show(this_one):\n        return this_one\n");
        assert_eq!(findings(&flagged, "python:S5720").len(), 1);
        let classmethod_clean =
            "class C:\n    @classmethod\n    def build(cls):\n        return cls\n";
        assert!(findings(&scan(classmethod_clean), "python:S5720").is_empty());
    }
}
