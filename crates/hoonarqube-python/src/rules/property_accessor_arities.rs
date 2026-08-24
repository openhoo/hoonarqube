use crate::support::for_each_method;
use crate::support::has_decorator;
use crate::support::issue_at;
use crate::support::positional_parameters;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5724 — property accessor arity -----------------------------------

pub(crate) fn check_property_accessor_arities(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_method(parsed.syntax().body.as_slice(), &mut |_class, function| {
        let required = if has_decorator(function, "property") {
            1
        } else if has_decorator(function, "setter") || has_decorator(function, "deleter") {
            2
        } else {
            return;
        };
        if positional_parameters(&function.parameters).len() == required {
            return;
        }
        issues.push(issue_at(
            "python:S5724",
            "Fix the parameter count of this property accessor.",
            function.name.range(),
            index,
            source,
        ));
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5724_checks_property_accessor_arity_exactly() {
        let flagged =
            scan("class C:\n    @property\n    def size(self, extra):\n        return 1\n");
        assert_eq!(findings(&flagged, "python:S5724").len(), 1);
        for clean in [
            "class C:\n    @property\n    def size(self):\n        return 1\n",
            "class C:\n    @size.setter\n    def size(self, value):\n        self._size = value\n",
        ] {
            assert!(findings(&scan(clean), "python:S5724").is_empty(), "{clean}");
        }
    }
}
