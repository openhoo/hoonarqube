use crate::support::for_each_method;
use crate::support::has_decorator;
use crate::support::issue_at;
use crate::support::positional_parameters;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

// --- python:S5724 — property accessor arity -----------------------------------

pub(crate) fn check_property_accessor_arities(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_method(parsed.syntax().body.as_slice(), &mut |_class, function| {
        let getter = has_decorator(function, "property");
        let setter = has_decorator(function, "setter");
        let deleter = has_decorator(function, "deleter");
        let required = if getter || deleter {
            1
        } else if setter {
            2
        } else {
            return;
        };
        let actual = positional_parameters(&function.parameters).len();
        if actual == required {
            return;
        }
        let message = if setter && actual < 2 {
            "Add the value parameter; property setter methods receive \"self\" and a value."
                .to_string()
        } else if getter && actual > 1 {
            format!(
                "Remove {} parameters; property getter methods receive only \"self\".",
                actual - 1
            )
        } else if deleter && actual > 1 {
            format!(
                "Remove {} parameters; property deleter methods receive only \"self\".",
                actual - 1
            )
        } else {
            "Add a \"self\" parameter to this property accessor.".to_string()
        };
        issues.push(issue_at(
            "python:S5724",
            &message,
            TextRange::new(
                function.name.start() - TextSize::new(4),
                function.parameters.end(),
            ),
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
