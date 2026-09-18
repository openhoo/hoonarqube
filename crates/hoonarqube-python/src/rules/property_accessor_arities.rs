use crate::support::for_each_method;
use crate::support::has_decorator;
use crate::support::issue_at;
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
        // Sonar's countRequiredParameters counts only parameters without
        // defaults or star markers — `def num_feat(self, force=1)` is a
        // valid one-required-parameter getter.
        let actual = function
            .parameters
            .posonlyargs
            .iter()
            .chain(&function.parameters.args)
            .filter(|param| param.default.is_none())
            .count();
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

    #[test]
    fn s5724_ignores_optional_and_star_parameters_on_getters() {
        // Issue #623: Sonar's countRequiredParameters counts only parameters
        // without a default value or a star marker, so an optional parameter
        // does not make a property getter non-compliant (django/django
        // `num_feat(self, force=1)` repro: hq 3 vs sonar 0).
        for clean in [
            "class L:\n    @property\n    def num_feat(self, force=1):\n        return 1\n",
            "class L:\n    @property\n    def num_feat(self, *args):\n        return 1\n",
            "class L:\n    @property\n    def num_feat(self, **kwargs):\n        return 1\n",
            "class L:\n    @property\n    def num_feat(self, *, key=1):\n        return 1\n",
        ] {
            assert!(findings(&scan(clean), "python:S5724").is_empty(), "{clean}");
        }
        // A required extra parameter still makes the getter non-compliant even
        // when optional parameters are also present.
        let flagged = scan(
            "class L:\n    @property\n    def num_feat(self, extra, force=1):\n        return 1\n",
        );
        assert_eq!(findings(&flagged, "python:S5724").len(), 1);
    }
}
