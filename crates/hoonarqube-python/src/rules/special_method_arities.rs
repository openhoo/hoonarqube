use crate::engine::file_context::FileContext;
use crate::support::for_each_method;
use crate::support::issue_at;
use crate::support::positional_parameters;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_special_method_arities(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    // Special methods dispatch through the class, so only class-body
    // definitions follow these tables; module-level dunder functions such as
    // the PEP 562 `__getattr__(name)` use their own module contracts.
    for_each_method(file_ctx.module_body, &mut |_class, function| {
        let Some(required) = required_special_method_arity(function.name.as_str()) else {
            return;
        };
        let actual = positional_parameters(&function.parameters).len();
        if function.name.as_str() == "__exit__"
            || function.parameters.vararg.is_some()
            || actual >= required
        {
            return;
        }
        issues.push(issue_at(
            "python:S5722",
            &format!(
                "Add {} parameters. Method {} should have {required} parameters.",
                required - actual,
                function.name
            ),
            function.name.range(),
            index,
            source,
        ));
    });
    issues
}

// --- python:S5722 — special method arity --------------------------------------

const ARITY_ONE_DUNDERS: [&str; 17] = [
    "__str__",
    "__repr__",
    "__len__",
    "__hash__",
    "__bool__",
    "__iter__",
    "__next__",
    "__enter__",
    "__dir__",
    "__index__",
    "__neg__",
    "__pos__",
    "__invert__",
    "__abs__",
    "__int__",
    "__float__",
    "__complex__",
];

const ARITY_TWO_DUNDERS: [&str; 40] = [
    "__add__",
    "__sub__",
    "__mul__",
    "__truediv__",
    "__floordiv__",
    "__mod__",
    "__pow__",
    "__lshift__",
    "__rshift__",
    "__and__",
    "__or__",
    "__xor__",
    "__eq__",
    "__ne__",
    "__lt__",
    "__le__",
    "__gt__",
    "__ge__",
    "__radd__",
    "__rsub__",
    "__rmul__",
    "__rtruediv__",
    "__rfloordiv__",
    "__rmod__",
    "__rpow__",
    "__rlshift__",
    "__rrshift__",
    "__rand__",
    "__ror__",
    "__rxor__",
    "__iadd__",
    "__isub__",
    "__imul__",
    "__contains__",
    "__getitem__",
    "__delitem__",
    "__delattr__",
    "__getattr__",
    "__getattribute__",
    "__delete__",
];

const ARITY_THREE_DUNDERS: [&str; 3] = ["__setitem__", "__setattr__", "__set_name__"];

fn required_special_method_arity(name: &str) -> Option<usize> {
    if ARITY_ONE_DUNDERS.contains(&name) {
        Some(1)
    } else if ARITY_TWO_DUNDERS.contains(&name) {
        Some(2)
    } else if ARITY_THREE_DUNDERS.contains(&name) {
        Some(3)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5722_flags_missing_special_method_parameters() {
        let flagged = scan("class C:\n    def __lt__(self):\n        return NotImplemented\n");
        assert_eq!(findings(&flagged, "python:S5722").len(), 1);
        let clean = "class C:\n    def __lt__(self, other):\n        return NotImplemented\n";
        assert!(findings(&scan(clean), "python:S5722").is_empty());
    }

    #[test]
    fn s5722_module_level_getattr_keeps_the_module_contract() {
        let module_dunder = "def __getattr__(name):\n    return name\n";
        assert!(findings(&scan(module_dunder), "python:S5722").is_empty());
        let flagged_class = "class C:\n    def __getattr__(self):\n        pass\n";
        assert_eq!(findings(&scan(flagged_class), "python:S5722").len(), 1);
        let clean_class = "class C:\n    def __getattr__(self, name):\n        return object.__getattribute__(self, name)\n";
        assert!(findings(&scan(clean_class), "python:S5722").is_empty());
    }

    #[test]
    fn s5722_delattr_requires_exactly_two_parameters() {
        let valid =
            "class C:\n    def __delattr__(self, name):\n        object.__delattr__(self, name)\n";
        assert!(findings(&scan(valid), "python:S5722").is_empty());
        let under_arity = "class C:\n    def __delattr__(self):\n        pass\n";
        assert_eq!(findings(&scan(under_arity), "python:S5722").len(), 1);
        let genuine_three = "class C:\n    def __setattr__(self):\n        pass\n";
        assert_eq!(findings(&scan(genuine_three), "python:S5722").len(), 1);
    }
}
