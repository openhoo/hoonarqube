use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::positional_parameters;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_special_method_arities(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::FunctionDef(function) = stmt else {
            continue;
        };
        let Some(required) = required_special_method_arity(function.name.as_str()) else {
            continue;
        };
        if function.name.as_str() == "__exit__"
            || function.parameters.vararg.is_some()
            || positional_parameters(&function.parameters).len() >= required
        {
            continue;
        }
        let actual = positional_parameters(&function.parameters).len();
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
    }
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

const ARITY_TWO_DUNDERS: [&str; 39] = [
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
    "__getattr__",
    "__getattribute__",
    "__delete__",
];

const ARITY_THREE_DUNDERS: [&str; 4] =
    ["__setitem__", "__setattr__", "__delattr__", "__set_name__"];

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
}
