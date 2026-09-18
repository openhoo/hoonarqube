use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_unreachable_test_methods(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut fixtures = std::collections::HashSet::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::FunctionDef(function) = *stmt
            && function.decorator_list.iter().any(|d| {
                let range = d.expression.range();
                let text = &source[range.start().to_usize()..range.end().to_usize()];
                text == "pytest.fixture" || text == "fixture"
            })
        {
            fixtures.insert(function.name.to_string());
        }
    }
    for stmt in &file_ctx.stmts {
        let Stmt::ClassDef(class) = stmt else {
            continue;
        };
        if !class.bases().iter().any(is_test_case_base) {
            continue;
        }
        let method_ranges: Vec<_> = class
            .body
            .iter()
            .filter_map(|member| match member {
                Stmt::FunctionDef(function) => Some(function.range()),
                _ => None,
            })
            .collect();
        let used = referenced_attributes(file_ctx, &method_ranges, class.name.as_str());
        for member in &class.body {
            if let Stmt::FunctionDef(function) = member {
                let name = function.name.as_str();
                if name.contains("test")
                    && !name.starts_with("test")
                    && is_sonar_helper(function, &fixtures)
                    && !used.contains(name)
                {
                    issues.push(issue_at(
                        "python:S5899",
                        "Rename this method so that it starts with \"test\" or remove this unused helper.",
                        function.name.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    }
    issues
}

/// Sonar's helper predicate: no decorators, and every parameter is
/// `self`/`cls` or a known fixture name.
fn is_sonar_helper(
    function: &ruff_python_ast::StmtFunctionDef,
    fixtures: &std::collections::HashSet<String>,
) -> bool {
    if !function.decorator_list.is_empty() {
        return false;
    }
    let params = &function.parameters;
    params
        .posonlyargs
        .iter()
        .chain(&params.args)
        .chain(&params.kwonlyargs)
        .all(|param| {
            let name = param.parameter.name.as_str();
            name == "self" || name == "cls" || fixtures.contains(name)
        })
}

/// Attribute names referenced as `self.X`, `cls.X`, or `ClassName.X` inside
/// the class's own method definitions. Sonar's
/// `NotDiscoverableTestMethodCheck` only reports a suspicious method when no
/// usage of it sits inside one of those definitions; usages elsewhere in the
/// file (module level, other classes, subclasses) do not exempt it.
fn referenced_attributes<'a>(
    file_ctx: &'a FileContext<'a>,
    method_ranges: &[ruff_text_size::TextRange],
    class_name: &str,
) -> std::collections::HashSet<&'a str> {
    let mut used = std::collections::HashSet::new();
    for expr in &file_ctx.exprs {
        let Expr::Attribute(attribute) = expr else {
            continue;
        };
        let Expr::Name(base) = attribute.value.as_ref() else {
            continue;
        };
        if !matches!(base.id.as_str(), "self" | "cls") && base.id.as_str() != class_name {
            continue;
        }
        if method_ranges
            .iter()
            .any(|range| range.contains_range(expr.range()))
        {
            used.insert(attribute.attr.as_str());
        }
    }
    used
}
// --- python:S5899 — unreachable test methods ------------------------------------

fn is_test_case_base(expr: &Expr) -> bool {
    let tail = match expr {
        Expr::Name(name) => Some(name.id.as_str()),
        Expr::Attribute(attribute) => Some(attribute.attr.as_str()),
        _ => None,
    };
    matches!(tail, Some(base) if base.ends_with("TestCase"))
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    // Sonar only reports a suspicious method when nothing inside the class's
    // own method definitions references it (NotDiscoverableTestMethodCheck).
    #[test]
    fn s5899_exempts_helpers_referenced_inside_the_class() {
        for used in [
            concat!(
                "class T(TestCase):\n",
                "    def my_test(self):\n",
                "        pass\n",
                "    def test_it(self):\n",
                "        self.my_test()\n",
            ),
            concat!(
                "class T(TestCase):\n",
                "    def my_test(self):\n",
                "        pass\n",
                "    def test_it(self):\n",
                "        self.run(self.my_test)\n",
            ),
            concat!(
                "class T(TestCase):\n",
                "    def my_test(self):\n",
                "        pass\n",
                "    def test_it(self):\n",
                "        T.my_test(self)\n",
            ),
            // Sonar counts usages inside the candidate's own definition.
            concat!(
                "class T(TestCase):\n",
                "    def my_test(self):\n",
                "        self.my_test()\n",
            ),
        ] {
            assert!(findings(&scan(used), "python:S5899").is_empty(), "{used}");
        }
    }

    #[test]
    fn s5899_still_flags_methods_only_used_outside_the_class() {
        // Sonar ignores usages outside the class's own method definitions.
        for flagged in [
            concat!(
                "class T(TestCase):\n",
                "    def my_test(self):\n",
                "        pass\n",
                "def caller():\n",
                "    T().my_test()\n",
            ),
            concat!(
                "class T(TestCase):\n",
                "    def my_test(self):\n",
                "        pass\n",
                "class Child(T):\n",
                "    def test_it(self):\n",
                "        self.my_test()\n",
            ),
        ] {
            assert_eq!(
                findings(&scan(flagged), "python:S5899").len(),
                1,
                "{flagged}"
            );
        }
    }
}
