use crate::support::for_each_stmt;
use crate::support::has_decorator;
use crate::support::issue_at;
use crate::support::positional_parameters;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_ast::StmtClassDef;
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
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::ClassDef(class) = stmt else {
            return;
        };
        // Metaclass methods receive the class they create, so a `cls` first
        // parameter is correct exactly as in a classmethod.
        let metaclass = is_metaclass(class);
        // A later `name = classmethod(name)` in the same body class-binds the
        // function, making its `cls` parameter correct.
        let deferred_classmethods = deferred_classmethod_names(class);
        for member in &class.body {
            let Stmt::FunctionDef(function) = member else {
                continue;
            };
            if has_decorator(function, "staticmethod") || has_decorator(function, "classmethod") {
                continue;
            }
            // Dunder methods that conventionally take `cls` or no first param.
            if EXEMPT_DUNDERS.contains(&function.name.id.as_str()) {
                continue;
            }
            if deferred_classmethods.contains(&function.name.id.as_str()) {
                continue;
            }
            if let Some(first) = positional_parameters(&function.parameters).first()
                && first.name.as_str() != "self"
                && !(metaclass && first.name.as_str() == "cls")
            {
                issues.push(issue_at(
                    "python:S5720",
                    &format!(
                        "Rename \"{}\" to \"self\" or add the missing \"self\" parameter.",
                        first.name
                    ),
                    first.name.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}

/// Whether the class directly inherits from `type` and therefore defines
/// metaclass methods whose first parameter receives the created class.
fn is_metaclass(class: &StmtClassDef) -> bool {
    class.arguments.as_deref().is_some_and(|arguments| {
        arguments.args.iter().any(|base| match base {
            Expr::Name(name) => name.id.as_str() == "type",
            Expr::Attribute(attribute) => attribute.attr.as_str() == "type",
            _ => false,
        })
    })
}

/// Names bound by a deferred `name = classmethod(name)` wrapper in the same
/// class body.
fn deferred_classmethod_names(class: &StmtClassDef) -> Vec<&str> {
    let mut names = Vec::new();
    for member in &class.body {
        let Stmt::Assign(assign) = member else {
            continue;
        };
        let [Expr::Name(target)] = assign.targets.as_slice() else {
            continue;
        };
        let Expr::Call(call) = assign.value.as_ref() else {
            continue;
        };
        if !matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "classmethod") {
            continue;
        }
        let Some(Expr::Name(bound)) = call.arguments.args.first() else {
            continue;
        };
        if target.id.as_str() == bound.id.as_str() {
            names.push(target.id.as_str());
        }
    }
    names
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
    #[test]
    fn s5720_dunder_new_is_exempt() {
        let flagged =
            scan("class C:\n    def __new__(cls):\n        return super().__new__(cls)\n");
        assert!(findings(&flagged, "python:S5720").is_empty());
    }

    #[test]
    fn s5720_dunder_init_subclass_is_exempt() {
        let flagged = scan("class C:\n    def __init_subclass__(cls):\n        pass\n");
        assert!(findings(&flagged, "python:S5720").is_empty());
    }

    #[test]
    fn s5720_metaclass_cls_methods_are_clean() {
        let metaclass = "class Meta(type):\n    def __instancecheck__(cls, instance):\n        return True\n\n\nclass C(metaclass=Meta):\n    pass\n";
        assert!(findings(&scan(metaclass), "python:S5720").is_empty());
        let flagged_in_metaclass =
            "class Meta(type):\n    def create(this_one):\n        return this_one\n";
        assert_eq!(
            findings(&scan(flagged_in_metaclass), "python:S5720").len(),
            1
        );
        let ordinary = "class C:\n    def show(this_one):\n        return this_one\n";
        assert_eq!(findings(&scan(ordinary), "python:S5720").len(), 1);
    }

    #[test]
    fn s5720_deferred_classmethod_assignment_is_recognized() {
        let deferred =
            "class C:\n    def make(cls):\n        return cls\n    make = classmethod(make)\n";
        assert!(findings(&scan(deferred), "python:S5720").is_empty());
        let unbound = "class C:\n    def make(cls):\n        return cls\n";
        assert_eq!(findings(&scan(unbound), "python:S5720").len(), 1);
        let renamed_binding =
            "class C:\n    def make(cls):\n        return cls\n    other = classmethod(make)\n";
        assert_eq!(findings(&scan(renamed_binding), "python:S5720").len(), 1);
    }
}
