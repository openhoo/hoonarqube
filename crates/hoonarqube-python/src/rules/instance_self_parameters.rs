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

/// `cls`/`mcs` are also allowed when the class might be a metaclass:
/// decorated classes, `type`/`Protocol` subclasses, or unresolved bases
/// (any base not defined in this file).
fn might_be_metaclass(class: &StmtClassDef, parsed: &Parsed<ModModule>) -> bool {
    let local_classes: std::collections::HashSet<&str> = {
        let mut names = std::collections::HashSet::new();
        for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
            if let Stmt::ClassDef(class) = stmt {
                names.insert(class.name.as_str());
            }
        });
        names
    };
    !class.decorator_list.is_empty()
        || class.arguments.as_deref().is_some_and(|arguments| {
            arguments.args.iter().any(|base| {
                let base_name = match base {
                    Expr::Name(name) => name.id.as_str(),
                    Expr::Attribute(attribute) => attribute.attr.as_str(),
                    _ => "",
                };
                matches!(base_name, "type" | "Protocol") || !local_classes.contains(base_name)
            })
        })
}

pub(crate) fn check_instance_self_parameters(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    // Nested classes are skipped by the reference (they may use a different
    // receiver name to avoid confusion).
    let mut nested_ranges = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::ClassDef(class) = stmt {
            for member in &class.body {
                if let Stmt::ClassDef(nested) = member {
                    nested_ranges.push(nested.range());
                }
            }
        }
    });
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::ClassDef(class) = stmt else {
            return;
        };
        if nested_ranges.contains(&class.range()) {
            return;
        }
        check_class_methods(class, parsed, index, source, &mut issues);
    });
    issues
}

/// Flags each method in `class` whose first parameter is not `self`/`_`/
/// `cls`/`mcs` under the reference's exemptions.
fn check_class_methods(
    class: &StmtClassDef,
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let metaclass = might_be_metaclass(class, parsed);
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
        // A name used elsewhere in the class body (decorator references,
        // rebinding wrappers) is exempt in the reference.
        if function_used_in_class_body(class, &function.name.id) {
            continue;
        }
        if let Some(first) = positional_parameters(&function.parameters).first() {
            let first_name = first.name.as_str();
            // `_` is a conventional "unused receiver" name; `cls`/`mcs`
            // are allowed when the class might be a metaclass or the
            // method carries any decorator (e.g. `@property` on enum
            // metaclasses).
            let cls_allowed = matches!(first_name, "cls" | "mcs")
                && (metaclass || !function.decorator_list.is_empty());
            if first_name == "self" || first_name == "_" || cls_allowed {
                continue;
            }
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
}

/// Whether the method name is referenced by a non-def statement in the class
/// body (e.g. `make = classmethod(make)` or decorator expressions).
fn function_used_in_class_body(class: &StmtClassDef, name: &str) -> bool {
    class.body.iter().any(|member| {
        if matches!(member, Stmt::FunctionDef(_)) {
            return false;
        }
        let mut found = false;
        for expr in crate::support::stmt_exprs(member) {
            let mut pending = vec![expr];
            while let Some(expr) = pending.pop() {
                if matches!(expr, Expr::Name(n) if n.id.as_str() == name) {
                    found = true;
                }
                pending.extend(crate::support::child_exprs(expr));
            }
        }
        found
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
        // The reference exempts any usage whose ancestor is the class body,
        // including rebinding under a different name.
        let renamed_binding =
            "class C:\n    def make(cls):\n        return cls\n    other = classmethod(make)\n";
        assert!(findings(&scan(renamed_binding), "python:S5720").is_empty());
    }
}
