use crate::engine::file_context::FileContext;
use crate::support::{child_bodies, issue_at, string_value_text};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt, StmtClassDef, StmtFunctionDef};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::{HashMap, HashSet};

const RULE_KEY: &str = "python:S8494";

/// Builtin types whose instances carry no `__dict__`: a class deriving only
/// from them cannot gain attributes beyond its `__slots__` either, so their
/// slots do not need to resolve (mirrors `BUILTIN_TYPES_WITHOUT_DICT`).
const BUILTIN_TYPES_WITHOUT_DICT: [&str; 17] = [
    "str",
    "int",
    "float",
    "bool",
    "bytes",
    "tuple",
    "frozenset",
    "range",
    "list",
    "set",
    "dict",
    "NoneType",
    "type",
    "super",
    "memoryview",
    "bytearray",
    "object",
];

/// python:S8494 — assigning to an attribute missing from a class's
/// `__slots__` raises `AttributeError` at runtime. Scope `ALL`.
///
/// Mirrors `SlotsAssignmentCheck`: for every class whose `__slots__`
/// resolves to a literal set of names (list/tuple/set/dict keys, a bare
/// string, or names singly assigned to string literals), every instance
/// method's `self.<attr>` assignment target is flagged when `<attr>` is
/// neither declared nor the name-mangled form of a declared private slot.
/// The issue anchors on the attribute name. Classes stay silent when
/// `__slots__` is absent or unresolvable, declares `__dict__`, or inherits
/// from a base that cannot be resolved lexically — imported bases and
/// attribute bases approximate the reference's `hasUnresolvedHierarchy`
/// bail-out, while bases defined in the same file contribute their own
/// slots recursively (builtin no-dict bases need none). Instance methods
/// are the undecorated functions with at least one positional parameter;
/// `@staticmethod`, `@classmethod`, and `__new__` are skipped, and the
/// first positional parameter supplies the `self` name. Assignments inside
/// nested functions or classes do not count.
pub(crate) fn check_slots_declared_attributes(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let classes: HashMap<&str, &StmtClassDef> = file_ctx
        .classes
        .iter()
        .map(|class| (class.name.as_str(), *class))
        .collect();
    let mut issues = Vec::new();
    for class in &file_ctx.classes {
        check_class(class, &classes, index, source, &mut issues);
    }
    issues
}

fn check_class(
    class: &StmtClassDef,
    classes: &HashMap<&str, &StmtClassDef>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let Some(own_slots) = extract_own_slots(class) else {
        return;
    };
    if own_slots.contains("__dict__") {
        return;
    }
    let mut allowed: HashSet<String> = own_slots;
    if !collect_ancestor_slots(class, classes, &mut allowed, &mut HashSet::new()) {
        return;
    }
    let class_name = class.name.as_str();
    for stmt in &class.body {
        let Stmt::FunctionDef(method) = stmt else {
            continue;
        };
        let Some(self_name) = instance_self_name(method) else {
            continue;
        };
        check_method_assignments(
            &method.body,
            self_name,
            &allowed,
            class_name,
            index,
            source,
            issues,
        );
    }
}

/// The first positional parameter name of an instance method: undecorated
/// (no `@staticmethod`/`@classmethod`), not `__new__`, with at least one
/// positional parameter.
fn instance_self_name(method: &StmtFunctionDef) -> Option<&str> {
    if method.name.as_str() == "__new__" {
        return None;
    }
    for decorator in &method.decorator_list {
        let target = match &decorator.expression {
            Expr::Call(call) => call.func.as_ref(),
            other => other,
        };
        if crate::support::dotted_name(target)
            .is_some_and(|path| path == "staticmethod" || path == "classmethod")
        {
            return None;
        }
    }
    method
        .parameters
        .posonlyargs
        .iter()
        .chain(&method.parameters.args)
        .next()
        .map(|arg| arg.parameter.name.as_str())
}

/// Flags `self.<attr>` assignment targets inside the method's own scope
/// (nested function and class bodies are skipped).
fn check_method_assignments(
    body: &[Stmt],
    self_name: &str,
    allowed: &HashSet<String>,
    class_name: &str,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let mut pending: Vec<&Stmt> = body.iter().rev().collect();
    while let Some(stmt) = pending.pop() {
        if matches!(stmt, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
            continue;
        }
        match stmt {
            Stmt::Assign(assign) => {
                for target in &assign.targets {
                    check_target(
                        target, self_name, allowed, class_name, index, source, issues,
                    );
                }
            }
            Stmt::AugAssign(aug) => {
                check_target(
                    &aug.target,
                    self_name,
                    allowed,
                    class_name,
                    index,
                    source,
                    issues,
                );
            }
            _ => {}
        }
        for suite in child_bodies(stmt) {
            pending.extend(suite.iter().rev());
        }
    }
}

/// Flags one assignment target when it is `self.<attr>` and `<attr>` is not
/// declared (directly or via the class's name-mangled private form).
/// Destructuring targets check each element (`self.x, self.y = ...` is one
/// `ExpressionList` of qualified expressions in the reference).
fn check_target(
    target: &Expr,
    self_name: &str,
    allowed: &HashSet<String>,
    class_name: &str,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    match target {
        Expr::Tuple(tuple) => {
            for elt in &tuple.elts {
                check_target(elt, self_name, allowed, class_name, index, source, issues);
            }
        }
        Expr::List(list) => {
            for elt in &list.elts {
                check_target(elt, self_name, allowed, class_name, index, source, issues);
            }
        }
        Expr::Starred(starred) => {
            check_target(
                &starred.value,
                self_name,
                allowed,
                class_name,
                index,
                source,
                issues,
            );
        }
        Expr::Attribute(attribute) => {
            if !matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == self_name)
            {
                return;
            }
            let attr = attribute.attr.as_str();
            if allowed.contains(attr) || allowed.contains(mangled_name(class_name, attr).as_str()) {
                return;
            }
            issues.push(issue_at(
                RULE_KEY,
                &format!("Add \"{attr}\" to the class's \"__slots__\"."),
                attribute.attr.range(),
                index,
                source,
            ));
        }
        _ => {}
    }
}

/// Python's name mangling: `__x` (not dunder) inside class `C` becomes
/// `_C__x` with leading underscores stripped from the class name.
fn mangled_name(class_name: &str, attr: &str) -> String {
    if attr.starts_with("__") && !attr.ends_with("__") {
        format!("_{}{}", class_name.trim_start_matches('_'), attr)
    } else {
        attr.to_string()
    }
}

/// The class's own `__slots__` names: the last `__slots__ = <expr>`
/// assignment in the class body, resolved to literal slot names; `None`
/// when absent or unresolvable.
fn extract_own_slots(class: &StmtClassDef) -> Option<HashSet<String>> {
    let mut slots = None;
    for stmt in &class.body {
        let Stmt::Assign(assign) = stmt else {
            continue;
        };
        let [Expr::Name(target)] = assign.targets.as_slice() else {
            continue;
        };
        if target.id.as_str() == "__slots__" {
            slots = extract_slot_names(&assign.value, &class.body);
        }
    }
    slots
}

/// Literal slot names of a `__slots__` value: list/tuple/set elements, dict
/// keys, or a bare string. Elements may be string literals or names singly
/// assigned to string literals in the class body.
fn extract_slot_names(value: &Expr, class_body: &[Stmt]) -> Option<HashSet<String>> {
    match value {
        Expr::StringLiteral(literal) => Some(HashSet::from([string_value_text(&literal.value)])),
        Expr::List(list) => extract_string_literals(list.elts.iter(), class_body),
        Expr::Tuple(tuple) => extract_string_literals(tuple.elts.iter(), class_body),
        Expr::Set(set) => extract_string_literals(set.elts.iter(), class_body),
        Expr::Dict(dict) => {
            let mut keys = Vec::new();
            for item in &dict.items {
                keys.push(item.key.as_ref()?);
            }
            extract_string_literals(keys.into_iter(), class_body)
        }
        _ => None,
    }
}

/// String literal text of every element; a `Name` element resolves through
/// its single assignment to a string literal in the class body. Any
/// unresolvable element fails the whole set.
fn extract_string_literals<'a>(
    elements: impl Iterator<Item = &'a Expr>,
    class_body: &[Stmt],
) -> Option<HashSet<String>> {
    let mut names = HashSet::new();
    for element in elements {
        match element {
            Expr::StringLiteral(literal) => {
                names.insert(string_value_text(&literal.value));
            }
            Expr::Name(name) => {
                let value = single_assigned_string(class_body, name.id.as_str())?;
                names.insert(value);
            }
            _ => return None,
        }
    }
    Some(names)
}

/// The text of `name`'s single plain assignment to a string literal
/// directly in the class body.
fn single_assigned_string(class_body: &[Stmt], name: &str) -> Option<String> {
    let mut found = None;
    for stmt in class_body {
        let Stmt::Assign(assign) = stmt else {
            continue;
        };
        let [Expr::Name(target)] = assign.targets.as_slice() else {
            continue;
        };
        if target.id.as_str() != name {
            continue;
        }
        if found.is_some() {
            return None;
        }
        let Expr::StringLiteral(literal) = assign.value.as_ref() else {
            return None;
        };
        found = Some(string_value_text(&literal.value));
    }
    found
}

/// Adds the slots of every ancestor resolvable in this file. Returns
/// `false` — mirroring `hasUnresolvedHierarchy` — when a base cannot be
/// resolved lexically (imported or attribute bases) or a base's own
/// `__slots__` is unresolvable. Builtin no-dict bases contribute nothing.
fn collect_ancestor_slots<'a>(
    class: &'a StmtClassDef,
    classes: &HashMap<&str, &'a StmtClassDef>,
    allowed: &mut HashSet<String>,
    visited: &mut HashSet<&'a str>,
) -> bool {
    let Some(arguments) = &class.arguments else {
        return true;
    };
    for base in &arguments.args {
        let Expr::Name(name) = base else {
            // Attribute or other base expressions are unresolvable
            // lexically — the reference bails on unresolved hierarchies.
            return false;
        };
        let base_name = name.id.as_str();
        if BUILTIN_TYPES_WITHOUT_DICT.contains(&base_name) {
            continue;
        }
        if base_name == class.name.as_str() || !visited.insert(base_name) {
            continue;
        }
        let Some(parent) = classes.get(base_name) else {
            return false;
        };
        let Some(parent_slots) = extract_own_slots(parent) else {
            return false;
        };
        allowed.extend(parent_slots);
        if !collect_ancestor_slots(parent, classes, allowed, visited) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S8494";

    /// Sonar's own pair: `self.age` is not in `__slots__` and flags on the
    /// attribute name; adding it to `__slots__` is clean.
    #[test]
    fn s8494_flags_sonar_example() {
        let flagged = scan(concat!(
            "class User:\n",
            "    __slots__ = ['name', 'email']\n",
            "\n",
            "    def __init__(self, name, email, age):\n",
            "        self.name = name\n",
            "        self.email = email\n",
            "        self.age = age\n",
        ));
        let hits = findings(&flagged, KEY);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].range.start.line, 7);
        assert_eq!(hits[0].range.start.column, 13);
        assert_eq!(hits[0].message, "Add \"age\" to the class's \"__slots__\".");
        let clean = scan(concat!(
            "class User:\n",
            "    __slots__ = ['name', 'email', 'age']\n",
            "\n",
            "    def __init__(self, name, email, age):\n",
            "        self.name = name\n",
            "        self.email = email\n",
            "        self.age = age\n",
        ));
        assert!(findings(&clean, KEY).is_empty());
    }

    /// Slot shapes (tuple/set/dict/string/name-bound), ancestor slots,
    /// mangled private names, destructuring, and augmented assignments.
    #[test]
    fn s8494_slot_shapes_and_inheritance() {
        let report = scan(concat!(
            "class Base:\n",
            "    __slots__ = ('base_attr',)\n",
            "\n",
            "class Child(Base):\n",
            "    __slots__ = {'own'}\n",
            "    def set(self, v):\n",
            "        self.base_attr = v\n",
            "        self.own = v\n",
            "        self.missing = v\n",
            "        self.missing += 1\n",
            "        self.a, self.b = v, v\n",
        ));
        let hits = findings(&report, KEY);
        assert_eq!(hits.len(), 4);
        let mangled = scan(concat!(
            "class C:\n",
            "    __slots__ = ['_C__hidden']\n",
            "    def set(self):\n",
            "        self.__hidden = 1\n",
            "        self.__other = 2\n",
        ));
        assert_eq!(findings(&mangled, KEY).len(), 1);
    }

    /// Negative controls: `__dict__` slots, unresolvable slots or bases,
    /// non-instance methods, nested scopes, and non-self attributes.
    #[test]
    fn s8494_negative_controls() {
        let clean = scan(concat!(
            "class WithDict:\n",
            "    __slots__ = ['x', '__dict__']\n",
            "    def set(self):\n",
            "        self.anything = 1\n",
            "\n",
            "class NoSlots:\n",
            "    def set(self):\n",
            "        self.anything = 1\n",
            "\n",
            "class Dynamic:\n",
            "    __slots__ = compute_slots()\n",
            "    def set(self):\n",
            "        self.anything = 1\n",
            "\n",
            "class Imported(imported.Base):\n",
            "    __slots__ = ['x']\n",
            "    def set(self):\n",
            "        self.anything = 1\n",
            "\n",
            "class Methods:\n",
            "    __slots__ = ['x']\n",
            "    @staticmethod\n",
            "    def stat(s):\n",
            "        s.anything = 1\n",
            "    @classmethod\n",
            "    def cls_method(cls):\n",
            "        cls.anything = 1\n",
            "    def set(self):\n",
            "        def nested():\n",
            "            self.anything = 1\n",
            "        other.anything = 1\n",
        ));
        assert!(findings(&clean, KEY).is_empty());
    }
}
