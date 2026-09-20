use std::collections::HashSet;
use std::path::Path;

use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt, StmtClassDef, StmtFunctionDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextSize};

use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::to_pos;
use crate::support::{ImportFqns, WebFrameworkFacts};
use crate::support::{is_pytest_file_name, is_test_scope_file};

const RULE_KEY: &str = "python:S2187";
const CLASS_MESSAGE: &str = "Add some tests to this class.";
const FILE_MESSAGE: &str = "Add some tests to this file.";

/// xUnit-style lifecycle methods that mark a `Test*` class as a real test
/// scaffold — the reference's `PYTEST_LIFECYCLE_METHODS`.
const PYTEST_LIFECYCLE_METHODS: &[&str] = &[
    "setUp",
    "tearDown",
    "setUpClass",
    "tearDownClass",
    "setup_method",
    "teardown_method",
    "setup_class",
    "teardown_class",
    "setup_module",
    "teardown_module",
];

/// python:S2187 (TEST scope) — a pytest-named file with no collected tests,
/// or a collected test class (`Test*` with lifecycle methods, or a
/// `unittest.TestCase` subclass) that declares no `test*` methods and
/// inherits none, misleads readers into believing behavior is verified.
/// Shared base classes, mixins, abstract classes, and placeholder-only
/// classes stay silent.
pub(crate) fn check_s2187_test_cases_contain_tests(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    path: &Path,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    if !is_test_scope_file(path) {
        return Vec::new();
    }
    let pytest_file = is_pytest_file_name(path);
    let facts = WebFrameworkFacts::build(file_ctx);
    let fqns = ImportFqns::build(file_ctx);
    let module = parsed.syntax().body.as_slice();

    let classes: Vec<&StmtClassDef> = module
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::ClassDef(class) => Some(class),
            _ => None,
        })
        .collect();
    let has_tests: Vec<bool> = classes
        .iter()
        .map(|class| has_collected_tests(class, &facts))
        .collect();

    let module_has_tests = module.iter().any(|stmt| match stmt {
        Stmt::FunctionDef(function) => is_test_method_name(function.name.as_str()),
        _ => false,
    });
    let any_tests = module_has_tests || has_tests.iter().any(|has| *has);
    if pytest_file && !any_tests {
        return vec![file_issue(index, source)];
    }

    let mut issues = Vec::new();
    for (idx, class) in classes.iter().enumerate() {
        if has_tests[idx] || !is_candidate_test_class(class, pytest_file, &facts, &fqns) {
            continue;
        }
        if has_descendant_with_tests(class, &classes, &has_tests, &facts) {
            continue;
        }
        if is_likely_shared_base(class, &facts, &fqns) {
            continue;
        }
        issues.push(issue_at(
            RULE_KEY,
            CLASS_MESSAGE,
            class.name.range(),
            index,
            source,
        ));
    }
    issues
}

/// The file-level finding for a pytest-named file with no collected tests,
/// anchored at offset zero like the reference's `addFileIssue`.
fn file_issue(index: &LineIndex, source: &str) -> Issue {
    Issue {
        rule_key: RULE_KEY.to_string(),
        message: FILE_MESSAGE.to_string(),
        range: hoonarqube_ir::Range {
            start: to_pos(TextSize::from(0), index, source),
            end: to_pos(TextSize::from(0), index, source),
        },
        fix: None,
        flows: Vec::new(),
        alternatives: Vec::new(),
    }
}

/// `test`-prefixed names are collected test methods (`isTestMethodName`).
fn is_test_method_name(name: &str) -> bool {
    name.starts_with("test")
}

/// Whether a class contributes collected tests: a local `test*` method or
/// one inherited through same-file bases.
fn has_collected_tests(class: &StmtClassDef, facts: &WebFrameworkFacts<'_>) -> bool {
    has_local_test_method(class) || has_inherited_test_method(class, facts)
}

/// A direct `test*` method (nested statements do not count — the reference
/// reads `classDef.body().statements()`).
fn has_local_test_method(class: &StmtClassDef) -> bool {
    class.body.iter().any(|stmt| match stmt {
        Stmt::FunctionDef(function) => is_test_method_name(function.name.as_str()),
        _ => false,
    })
}

/// Whether any same-file ancestor declares a `test*` method —
/// `superClassesDeclareTests` over the lexical class graph.
fn has_inherited_test_method(class: &StmtClassDef, facts: &WebFrameworkFacts<'_>) -> bool {
    let mut visited = HashSet::new();
    let mut pending: Vec<&StmtClassDef> = vec![class];
    while let Some(current) = pending.pop() {
        if !visited.insert(current as *const StmtClassDef) {
            continue;
        }
        for base in direct_base_classes(current, facts) {
            if has_local_test_method(base) {
                return true;
            }
            pending.push(base);
        }
    }
    false
}

/// The same-file class definitions a class directly extends.
fn direct_base_classes<'a>(
    class: &'a StmtClassDef,
    facts: &WebFrameworkFacts<'a>,
) -> Vec<&'a StmtClassDef> {
    class
        .bases()
        .iter()
        .filter_map(|base| facts.resolve_class_def(base, base.range()))
        .collect()
}

/// Whether `candidate` is a collected test class: a pytest-style `Test*`
/// class in a pytest-named file, or a `unittest.TestCase` subclass.
fn is_candidate_test_class(
    class: &StmtClassDef,
    pytest_file: bool,
    facts: &WebFrameworkFacts<'_>,
    fqns: &ImportFqns,
) -> bool {
    (pytest_file && is_pytest_style_test_class(class, fqns))
        || is_unittest_test_case(class, facts, fqns)
}

/// `Test*`-named, constructor-free, and carrying at least one lifecycle
/// method or `pytest.fixture` member — `isPytestStyleTestClass`.
fn is_pytest_style_test_class(class: &StmtClassDef, fqns: &ImportFqns) -> bool {
    class.name.as_str().starts_with("Test")
        && !has_constructor(class)
        && has_pytest_lifecycle(class, fqns)
}

/// `__init__`/`__new__` mark a helper class pytest will not collect.
fn has_constructor(class: &StmtClassDef) -> bool {
    class.body.iter().any(|stmt| match stmt {
        Stmt::FunctionDef(function) => {
            matches!(function.name.as_str(), "__init__" | "__new__")
        }
        _ => false,
    })
}

/// A lifecycle method or a `pytest.fixture`-decorated member.
fn has_pytest_lifecycle(class: &StmtClassDef, fqns: &ImportFqns) -> bool {
    class.body.iter().any(|stmt| match stmt {
        Stmt::FunctionDef(function) => {
            PYTEST_LIFECYCLE_METHODS.contains(&function.name.as_str())
                || function.decorator_list.iter().any(|decorator| {
                    let expr = match &decorator.expression {
                        Expr::Call(call) => call.func.as_ref(),
                        expr => expr,
                    };
                    fqns.is_fqn(expr, "pytest.fixture")
                })
        }
        _ => false,
    })
}

/// Whether any transitive base resolves to a `unittest.*TestCase*` type —
/// `isUnittestTestCaseClass` over `getParentClassesFQN`, which walks the
/// whole superclass chain. Same-file bases recurse; imported and unbound
/// bases match on their dotted path.
fn is_unittest_test_case(
    class: &StmtClassDef,
    facts: &WebFrameworkFacts<'_>,
    fqns: &ImportFqns,
) -> bool {
    let mut visited = HashSet::new();
    let mut pending: Vec<&StmtClassDef> = vec![class];
    while let Some(current) = pending.pop() {
        if !visited.insert(current as *const StmtClassDef) {
            continue;
        }
        for base in current.bases() {
            if let Some(resolved) = facts.resolve_class_def(base, base.range()) {
                pending.push(resolved);
                continue;
            }
            if fqns
                .resolve(base)
                .is_some_and(|fqn| fqn.contains("unittest") && fqn.contains("TestCase"))
            {
                return true;
            }
        }
    }
    false
}

/// Whether another top-level class with collected tests extends
/// `candidate` — shared scaffolds stay silent when real tests derive
/// from them.
fn has_descendant_with_tests(
    candidate: &StmtClassDef,
    classes: &[&StmtClassDef],
    has_tests: &[bool],
    facts: &WebFrameworkFacts<'_>,
) -> bool {
    classes
        .iter()
        .zip(has_tests)
        .filter(|(class, has)| **has && class.name.range() != candidate.name.range())
        .any(|(class, _)| extends_class(*class, candidate, facts))
}

/// Whether `class` transitively extends `ancestor` through same-file bases.
fn extends_class(
    class: &StmtClassDef,
    ancestor: &StmtClassDef,
    facts: &WebFrameworkFacts<'_>,
) -> bool {
    let mut visited = HashSet::new();
    let mut pending: Vec<&StmtClassDef> = vec![class];
    while let Some(current) = pending.pop() {
        if !visited.insert(current as *const StmtClassDef) {
            continue;
        }
        for base in direct_base_classes(current, facts) {
            if std::ptr::eq(base, ancestor) {
                return true;
            }
            pending.push(base);
        }
    }
    false
}

/// `Base*`, `*Mixin`, abstract, and placeholder-only classes are shared
/// scaffolding rather than missing tests — `isLikelySharedBaseClass`.
fn is_likely_shared_base(
    class: &StmtClassDef,
    facts: &WebFrameworkFacts<'_>,
    fqns: &ImportFqns,
) -> bool {
    let name = class.name.as_str();
    name.starts_with("Base")
        || name.ends_with("Mixin")
        || is_abstract_base(class, facts, fqns)
        || only_placeholder_methods(class, fqns)
}

/// A `metaclass=` keyword or a transitive `abc.ABC` ancestor marks the
/// class abstract — `hasMetaClass || hasAncestorMatching(abc.ABC)`.
fn is_abstract_base(
    class: &StmtClassDef,
    facts: &WebFrameworkFacts<'_>,
    fqns: &ImportFqns,
) -> bool {
    if class.arguments.as_deref().is_some_and(|arguments| {
        arguments
            .keywords
            .iter()
            .any(|keyword| keyword.arg.as_deref() == Some("metaclass"))
    }) {
        return true;
    }
    let mut visited = HashSet::new();
    let mut pending: Vec<&StmtClassDef> = vec![class];
    while let Some(current) = pending.pop() {
        if !visited.insert(current as *const StmtClassDef) {
            continue;
        }
        for base in current.bases() {
            if fqns.is_fqn(base, "abc.ABC") {
                return true;
            }
            if let Some(resolved) = facts.resolve_class_def(base, base.range()) {
                pending.push(resolved);
            }
        }
    }
    false
}

/// Every method body is a single `pass` or `raise NotImplementedError` —
/// the class is a scaffold, not a missing test.
fn only_placeholder_methods(class: &StmtClassDef, fqns: &ImportFqns) -> bool {
    let methods: Vec<&StmtFunctionDef> = class
        .body
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::FunctionDef(function) => Some(function),
            _ => None,
        })
        .collect();
    !methods.is_empty()
        && methods
            .iter()
            .all(|method| is_placeholder_method(method, fqns))
}

/// A one-statement body of `pass` or `raise NotImplementedError` (a
/// `raise ... from ...` carries a second expression and is not a
/// placeholder).
fn is_placeholder_method(method: &StmtFunctionDef, fqns: &ImportFqns) -> bool {
    let [statement] = method.body.as_slice() else {
        return false;
    };
    match statement {
        Stmt::Pass(_) => true,
        Stmt::Raise(raise) if raise.cause.is_none() => raise
            .exc
            .as_deref()
            .is_some_and(|expr| is_not_implemented_error(expr, fqns)),
        _ => false,
    }
}

/// `NotImplementedError` or `NotImplementedError()` resolving to the
/// builtin in any spelling.
fn is_not_implemented_error(expr: &Expr, fqns: &ImportFqns) -> bool {
    let target = match expr {
        Expr::Call(call) => call.func.as_ref(),
        expr => expr,
    };
    match target {
        Expr::Name(name) if name.id.as_str() == "NotImplementedError" => true,
        _ => fqns.is_fqn(target, "builtins.NotImplementedError"),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::test_support::{findings, pos, scan_at, scan_test_file};

    #[test]
    fn s2187_flags_empty_unittest_case_on_sonar_example() {
        // The reference unittest Noncompliant example, verbatim; scanned
        // under a non-pytest test path so the class issue fires.
        let flagged = scan_at(
            PathBuf::from("tests/testcases.py"),
            concat!(
                "import unittest\n",
                "\n",
                "class TestSomeClass(unittest.TestCase):  # Noncompliant\n",
                "    pass\n",
            ),
        );
        let found = findings(&flagged, "python:S2187");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start, pos(3, 6));
        assert_eq!(found[0].range.end, pos(3, 19));
        assert_eq!(found[0].message, "Add some tests to this class.");
    }

    #[test]
    fn s2187_accepts_unittest_case_with_test_on_sonar_example() {
        // The reference unittest Compliant solution, verbatim.
        let clean = scan_at(
            PathBuf::from("tests/testcases.py"),
            concat!(
                "import unittest\n",
                "\n",
                "class TestSomeClass(unittest.TestCase):\n",
                "    def test_some_method_should_return_true(self):\n",
                "        self.assertTrue(some_method())\n",
            ),
        );
        assert!(findings(&clean, "python:S2187").is_empty());
    }

    #[test]
    fn s2187_flags_pytest_class_with_only_fixtures() {
        // The reference pytest Noncompliant example, verbatim.
        let flagged = scan_test_file(concat!(
            "# test_example.py\n",
            "class TestSomeClass:\n",
            "    pass\n",
        ));
        let found = findings(&flagged, "python:S2187");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].message, "Add some tests to this file.");
    }

    #[test]
    fn s2187_accepts_pytest_class_with_test() {
        // The reference pytest Compliant solution, verbatim.
        let clean = scan_test_file(concat!(
            "# test_example.py\n",
            "class TestSomeClass:\n",
            "    def test_some_method_should_return_true(self):\n",
            "        assert some_method() is True\n",
        ));
        assert!(findings(&clean, "python:S2187").is_empty());
    }

    #[test]
    fn s2187_flags_lifecycle_only_classes_and_skips_scaffolds() {
        let flagged = scan_test_file(concat!(
            "import unittest\n",
            "import pytest\n",
            "\n",
            "def test_module_level_test():\n",
            "    assert True\n",
            "\n",
            "class TestPytestWithoutTests:  # Noncompliant\n",
            "    @pytest.fixture\n",
            "    def setup_data(self):\n",
            "        return 42\n",
            "\n",
            "class TestPytestEndpoint:  # Noncompliant\n",
            "    @pytest.fixture(autouse=True)\n",
            "    def setup_attrs(self):\n",
            "        self.value = 42\n",
            "\n",
            "    def teardown_method(self):\n",
            "        self.value = None\n",
            "\n",
            "class TestPytestXunitOnly:  # Noncompliant\n",
            "    def teardown_method(self):\n",
            "        self.value = None\n",
            "\n",
            "class HelperPytestClass:\n",
            "    def helper(self):\n",
            "        return 42\n",
            "\n",
            "class TestPytestHelperWithInit:\n",
            "    def __init__(self):\n",
            "        self.value = 42\n",
            "\n",
            "class TestAmbiguousWithoutLifecycle:\n",
            "    def helper(self):\n",
            "        return 42\n",
        ));
        let found = findings(&flagged, "python:S2187");
        assert_eq!(found.len(), 3);
        assert!(
            found
                .iter()
                .all(|issue| issue.message == "Add some tests to this class.")
        );
    }

    #[test]
    fn s2187_skips_shared_bases_and_inherited_tests() {
        let clean = scan_at(
            PathBuf::from("tests/testcases.py"),
            concat!(
                "import unittest\n",
                "\n",
                "class BaseSharedTestCase(unittest.TestCase):\n",
                "    def helper(self):\n",
                "        return 42\n",
                "\n",
                "class HelperMixin(unittest.TestCase):\n",
                "    def helper(self):\n",
                "        return 42\n",
                "\n",
                "class BaseWithInheritedTest(unittest.TestCase):\n",
                "    def test_from_base(self):\n",
                "        self.assertTrue(True)\n",
                "\n",
                "class DerivedInheritingTest(BaseWithInheritedTest):\n",
                "    def helper(self):\n",
                "        return 42\n",
                "\n",
                "class BaseHelperTestCase(unittest.TestCase):\n",
                "    def helper(self):\n",
                "        return 42\n",
                "\n",
                "class DerivedWithOwnTest(BaseHelperTestCase):\n",
                "    def test_ok(self):\n",
                "        self.assertEqual(42, self.helper())\n",
            ),
        );
        assert!(findings(&clean, "python:S2187").is_empty());
    }

    #[test]
    fn s2187_flags_derived_case_without_real_inherited_test() {
        // `test_data` is an attribute, not a method — the derived class has
        // no collected tests and is flagged through the transitive
        // unittest.TestCase ancestry.
        let flagged = scan_at(
            PathBuf::from("tests/testcases.py"),
            concat!(
                "import unittest\n",
                "\n",
                "def test_ok():\n",
                "    assert True\n",
                "\n",
                "class BaseWithTestAttribute(unittest.TestCase):\n",
                "    test_data = True\n",
                "\n",
                "class DerivedWithoutRealInheritedTest(BaseWithTestAttribute):  # Noncompliant\n",
                "    def helper(self):\n",
                "        return 42\n",
            ),
        );
        let found = findings(&flagged, "python:S2187");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start, pos(9, 6));
    }

    #[test]
    fn s2187_stays_silent_outside_test_scope() {
        let clean = scan_at(
            PathBuf::from("src/module.py"),
            concat!(
                "import unittest\n",
                "\n",
                "class EmptyUnittestCase(unittest.TestCase):\n",
                "    pass\n",
            ),
        );
        assert!(findings(&clean, "python:S2187").is_empty());
    }
}
