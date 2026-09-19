use std::collections::HashSet;

use ruff_python_ast::{
    BoolOp, CmpOp, ExceptHandler, Expr, ExprAttribute, ExprCall, ExprName, Stmt, StmtIf, StmtTry,
    UnaryOp,
};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::engine::file_context::FileContext;
use crate::rules::bs4_page_elements::is_page_element;
use crate::support::{WebFrameworkFacts, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8904";

/// Search methods that return `None` when nothing matches (Sonar's
/// `IS_BS4_SEARCH_CALL`: `Tag.find`/`Tag.select_one` plus the `PageElement`
/// find_* singles). The deprecated camelCase aliases are absent — Sonar's
/// type inference cannot resolve them either.
const SEARCH_METHODS: &[&str] = &[
    "find",
    "select_one",
    "find_next",
    "find_previous",
    "find_next_sibling",
    "find_previous_sibling",
    "find_parent",
];

/// Per-file scan state shared by the access checks.
struct Scan<'a> {
    facts: WebFrameworkFacts<'a>,
    file_ctx: &'a FileContext<'a>,
    index: &'a LineIndex,
    source: &'a str,
    issues: Vec<Issue>,
    /// Attribute expressions that are the callee of a call — needed for
    /// the "callee of a search call" skip in `check_attribute`.
    callee_ranges: HashSet<TextRange>,
}

/// python:S8904 — `find()`/`select_one()`/`find_*()` return `None` when no
/// element matches, so reading `.text`, subscripting `["class"]`, or
/// chaining another search on the result crashes on missing markup. Sonar
/// flags the first unsafe access: the search method name for inline chains
/// (`soup.find("p").text` anchors on `find`), the attribute name or whole
/// subscript for a variable bound once to a search call. Accesses guarded
/// by an enclosing `if element`/`is not None`/`!= None` check, an earlier
/// early-exit `if element is None`/`not element`/`== None`, a preceding
/// `assert`, or a `try`/`except AttributeError` stay silent.
pub(crate) fn check_s8904_element_none_check(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut scan = Scan {
        facts: WebFrameworkFacts::build(file_ctx),
        file_ctx,
        index,
        source,
        issues: Vec::new(),
        callee_ranges: file_ctx
            .calls
            .iter()
            .map(|call| call.func.range())
            .collect(),
    };

    for expr in &file_ctx.exprs {
        match expr {
            Expr::Attribute(attribute) => scan.check_attribute(attribute),
            Expr::Subscript(subscript) => {
                if is_assignment_target(file_ctx, expr.range()) {
                    continue;
                }
                scan.check_object_access(
                    &subscript.value,
                    expr.range(),
                    &subscript_description(subscript.slice.as_ref()),
                );
            }
            _ => {}
        }
    }
    scan.issues
}

impl Scan<'_> {
    /// Sonar's `checkQualifiedExpr`: when the attribute is itself the
    /// callee of a bs4 search call, the access is safe unless the
    /// qualifier is another search call result
    /// (`soup.find("div").find("p")` still flags the first `find` through
    /// the object-access path).
    fn check_attribute(&mut self, attribute: &ExprAttribute) {
        if self.callee_ranges.contains(&attribute.range())
            && self.is_search_method_on_element(attribute)
            && !matches!(
                attribute.value.as_ref(),
                Expr::Call(qualifier_call) if self.is_search_call(qualifier_call)
            )
        {
            return;
        }
        self.check_object_access(
            &attribute.value,
            attribute.attr.range(),
            &format!(".{}", attribute.attr.as_str()),
        );
    }

    /// Shared access check for `object.attr` and `object[...]`: flag when
    /// the object is an inline search call or a name bound once to one,
    /// unless the access sits inside a `try` whose handlers catch
    /// `AttributeError`.
    fn check_object_access(&mut self, object: &Expr, issue_range: TextRange, access: &str) {
        if is_inside_catching_try(self.file_ctx, issue_range) {
            return;
        }
        match object {
            Expr::Call(call) if self.is_search_call(call) => {
                // Only the first unsafe access in a chain is raised: when
                // the search call's own qualifier is another search call,
                // an earlier issue already covers it.
                if let Expr::Attribute(inner) = call.func.as_ref()
                    && matches!(
                        inner.value.as_ref(),
                        Expr::Call(inner_call) if self.is_search_call(inner_call)
                    )
                {
                    return;
                }
                let anchor = match call.func.as_ref() {
                    Expr::Attribute(inner) => inner.attr.range(),
                    _ => issue_range,
                };
                self.push_issue(anchor, access);
            }
            Expr::Name(name) => self.check_name_access(name, issue_range, access),
            _ => {}
        }
    }

    /// A name access is unsafe when the name is bound exactly once to a
    /// bs4 search call and no None-guard covers this read.
    fn check_name_access(&mut self, name: &ExprName, issue_range: TextRange, access: &str) {
        let bound_to_search_call = match self
            .facts
            .single_assigned_value(name.id.as_str(), name.range())
        {
            Some(Expr::Call(call)) => self.is_search_call(call),
            _ => false,
        };
        if !bound_to_search_call {
            return;
        }
        if is_guarded_by_none_check(self.file_ctx, name.id.as_str(), name.range()) {
            return;
        }
        self.push_issue(issue_range, access);
    }

    /// `call` is a bs4 search call: `find`/`select_one`/`find_*` on a
    /// `PageElement` receiver.
    fn is_search_call(&self, call: &ExprCall) -> bool {
        match call.func.as_ref() {
            Expr::Attribute(attribute) => self.is_search_method_on_element(attribute),
            _ => false,
        }
    }

    fn is_search_method_on_element(&self, attribute: &ExprAttribute) -> bool {
        SEARCH_METHODS.contains(&attribute.attr.as_str())
            && is_page_element(&self.facts, &attribute.value)
    }

    fn push_issue(&mut self, range: TextRange, access: &str) {
        self.issues.push(issue_at(
            RULE_KEY,
            &format!("Check if this element exists before accessing it with `{access}`."),
            range,
            self.index,
            self.source,
        ));
    }
}

/// `[class]` for a single string subscript, `[]` otherwise — Sonar's
/// `subscriptDescription`.
fn subscript_description(slice: &Expr) -> String {
    match slice {
        Expr::StringLiteral(literal) => format!("[{}]", literal.value.to_str()),
        _ => "[]".to_string(),
    }
}

/// The subscript expression is a write target (`element["class"] = x`),
/// not a read. Sonar compares the assignment's flattened LHS expressions
/// for identity; range equality on tuple/list-flattened targets mirrors
/// that.
fn is_assignment_target(file_ctx: &FileContext, range: TextRange) -> bool {
    file_ctx.stmts.iter().any(|stmt| {
        let Stmt::Assign(assign) = stmt else {
            return false;
        };
        assign
            .targets
            .iter()
            .any(|target| target_contains(target, range))
    })
}

fn target_contains(expr: &Expr, range: TextRange) -> bool {
    if expr.range() == range {
        return true;
    }
    match expr {
        Expr::Tuple(tuple) => tuple.elts.iter().any(|elt| target_contains(elt, range)),
        Expr::List(list) => list.elts.iter().any(|elt| target_contains(elt, range)),
        _ => false,
    }
}

/// The access sits inside the body of a `try` whose handlers catch
/// `AttributeError`. Sonar's `catchesAttributeError` returns false on the
/// first bare `except:` and true on the first clause listing
/// `AttributeError` (including inside a tuple), whichever comes first.
fn is_inside_catching_try(file_ctx: &FileContext, range: TextRange) -> bool {
    file_ctx.stmts.iter().any(|stmt| {
        let Stmt::Try(try_stmt) = stmt else {
            return false;
        };
        body_contains(&try_stmt.body, range) && catches_attribute_error(try_stmt)
    })
}

fn body_contains(body: &[Stmt], range: TextRange) -> bool {
    let (Some(first), Some(last)) = (body.first(), body.last()) else {
        return false;
    };
    let span = TextRange::new(first.range().start(), last.range().end());
    span.contains_range(range)
}

fn catches_attribute_error(try_stmt: &StmtTry) -> bool {
    for handler in &try_stmt.handlers {
        let ExceptHandler::ExceptHandler(handler) = handler;
        let Some(exception) = &handler.type_ else {
            // A bare `except:` is too broad to prove the access is safe.
            return false;
        };
        if flatten_tuples(exception)
            .iter()
            .any(|expr| is_attribute_error(expr))
        {
            return true;
        }
    }
    false
}

fn flatten_tuples(expr: &Expr) -> Vec<&Expr> {
    match expr {
        Expr::Tuple(tuple) => tuple.elts.iter().flat_map(flatten_tuples).collect(),
        _ => vec![expr],
    }
}

fn is_attribute_error(expr: &Expr) -> bool {
    match expr {
        Expr::Name(name) => name.id.as_str() == "AttributeError",
        Expr::Attribute(attribute) => attribute.attr.as_str() == "AttributeError",
        _ => false,
    }
}

/// Sonar's `isGuardedByNoneCheck`: an enclosing `if` whose condition tests
/// the name for truthiness (`if element:`, `if element is not None:`, `if
/// element != None:`, possibly inside an `and` chain), an earlier
/// early-exit `if` in the same scope testing for None/falsiness (`if
/// element is None: return`, `if not element: return`, `if element ==
/// None: return`), or an earlier `assert` on the name.
fn is_guarded_by_none_check(file_ctx: &FileContext, name: &str, access: TextRange) -> bool {
    let scope = innermost_function_range(file_ctx, access);
    file_ctx.stmts.iter().any(|stmt| match stmt {
        Stmt::If(if_stmt) => {
            if body_contains(&if_stmt.body, access) && condition_checks_truthy(&if_stmt.test, name)
            {
                return true;
            }
            stmt.range().start() < access.start()
                && same_scope(file_ctx, stmt.range(), scope)
                && is_early_exit_none_guard(if_stmt, name)
        }
        Stmt::Assert(assert) => {
            stmt.range().start() < access.start()
                && same_scope(file_ctx, stmt.range(), scope)
                && condition_checks_truthy(&assert.test, name)
        }
        _ => false,
    })
}

/// The if body exits unconditionally and its condition tests the name for
/// None or falsiness — the mirror image of a positive guard.
fn is_early_exit_none_guard(if_stmt: &StmtIf, name: &str) -> bool {
    let Some(last) = if_stmt.body.last() else {
        return false;
    };
    if !matches!(
        last,
        Stmt::Return(_) | Stmt::Raise(_) | Stmt::Continue(_) | Stmt::Break(_)
    ) {
        return false;
    }
    condition_checks_none_or_falsy(&if_stmt.test, name)
}

/// `element`, `element is not None`, `element != None`, or an `and` chain
/// containing one of those.
fn condition_checks_truthy(condition: &Expr, name: &str) -> bool {
    match condition {
        Expr::Name(operand) => operand.id.as_str() == name,
        Expr::BoolOp(bool_op) if bool_op.op == BoolOp::And => bool_op
            .values
            .iter()
            .any(|value| condition_checks_truthy(value, name)),
        Expr::Compare(compare) if compare.ops.len() == 1 => match compare.ops[0] {
            CmpOp::IsNot | CmpOp::NotEq => {
                name_compared_to_none(name, &compare.left, &compare.comparators[0])
            }
            _ => false,
        },
        _ => false,
    }
}

/// `not element`, `element is None`, or `element == None`.
fn condition_checks_none_or_falsy(condition: &Expr, name: &str) -> bool {
    match condition {
        Expr::UnaryOp(unary) if unary.op == UnaryOp::Not => name_matches(name, &unary.operand),
        Expr::Compare(compare) if compare.ops.len() == 1 => match compare.ops[0] {
            CmpOp::Is | CmpOp::Eq => {
                name_compared_to_none(name, &compare.left, &compare.comparators[0])
            }
            _ => false,
        },
        _ => false,
    }
}

fn name_compared_to_none(name: &str, left: &Expr, right: &Expr) -> bool {
    (name_matches(name, left) && matches!(right, Expr::NoneLiteral(_)))
        || (name_matches(name, right) && matches!(left, Expr::NoneLiteral(_)))
}

fn name_matches(name: &str, expr: &Expr) -> bool {
    matches!(expr, Expr::Name(operand) if operand.id.as_str() == name)
}

/// The smallest function definition containing `range`, if any — the
/// scope Sonar's symbol table would attribute the name to.
fn innermost_function_range(file_ctx: &FileContext, range: TextRange) -> Option<TextRange> {
    file_ctx
        .functions
        .iter()
        .filter(|function| function.range().contains_range(range))
        .map(ruff_text_size::Ranged::range)
        .min_by_key(|range| range.len())
}

/// Guard and access must belong to the same innermost function so a
/// same-named local in a sibling function cannot guard the read.
fn same_scope(file_ctx: &FileContext, stmt: TextRange, scope: Option<TextRange>) -> bool {
    innermost_function_range(file_ctx, stmt) == scope
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    const KEY: &str = "python:S8904";

    #[test]
    fn s8904_flags_the_sonar_noncompliant_example() {
        let source = r#"from bs4 import BeautifulSoup

soup = BeautifulSoup(html_content, "html.parser")
figure = soup.find("dd", class_="investment_sought").text
print(figure)
"#;
        let report = scan(source);
        let found = findings(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Check if this element exists before accessing it with `.text`."
        );
        // Sonar anchors on the `find` method name.
        assert_eq!(found[0].range.start, pos(4, 14));
        assert_eq!(found[0].range.end, pos(4, 18));
    }

    #[test]
    fn s8904_flags_inline_access_on_every_search_method() {
        let source = r#"from bs4 import BeautifulSoup

soup = BeautifulSoup(html, "html.parser")

a = soup.find("p").text
b = soup.find("a")["class"]
c = soup.find("a")[key]
d = soup.select_one("p").text
e = soup.find_next("p").text
f = soup.find_previous("p").text
g = soup.find_next_sibling("p").text
h = soup.find_previous_sibling("p").text
i = soup.find_parent("div").text
j = soup.find("p").get_text()
"#;
        let report = scan(source);
        assert_eq!(findings(&report, KEY).len(), 10);
    }

    #[test]
    fn s8904_flags_chained_search_once_on_the_first_call() {
        let source = r#"from bs4 import BeautifulSoup

soup = BeautifulSoup(html, "html.parser")

text = soup.find("div").find("p").text
inner = soup.find("div").find("p")
"#;
        let report = scan(source);
        let found = findings(&report, KEY);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|issue| issue.message.contains("`.find`")));
        // Both anchor on the first `find` of their chain.
        assert_eq!(found[0].range.start, pos(5, 12));
        assert_eq!(found[1].range.start, pos(6, 13));
    }

    #[test]
    fn s8904_flags_unguarded_variable_access() {
        let source = r#"from bs4 import BeautifulSoup

def f(cond, other):
    soup = BeautifulSoup(html, "html.parser")
    element = soup.find("p")
    text = element.text
    cls = element["class"]
    call = element.get_text()

    selected = soup.select_one("p")
    value = selected.text

    if not element:
        pass
    again = element.text

    if element is not other:
        third = element.text
"#;
        let report = scan(source);
        assert_eq!(findings(&report, KEY).len(), 6);
    }

    #[test]
    fn s8904_accepts_guarded_access() {
        let source = r#"from bs4 import BeautifulSoup

def f():
    soup = BeautifulSoup(html, "html.parser")
    element = soup.find("p")
    if element is not None:
        a = element.text
        b = element["class"]
    if element:
        c = element.text
    if element is not None:
        if True:
            d = element.text
    if element is not None and True:
        e = element.text
    if True and element is not None:
        f2 = element.text
    if element != None:
        g = element.text
    if None != element:
        h = element.text
"#;
        let report = scan(source);
        assert!(findings(&report, KEY).is_empty());
    }

    #[test]
    fn s8904_accepts_early_exit_and_assert_guards() {
        let source = r#"from bs4 import BeautifulSoup

def f():
    soup = BeautifulSoup(html, "html.parser")

    a = soup.find("p")
    if a == None:
        return
    x = a.text

    b = soup.find("p")
    if None == b:
        return
    y = b.text

    c = soup.find("p")
    if None is c:
        return
    z = c.text

    d = soup.find("p")
    if d is None:
        return
    w = d.text

    e = soup.find("p")
    if not e:
        return
    v = e.text

    g = soup.find("p")
    assert g
    u = g.text

    h = soup.find("p")
    assert h is not None
    t = h.text
"#;
        let report = scan(source);
        assert!(findings(&report, KEY).is_empty());
    }

    #[test]
    fn s8904_flags_inverted_guards_and_assert_none() {
        let source = r#"from bs4 import BeautifulSoup

def f():
    soup = BeautifulSoup(html, "html.parser")

    a = soup.find("p")
    if a is not None:
        return
    x = a.text

    b = soup.find("p")
    assert b is None
    y = b.text
"#;
        let report = scan(source);
        assert_eq!(findings(&report, KEY).len(), 2);
    }

    #[test]
    fn s8904_try_except_only_attribute_error_suppresses() {
        let source = r#"from bs4 import BeautifulSoup

def f():
    soup = BeautifulSoup(html, "html.parser")
    try:
        a = soup.find("p").text
    except AttributeError:
        pass
    try:
        b = soup.find("p").text
    except (AttributeError, TypeError):
        pass
    try:
        c = soup.find("p").text
    except Exception:
        pass
    try:
        d = soup.find("p").text
    except:
        pass
    try:
        e = soup.find("p").text
    except ValueError:
        pass
"#;
        let report = scan(source);
        assert_eq!(findings(&report, KEY).len(), 3);
    }

    #[test]
    fn s8904_ignores_parameters_writes_and_non_bs4_objects() {
        let source = r#"from bs4 import BeautifulSoup

def f(element):
    text = element.text

def g():
    soup = BeautifulSoup(html, "html.parser")
    element = soup.find("p")
    element["class"] = "active"

    d = {"key": "value"}
    val = d["key"]
    text = d.get("key")
"#;
        let report = scan(source);
        assert!(findings(&report, KEY).is_empty());
    }
}
