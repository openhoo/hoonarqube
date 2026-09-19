use ruff_python_ast::{Expr, ExprCall, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::engine::file_context::FileContext;
use crate::support::{WebFrameworkFacts, issue_at, nth_or_keyword_argument};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8905";
const MESSAGE: &str = "Specify the parser to use for \"BeautifulSoup\".";

/// python:S8905 — `BeautifulSoup(markup)` without a parser picks whatever
/// engine happens to be installed, so the same markup parses differently
/// across environments. Sonar flags the `BeautifulSoup` callee (type
/// `bs4.BeautifulSoup`) when neither the `features` argument (second
/// positional or keyword) nor the `builder` argument (third positional or
/// keyword) is present; a present-but-`None` value still counts as an
/// explicit choice.
pub(crate) fn check_s8905_beautifulsoup_parser(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !is_beautifulsoup_callee(&facts, file_ctx, call) {
            continue;
        }
        let parser_pinned = nth_or_keyword_argument(call, 1, "features").is_some()
            || nth_or_keyword_argument(call, 2, "builder").is_some();
        if parser_pinned {
            continue;
        }
        issues.push(issue_at(
            RULE_KEY,
            MESSAGE,
            call.func.range(),
            index,
            source,
        ));
    }
    issues
}

/// The callee resolves to `bs4.BeautifulSoup`. `expr_fqn` covers the
/// single-binding cases; when the name has several bindings in one scope
/// (the resolver conservatively reports `Bound`), the nearest preceding
/// binding decides — matching Sonar's flow-sensitive symbol resolution,
/// where `from bs4 import BeautifulSoup` followed by a local
/// `class BeautifulSoup` still flags calls before the class.
fn is_beautifulsoup_callee(
    facts: &WebFrameworkFacts<'_>,
    file_ctx: &FileContext,
    call: &ExprCall,
) -> bool {
    if let Some(fqn) = facts.expr_fqn(&call.func) {
        return fqn == "bs4.BeautifulSoup";
    }
    let Expr::Name(name) = call.func.as_ref() else {
        return false;
    };
    nearest_preceding_binding(facts, file_ctx, name.id.as_str(), call.range())
        .is_some_and(|binding| import_binds_bs4_soup(binding, name.id.as_str()))
}

/// The binding of `name` nearest before `at`, walking the scope chain
/// (innermost function/lambda outward, module last) the way
/// `WebFrameworkFacts` scopes statements.
fn nearest_preceding_binding<'a>(
    facts: &WebFrameworkFacts<'a>,
    file_ctx: &'a FileContext<'a>,
    name: &str,
    at: TextRange,
) -> Option<&'a Stmt> {
    for scope in scope_chain(facts, file_ctx, at) {
        let binding = file_ctx
            .stmts
            .iter()
            .filter(|stmt| {
                stmt.range().start() < at.start()
                    && innermost_scope(facts, file_ctx, stmt.range()) == scope
                    && stores_name(stmt, name)
            })
            .max_by_key(|stmt| stmt.range().start())
            .copied();
        if binding.is_some() {
            return binding;
        }
    }
    None
}

/// Enclosing function/lambda scopes, innermost first, then module scope.
fn scope_chain(
    facts: &WebFrameworkFacts<'_>,
    file_ctx: &FileContext,
    at: TextRange,
) -> Vec<Option<TextRange>> {
    let mut scopes: Vec<Option<TextRange>> = file_ctx
        .functions
        .iter()
        .map(Ranged::range)
        .chain(facts.lambdas().map(Ranged::range))
        .filter(|scope| scope.contains_range(at))
        .map(Some)
        .collect();
    scopes.sort_by_key(|scope| scope.map_or(u32::MAX, |range| range.len().into()));
    scopes.push(None);
    scopes
}

/// The innermost function/lambda range containing `range`, or `None` for
/// module scope — the same scope notion `WebFrameworkFacts` uses.
fn innermost_scope(
    facts: &WebFrameworkFacts<'_>,
    file_ctx: &FileContext,
    range: TextRange,
) -> Option<TextRange> {
    file_ctx
        .functions
        .iter()
        .map(Ranged::range)
        .chain(facts.lambdas().map(Ranged::range))
        .filter(|scope| scope.contains_range(range))
        .min_by_key(|range| range.len())
}

/// Whether `stmt` binds `name` in its own scope (imports, assignments,
/// definitions — mirroring `stmt_store_names` for the shapes that matter
/// here).
fn stores_name(stmt: &Stmt, name: &str) -> bool {
    match stmt {
        Stmt::Import(import) => import.names.iter().any(|alias| {
            let local = alias.asname.as_ref().map_or_else(
                || alias.name.as_str().split('.').next().unwrap_or(""),
                ruff_python_ast::Identifier::as_str,
            );
            local == name
        }),
        Stmt::ImportFrom(import) => import.names.iter().any(|alias| {
            alias
                .asname
                .as_ref()
                .map_or_else(|| alias.name.as_str(), ruff_python_ast::Identifier::as_str)
                == name
        }),
        Stmt::Assign(assign) => assign.targets.iter().any(
            |target| matches!(target, Expr::Name(target_name) if target_name.id.as_str() == name),
        ),
        Stmt::AnnAssign(assign) => {
            matches!(assign.target.as_ref(), Expr::Name(target_name) if target_name.id.as_str() == name)
        }
        Stmt::AugAssign(assign) => {
            matches!(assign.target.as_ref(), Expr::Name(target_name) if target_name.id.as_str() == name)
        }
        Stmt::FunctionDef(function) => function.name.as_str() == name,
        Stmt::ClassDef(class) => class.name.as_str() == name,
        _ => false,
    }
}

/// The binding statement is an import that binds `name` to
/// `bs4.BeautifulSoup` (`from bs4 import BeautifulSoup [as name]` or
/// `import bs4.BeautifulSoup`).
fn import_binds_bs4_soup(stmt: &Stmt, name: &str) -> bool {
    match stmt {
        Stmt::ImportFrom(import) => {
            if import.level != 0 || import.module.as_deref() != Some("bs4") {
                return false;
            }
            import.names.iter().any(|alias| {
                alias.name.as_str() == "BeautifulSoup"
                    && alias
                        .asname
                        .as_ref()
                        .is_none_or(|asname| asname.as_str() == name)
            })
        }
        // `import bs4.BeautifulSoup` binds `bs4`, not `BeautifulSoup` —
        // only an explicit alias binds the callee name.
        Stmt::Import(import) => import.names.iter().any(|alias| {
            alias.name.as_str() == "bs4.BeautifulSoup"
                && alias
                    .asname
                    .as_ref()
                    .is_some_and(|asname| asname.as_str() == name)
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    const KEY: &str = "python:S8905";

    #[test]
    fn s8905_flags_the_sonar_noncompliant_examples() {
        let source = r"from bs4 import BeautifulSoup
from urllib.request import urlopen

webpage = urlopen('http://example.com')
soup = BeautifulSoup(webpage)
table = soup.find('table', {'class': 'data'})
";
        let report = scan(source);
        let found = findings(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Specify the parser to use for \"BeautifulSoup\"."
        );
        assert_eq!(found[0].range.start, pos(5, 7));
        assert_eq!(found[0].range.end, pos(5, 20));
    }

    #[test]
    fn s8905_flags_constructor_without_markup() {
        let source = r"from bs4 import BeautifulSoup

soup = BeautifulSoup()
";
        let report = scan(source);
        assert_eq!(findings(&report, KEY).len(), 1);
    }

    #[test]
    fn s8905_accepts_the_sonar_compliant_examples() {
        let source = r#"from bs4 import BeautifulSoup
from bs4.builder import HTMLParserTreeBuilder

html = "<html><body><p>test</p></body></html>"

soup = BeautifulSoup(html, None)
soup = BeautifulSoup(html, features=None)
soup = BeautifulSoup(html, 'html.parser')
soup = BeautifulSoup(html, 'lxml')
soup = BeautifulSoup(html, 'html5lib')
soup = BeautifulSoup(html, features='html.parser')
soup = BeautifulSoup(features='html.parser', markup=html)
soup = BeautifulSoup(html, builder=None)
soup = BeautifulSoup(html, builder=HTMLParserTreeBuilder())
soup = BeautifulSoup(html, None, HTMLParserTreeBuilder())
"#;
        let report = scan(source);
        assert!(findings(&report, KEY).is_empty());
    }

    #[test]
    fn s8905_ignores_non_bs4_constructors() {
        let source = r#"class BeautifulSoup:
    def __init__(self, markup):
        pass

soup = BeautifulSoup("<p>x</p>")
"#;
        let report = scan(source);
        assert!(findings(&report, KEY).is_empty());
    }

    #[test]
    fn s8905_resolves_module_qualified_and_aliased_imports() {
        let source = r#"import bs4
from bs4 import BeautifulSoup as BS

a = bs4.BeautifulSoup("<p>x</p>")
b = BS("<p>x</p>")
c = bs4.BeautifulSoup("<p>x</p>", "html.parser")
"#;
        let report = scan(source);
        let found = findings(&report, KEY);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start, pos(4, 4));
        assert_eq!(found[1].range.start, pos(5, 4));
    }
}
