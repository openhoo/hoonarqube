//! Shared `BeautifulSoup` receiver classification for the
//! `python:S89xx` `BeautifulSoup` rule family
//! (`S8900`/`S8903`/`S8904`/`S8905`/`S8906`).
//!
//! Sonar's checks type-match receivers against `bs4.element.PageElement`
//! (which `BeautifulSoup` and `Tag` extend). hoonarqube has no type
//! inference, so the family shares this lexical approximation built on
//! [`WebFrameworkFacts::expr_fqn`]: an expression is a page element when
//! its resolved FQN is a bs4 element type, or the result of a member
//! access/call on one that returns another element (`soup.find("a")`,
//! `tag.parent`, `soup.body`, …). Members known to return non-elements
//! (`find_all`, `get_text`, `text`, …) stop the chain so
//! `soup.find_all("a").find("b")` is not treated as a Tag receiver.

use ruff_python_ast::Expr;

use crate::support::WebFrameworkFacts;

/// FQNs that denote a `bs4.element.PageElement` instance: the element
/// classes themselves plus the `bs4` package-level re-exports.
const ELEMENT_BASES: &[&str] = &[
    "bs4.BeautifulSoup",
    "bs4.Tag",
    "bs4.PageElement",
    "bs4.NavigableString",
    "bs4.element.BeautifulSoup",
    "bs4.element.Tag",
    "bs4.element.PageElement",
    "bs4.element.NavigableString",
    "bs4.element.Script",
    "bs4.element.Stylesheet",
    "bs4.element.TemplateString",
    "bs4.element.RubyParenthesisString",
    "bs4.element.RubyTextString",
    "bs4.element.Declaration",
    "bs4.element.Doctype",
    "bs4.element.ProcessingInstruction",
    "bs4.element.CData",
    "bs4.element.Comment",
];

/// Members whose result is never a page element. Any member not listed
/// here is treated as element-returning: `PageElement.__getattr__` yields
/// a `Tag` for arbitrary attribute reads (`soup.body`, `soup.title`), and
/// the element-returning methods (`find`, `find_parent`, `parent`,
/// `next_sibling`, `replace_with`, `extract`, `wrap`, …) all produce
/// elements again. Listing the non-element members keeps
/// `soup.find_all("a").find("b")` silent while unknown members follow the
/// `__getattr__` convention.
const NON_ELEMENT_MEMBERS: &[&str] = &[
    "find_all",
    "find_all_next",
    "find_all_previous",
    "find_next_siblings",
    "find_previous_siblings",
    "find_parents",
    "select",
    "get_text",
    "getText",
    "text",
    "get_attribute_list",
    "findAll",
    "findChildren",
    "findAllNext",
    "findAllPrevious",
    "findNextSiblings",
    "findPreviousSiblings",
    "findParents",
    "name",
    "attrs",
    "has_attr",
    "encode",
    "decode",
    "prettify",
    "decompose",
    "insert",
    "append",
    "extend",
    "insert_before",
    "insert_after",
    "clear",
    "index",
];

/// Whether `fqn` denotes a `bs4.element.PageElement` instance: a bs4
/// element type, or a chain of member accesses on one whose members are
/// not known to return non-elements.
pub(crate) fn is_page_element_fqn(fqn: &str) -> bool {
    let mut rest = fqn;
    loop {
        if ELEMENT_BASES.contains(&rest) {
            return true;
        }
        let Some((base, member)) = rest.rsplit_once('.') else {
            return false;
        };
        if NON_ELEMENT_MEMBERS.contains(&member) {
            return false;
        }
        rest = base;
    }
}

/// Whether `expr` resolves to a `bs4.element.PageElement` instance.
pub(crate) fn is_page_element(facts: &WebFrameworkFacts<'_>, expr: &Expr) -> bool {
    facts
        .expr_fqn(expr)
        .is_some_and(|fqn| is_page_element_fqn(&fqn))
}
