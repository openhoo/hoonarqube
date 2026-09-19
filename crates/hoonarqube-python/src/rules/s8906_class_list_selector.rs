use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::rules::bs4_page_elements::is_page_element;
use crate::support::{WebFrameworkFacts, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8906";
const MESSAGE_SELECT_ONE: &str = "Use \"select_one()\" with a chained CSS class selector instead.";
const MESSAGE_SELECT: &str = "Use \"select()\" with a chained CSS class selector instead.";

/// Single-result search methods — the CSS replacement is `select_one()`.
/// Covers `Tag.find` plus the `PageElement` find_* singles and their
/// deprecated camelCase aliases (Sonar matches the aliases by name because
/// type inference cannot resolve them).
const SINGLE_RESULT_METHODS: &[&str] = &[
    "find",
    "find_parent",
    "find_next",
    "find_next_sibling",
    "find_previous",
    "find_previous_sibling",
    "findChild",
    "findParent",
    "findNext",
    "findNextSibling",
    "findPrevious",
    "findPreviousSibling",
];

/// List-returning search methods — the CSS replacement is `select()`.
const LIST_RESULT_METHODS: &[&str] = &[
    "find_all",
    "find_parents",
    "find_all_next",
    "find_next_siblings",
    "find_all_previous",
    "find_previous_siblings",
    "findAll",
    "findChildren",
    "findParents",
    "findAllNext",
    "findNextSiblings",
    "findAllPrevious",
    "findPreviousSiblings",
];

/// python:S8906 — `class_=['A', 'B']` on a bs4 search call uses OR logic
/// (any class matches), which reads like the AND logic of the CSS selector
/// `.A.B`. Sonar flags the whole `class_` argument when it is a list
/// literal of two or more classes on a `PageElement` search method,
/// suggesting `select_one()` for single-result methods and `select()` for
/// list-returning ones. A single-element list is unambiguous and stays
/// silent.
pub(crate) fn check_s8906_class_list_selector(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Expr::Attribute(attribute) = call.func.as_ref() else {
            continue;
        };
        let method = attribute.attr.as_str();
        let message = if SINGLE_RESULT_METHODS.contains(&method) {
            MESSAGE_SELECT_ONE
        } else if LIST_RESULT_METHODS.contains(&method) {
            MESSAGE_SELECT
        } else {
            continue;
        };
        if !is_page_element(&facts, &attribute.value) {
            continue;
        }
        let Some(class_keyword) = call
            .arguments
            .keywords
            .iter()
            .find(|keyword| keyword.arg.as_deref() == Some("class_"))
        else {
            continue;
        };
        let Expr::List(list) = &class_keyword.value else {
            continue;
        };
        if list.elts.len() < 2 {
            continue;
        }
        issues.push(issue_at(
            RULE_KEY,
            message,
            class_keyword.range(),
            index,
            source,
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    const KEY: &str = "python:S8906";

    #[test]
    fn s8906_flags_the_sonar_noncompliant_example() {
        let source = r"from bs4 import BeautifulSoup

soup = BeautifulSoup(html, 'html.parser')
results = soup.find_all('div', class_=['A', 'B'])
";
        let report = scan(source);
        let found = findings(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Use \"select()\" with a chained CSS class selector instead."
        );
        // Sonar anchors on the whole `class_=['A', 'B']` argument.
        assert_eq!(found[0].range.start, pos(4, 31));
        assert_eq!(found[0].range.end, pos(4, 48));
    }

    #[test]
    fn s8906_flags_every_list_result_method() {
        let source = r"from bs4 import BeautifulSoup

soup = BeautifulSoup(html, 'html.parser')

soup.find_all('div', class_=['A', 'B'])
soup.findAll('div', class_=['A', 'B'])
soup.find_all(class_=['A', 'B', 'C'])
soup.find_all('div', class_=['A', 'B', 'C'])
soup.findChildren('div', class_=['A', 'B'])
soup.find_parents('div', class_=['A', 'B'])
soup.findParents('div', class_=['A', 'B'])
soup.find_all_next('div', class_=['A', 'B'])
soup.findAllNext('div', class_=['A', 'B'])
soup.find_next_siblings('div', class_=['A', 'B'])
soup.findNextSiblings('div', class_=['A', 'B'])
soup.find_all_previous('div', class_=['A', 'B'])
soup.findAllPrevious('div', class_=['A', 'B'])
soup.find_previous_siblings('div', class_=['A', 'B'])
soup.findPreviousSiblings('div', class_=['A', 'B'])
";
        let report = scan(source);
        let found = findings(&report, KEY);
        assert_eq!(found.len(), 15);
        assert!(found.iter().all(|issue| issue.message.contains("select()")));
    }

    #[test]
    fn s8906_flags_every_single_result_method() {
        let source = r"from bs4 import BeautifulSoup

soup = BeautifulSoup(html, 'html.parser')

soup.find('div', class_=['A', 'B'])
soup.findChild('div', class_=['A', 'B'])
soup.find_parent('div', class_=['A', 'B'])
soup.findParent('div', class_=['A', 'B'])
soup.find_next('div', class_=['A', 'B'])
soup.findNext('div', class_=['A', 'B'])
soup.find_next_sibling('div', class_=['A', 'B'])
soup.findNextSibling('div', class_=['A', 'B'])
soup.find_previous('div', class_=['A', 'B'])
soup.findPrevious('div', class_=['A', 'B'])
soup.find_previous_sibling('div', class_=['A', 'B'])
soup.findPreviousSibling('div', class_=['A', 'B'])
";
        let report = scan(source);
        let found = findings(&report, KEY);
        assert_eq!(found.len(), 12);
        assert!(
            found
                .iter()
                .all(|issue| issue.message.contains("select_one()"))
        );
    }

    #[test]
    fn s8906_accepts_the_sonar_compliant_examples() {
        let source = r"from bs4 import BeautifulSoup

soup = BeautifulSoup(html, 'html.parser')

result = soup.select('div.A.B')
result = soup.select_one('div.A.B')

result = soup.find_all('div', class_='A')
result = soup.find('div', class_='A')
result = soup.find_parent('div', class_='A')
result = soup.find_next('div', class_='A')
result = soup.find_next_sibling('div', class_='A')
result = soup.find_previous('div', class_='A')
result = soup.find_previous_sibling('div', class_='A')

result = soup.find_all('div', class_=['A'])
result = soup.find('div', class_=['A'])

result = soup.find_all('div')
result = soup.find('div')
result = soup.find_all('div', other=['A', 'B'])

def not_beautifulsoup(some_obj):
    result = some_obj.find_all('div', class_=['A', 'B'])
    result = some_obj.findAll('div', class_=['A', 'B'])
    result = some_obj.find('div', class_=['A', 'B'])
    result = some_obj.findChild('div', class_=['A', 'B'])
    result = some_obj.find_parent('div', class_=['A', 'B'])
    result = some_obj.findParent('div', class_=['A', 'B'])
";
        let report = scan(source);
        assert!(findings(&report, KEY).is_empty());
    }
}
