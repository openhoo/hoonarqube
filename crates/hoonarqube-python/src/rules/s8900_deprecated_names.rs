use std::collections::HashSet;

use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::engine::file_context::FileContext;
use crate::rules::bs4_page_elements::is_page_element;
use crate::support::{WebFrameworkFacts, issue_at, keyword_name_range};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8900";

/// Beautiful Soup 3 camelCase methods kept as deprecated aliases in bs4,
/// mapped to their modern names (Sonar's `DEPRECATED_METHODS`).
const DEPRECATED_METHODS: &[(&str, &str)] = &[
    ("findAll", "find_all"),
    ("findChild", "find"),
    ("findChildren", "find_all"),
    ("findNext", "find_next"),
    ("findAllNext", "find_all_next"),
    ("findPrevious", "find_previous"),
    ("findAllPrevious", "find_all_previous"),
    ("findNextSibling", "find_next_sibling"),
    ("findNextSiblings", "find_next_siblings"),
    ("findPreviousSibling", "find_previous_sibling"),
    ("findPreviousSiblings", "find_previous_siblings"),
    ("findParent", "find_parent"),
    ("findParents", "find_parents"),
    ("replaceWith", "replace_with"),
    ("getText", "get_text"),
];

/// Deprecated camelCase navigation attributes (Sonar's `DEPRECATED_ATTRS`).
const DEPRECATED_ATTRS: &[(&str, &str)] = &[
    ("nextSibling", "next_sibling"),
    ("previousSibling", "previous_sibling"),
];

/// Methods that accept the deprecated `text=` keyword: the modern
/// find-family names plus the deprecated aliases that map onto them.
/// `find_parent`/`find_parents` (and their aliases) take no `string=`
/// argument, and `replace_with`/`get_text` are not find methods, so all
/// four spellings are absent — matching Sonar's `FIND_FAMILY_METHODS`.
const FIND_FAMILY_METHODS: &[&str] = &[
    "find",
    "find_all",
    "find_next",
    "find_all_next",
    "find_previous",
    "find_all_previous",
    "find_next_sibling",
    "find_next_siblings",
    "find_previous_sibling",
    "find_previous_siblings",
    "findAll",
    "findChild",
    "findChildren",
    "findNext",
    "findAllNext",
    "findPrevious",
    "findAllPrevious",
    "findNextSibling",
    "findNextSiblings",
    "findPreviousSibling",
    "findPreviousSiblings",
];

/// python:S8900 — Beautiful Soup 3's camelCase API still works in bs4 but
/// is deprecated. On a `bs4.element.PageElement` receiver Sonar flags the
/// deprecated method name in a call (`Replace the deprecated
/// 'findAll()' method with 'find_all()'.`), a bare deprecated attribute read
/// (`soup.nextSibling`), and the `text=` keyword on any find-family call —
/// a deprecated method call carrying `text=` raises both issues.
pub(crate) fn check_s8900_deprecated_names(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();

    // Attribute expressions that are the callee of a call are handled by
    // the call pass below; Sonar's QUALIFIED_EXPR consumer skips them.
    let callee_ranges: HashSet<TextRange> = file_ctx
        .calls
        .iter()
        .map(|call| call.func.range())
        .collect();

    for call in &file_ctx.calls {
        let Expr::Attribute(attribute) = call.func.as_ref() else {
            continue;
        };
        if !is_page_element(&facts, &attribute.value) {
            continue;
        }
        let method = attribute.attr.as_str();
        if let Some(modern) = deprecated_method(method) {
            issues.push(issue_at(
                RULE_KEY,
                &format!("Replace the deprecated '{method}()' method with '{modern}()'."),
                attribute.attr.range(),
                index,
                source,
            ));
        }
        if FIND_FAMILY_METHODS.contains(&method)
            && let Some(text_range) = keyword_name_range(call, "text")
        {
            issues.push(issue_at(
                RULE_KEY,
                "Replace the deprecated 'text' keyword argument with 'string'.",
                text_range,
                index,
                source,
            ));
        }
    }

    for expr in &file_ctx.exprs {
        let Expr::Attribute(attribute) = expr else {
            continue;
        };
        if callee_ranges.contains(&expr.range()) {
            continue;
        }
        let Some(modern) = deprecated_attr(attribute.attr.as_str()) else {
            continue;
        };
        if !is_page_element(&facts, &attribute.value) {
            continue;
        }
        issues.push(issue_at(
            RULE_KEY,
            &format!(
                "Replace the deprecated '{}' attribute with '{modern}'.",
                attribute.attr.as_str()
            ),
            attribute.attr.range(),
            index,
            source,
        ));
    }
    issues
}

fn deprecated_method(name: &str) -> Option<&'static str> {
    DEPRECATED_METHODS
        .iter()
        .find(|(deprecated, _)| *deprecated == name)
        .map(|(_, modern)| *modern)
}

fn deprecated_attr(name: &str) -> Option<&'static str> {
    DEPRECATED_ATTRS
        .iter()
        .find(|(deprecated, _)| *deprecated == name)
        .map(|(_, modern)| *modern)
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    const KEY: &str = "python:S8900";

    #[test]
    fn s8900_flags_the_sonar_noncompliant_examples() {
        let source = r"from bs4 import BeautifulSoup

soup = BeautifulSoup(html, 'html.parser')
result = soup.find_all('a', text='Click here')
result = soup.findAll('a', string='Click here')
";
        let report = scan(source);
        let found = findings(&report, KEY);
        assert_eq!(found.len(), 2);
        assert_eq!(
            found[0].message,
            "Replace the deprecated 'text' keyword argument with 'string'."
        );
        assert_eq!(found[0].range.start, pos(4, 28));
        assert_eq!(
            found[1].message,
            "Replace the deprecated 'findAll()' method with 'find_all()'."
        );
        assert_eq!(found[1].range.start, pos(5, 14));
        assert_eq!(found[1].range.end, pos(5, 21));
    }

    #[test]
    fn s8900_flags_every_deprecated_method_on_soup_and_tag() {
        let source = r"from bs4 import BeautifulSoup, Tag

soup = BeautifulSoup(html, 'html.parser')
tag = Tag(name='a')

soup.findAll('a')
soup.findChild('a')
soup.findChildren('a')
soup.findNext('a')
soup.findAllNext('a')
soup.findPrevious('a')
soup.findAllPrevious('a')
soup.findNextSibling('a')
soup.findNextSiblings('a')
soup.findPreviousSibling('a')
soup.findPreviousSiblings('a')
soup.findParent('a')
soup.findParents('a')
soup.replaceWith('other')
soup.getText()

tag.findAll('b')
tag.findChild('b')
tag.findNext('b')
tag.getText()
";
        let report = scan(source);
        assert_eq!(findings(&report, KEY).len(), 19);
    }

    #[test]
    fn s8900_flags_deprecated_attributes_and_text_keyword() {
        let source = r"from bs4 import BeautifulSoup, Tag

soup = BeautifulSoup(html, 'html.parser')
tag = Tag(name='a')

_ = soup.nextSibling
_ = soup.previousSibling
_ = tag.nextSibling
_ = tag.previousSibling

soup.find('a', text='Click here')
soup.find_all('a', text='Click here')
soup.find_next('a', text='x')
soup.find_all_next('a', text='x')
soup.find_previous('a', text='x')
soup.find_all_previous('a', text='x')
soup.find_next_sibling('a', text='x')
soup.find_next_siblings('a', text='x')
soup.find_previous_sibling('a', text='x')
soup.find_previous_siblings('a', text='x')
";
        let report = scan(source);
        assert_eq!(findings(&report, KEY).len(), 14);
    }

    #[test]
    fn s8900_raises_both_issues_on_deprecated_method_with_text() {
        let source = r"from bs4 import BeautifulSoup

soup = BeautifulSoup(html, 'html.parser')
soup.findAll('a', text='Click here')
";
        let report = scan(source);
        let found = findings(&report, KEY);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn s8900_accepts_the_sonar_compliant_examples() {
        let source = r"from bs4 import BeautifulSoup, Tag

soup = BeautifulSoup(html, 'html.parser')
tag = Tag(name='a')

soup.find('a')
soup.find_all('a')
soup.find_next('a')
soup.find_all_next('a')
soup.find_previous('a')
soup.find_all_previous('a')
soup.find_next_sibling('a')
soup.find_next_siblings('a')
soup.find_previous_sibling('a')
soup.find_previous_siblings('a')
soup.find_parent('a')
soup.find_parents('a')
soup.replace_with('other')
soup.get_text()

_ = soup.next_sibling
_ = soup.previous_sibling
_ = tag.next_sibling
_ = tag.previous_sibling

soup.find('a', string='Click here')
soup.find_all('a', string='Click here')

# find_parent/find_parents take no string= argument, so text= is not
# the deprecated alias there.
soup.find_parent('a', text='x')
soup.find_parents('a', text='x')
";
        let report = scan(source);
        assert!(findings(&report, KEY).is_empty());
    }

    #[test]
    fn s8900_ignores_non_bs4_receivers() {
        let source = r"class FakeElement:
    def findAll(self):
        pass
    nextSibling = None

obj = FakeElement()
obj.findAll()
_ = obj.nextSibling
";
        let report = scan(source);
        assert!(findings(&report, KEY).is_empty());
    }
}
