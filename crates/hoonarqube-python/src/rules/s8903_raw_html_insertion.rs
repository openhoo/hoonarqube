use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::rules::bs4_page_elements::is_page_element;
use crate::support::{WebFrameworkFacts, issue_at, nth_or_keyword_argument};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8903";
const MESSAGE: &str = "Use \"new_tag()\" instead of inserting raw HTML strings.";

/// python:S8903 — inserting a raw markup string into the tree stores it as
/// escaped text, not as elements. Sonar flags the `insert`/`append`/
/// `extend` method name on a `bs4.element.PageElement` receiver when the
/// inserted content (`insert`'s second positional or `new_child` keyword,
/// `append`'s `tag`, `extend`'s `tags`) is a string literal shaped like a
/// tag — starting with `<` and ending with `>` — including a name bound
/// once to such a literal. Plain text, lists, and non-bs4 receivers stay
/// silent.
pub(crate) fn check_s8903_raw_html_insertion(
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
        let (position, keyword) = match attribute.attr.as_str() {
            "insert" => (1, "new_child"),
            "append" => (0, "tag"),
            "extend" => (0, "tags"),
            _ => continue,
        };
        if !is_page_element(&facts, &attribute.value) {
            continue;
        }
        let Some(content) = nth_or_keyword_argument(call, position, keyword) else {
            continue;
        };
        if !looks_like_html_markup(&facts, content) {
            continue;
        }
        issues.push(issue_at(
            RULE_KEY,
            MESSAGE,
            attribute.attr.range(),
            index,
            source,
        ));
    }
    issues
}

/// Sonar's `Expressions.extractStringLiteral`: a string literal, or a name
/// bound exactly once to one, whose value starts with `<` and ends with
/// `>` — the shape of a markup fragment rather than plain text.
fn looks_like_html_markup(facts: &WebFrameworkFacts<'_>, expr: &Expr) -> bool {
    let literal_text = match expr {
        Expr::StringLiteral(literal) => Some(literal.value.to_str()),
        Expr::Name(name) => match facts.single_assigned_value(name.id.as_str(), name.range()) {
            Some(Expr::StringLiteral(literal)) => Some(literal.value.to_str()),
            _ => None,
        },
        _ => None,
    };
    literal_text.is_some_and(|text| text.starts_with('<') && text.ends_with('>'))
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    const KEY: &str = "python:S8903";

    #[test]
    fn s8903_flags_the_sonar_noncompliant_examples() {
        let source = r#"from bs4 import BeautifulSoup

soup = BeautifulSoup('<html><body></body></html>', 'html.parser')
soup.body.insert(0, '<div id="file_history"></div>')
"#;
        let report = scan(source);
        let found = findings(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Use \"new_tag()\" instead of inserting raw HTML strings."
        );
        // Sonar anchors on the `insert` method name.
        assert_eq!(found[0].range.start, pos(4, 10));
        assert_eq!(found[0].range.end, pos(4, 16));
    }

    #[test]
    fn s8903_flags_insert_append_extend_on_soup_and_tags() {
        let source = r#"from bs4 import BeautifulSoup

soup = BeautifulSoup('<html><body></body></html>', 'html.parser')

soup.insert(0, '<div id="file_history"></div>')
soup.append('<p>some text</p>')
tag = soup.new_tag('section')
tag.insert(0, '<span class="x"></span>')
tag.append('<b>bold</b>')
tag.extend('<li>item</li>')
soup.extend(tags='<li>item</li>')

html_fragment = '<div class="content"></div>'
tag.insert(0, html_fragment)
tag.append(html_fragment)
"#;
        let report = scan(source);
        assert_eq!(findings(&report, KEY).len(), 8);
    }

    #[test]
    fn s8903_accepts_the_sonar_compliant_examples() {
        let source = r#"from bs4 import BeautifulSoup

soup = BeautifulSoup('<html><body></body></html>', 'html.parser')
tag = soup.new_tag('section')

soup.append("Hello world")
tag.insert(0, "some text")

new_tag = soup.new_tag('div', id='file_history')
soup.insert(0, new_tag)
soup.append(new_tag)

soup.insert(0, 42)
soup.append(None)
soup.extend([new_tag])
soup.extend(tags=['<li>item</li>'])
soup.append("<= 3")

my_list = [1, 2, 3]
my_list.insert(0, '<div>')
my_list.append('<p>')
"#;
        let report = scan(source);
        assert!(findings(&report, KEY).is_empty());
    }

    #[test]
    fn s8903_ignores_untyped_receivers() {
        let source = r"def render(element):
    element.append('<p>x</p>')
    element.insert(0, '<p>x</p>')
";
        let report = scan(source);
        assert!(findings(&report, KEY).is_empty());
    }
}
