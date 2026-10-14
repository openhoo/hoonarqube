//! `ruby:S1134` and `ruby:S1135` — track the first eligible FIXME or TODO
//! tag in each parsed comment. The tag boundaries and messages are pinned
//! to the Ruby 1.25.0.2597 plugin in the `SonarQube` 26.9 reference.

use std::sync::LazyLock;

use crate::support::{SourceMap, node_text, walk};
use hoonarqube_ir::Issue;
use regex::Regex;
use tree_sitter::Node;

static TODO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|[^\p{L}0-9])(?i-u:(todo))($|[^\p{L}0-9])")
        .expect("constant TODO comment pattern")
});
static FIXME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|[^\p{L}0-9])(?i-u:(fixme))($|[^\p{L}0-9])")
        .expect("constant FIXME comment pattern")
});

pub(crate) fn check(root: Node<'_>, source: &str) -> Vec<Issue> {
    if root.has_error() {
        return Vec::new();
    }
    let map = SourceMap::new(source);
    let mut issues = Vec::new();
    walk(root, |node| {
        if node.kind() != "comment" {
            return;
        }
        for (pattern, key, message) in [
            (
                &*TODO,
                "ruby:S1135",
                "Complete the task associated to this TODO comment.",
            ),
            (
                &*FIXME,
                "ruby:S1134",
                "Take the required action to fix the issue indicated by this \"FIXME\" comment.",
            ),
        ] {
            if let Some(tag) = pattern
                .captures(node_text(node, source))
                .and_then(|captures| captures.get(2))
            {
                issues.push(Issue::new(
                    key,
                    message,
                    map.range(
                        node.start_byte() + tag.start(),
                        node.start_byte() + tag.end(),
                    ),
                ));
            }
        }
    });
    issues
}
