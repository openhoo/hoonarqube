//! Ruby S1186: report a method whose implementation is empty and undocumented.

use crate::support::{SourceMap, walk};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

pub(crate) fn check(root: Node<'_>, source: &str) -> Vec<Issue> {
    if root.has_error() {
        return Vec::new();
    }
    let map = std::cell::OnceCell::new();
    let mut comments = Vec::new();
    let mut methods = Vec::new();
    walk(root, |node| match node.kind() {
        "comment" => comments.push((node.start_byte(), node.start_position().row)),
        "method" | "singleton_method" if is_empty(node, source) => methods.push(node),
        _ => {}
    });
    methods.into_iter().filter_map(|node| {
        let end = node.end_byte();
        let row = node.end_position().row;
        let index = comments.partition_point(|&(offset, _)| offset < node.start_byte());
        if let Some(&(offset, line)) = comments.get(index)
            && (offset < end || (line == row && offset < parent_extent(node))) {
            return None;
        }
        Some(Issue::new(
            "ruby:S1186",
            "Add a nested comment explaining why this function is empty or complete the implementation.",
            map.get_or_init(|| SourceMap::new(source)).node_range(node),
        ))
    }).collect()
}

fn is_empty(node: Node<'_>, source: &str) -> bool {
    if node
        .child_by_field_name("name")
        .is_some_and(|name| &source[name.byte_range()] == "initialize")
    {
        return false;
    }
    let Some(body) = node.child_by_field_name("body") else {
        return true;
    };
    let mut cursor = body.walk();
    body.kind() == "body_statement"
        && body
            .named_children(&mut cursor)
            .all(|n| matches!(n.kind(), "empty_statement" | "comment"))
}

/// The reference attaches a trailing comment only while it is inside the
/// enclosing expression. A list of statements ends at its last statement.
fn parent_extent(node: Node<'_>) -> usize {
    let Some(parent) = node.parent() else {
        return node.end_byte();
    };
    if !matches!(
        parent.kind(),
        "program" | "body_statement" | "then" | "else" | "block_body"
    ) {
        return parent.end_byte();
    }
    let mut back = (0..parent.named_child_count())
        .rev()
        .filter_map(|i| parent.named_child(i))
        .filter(|child| !matches!(child.kind(), "comment" | "empty_statement"));
    let Some(last) = back.next() else {
        return node.end_byte();
    };
    // A single statement in a class, module, conditional or block has the
    // surrounding construct as its parent. A method body has its own extent.
    if last.id() == node.id()
        && back.next().is_none()
        && let Some(outer) = parent.parent()
        && matches!(
            outer.kind(),
            "class" | "module" | "if" | "unless" | "do_block" | "block" | "singleton_class"
        )
    {
        return outer.end_byte();
    }
    last.end_byte()
}

#[cfg(test)]
mod tests {
    use crate::{AnalyzerOptions, analyze};
    use std::path::PathBuf;

    fn empty_methods(source: &str) -> Vec<(u32, u32, u32, u32)> {
        analyze(
            PathBuf::from("control.rb"),
            source,
            &AnalyzerOptions::default(),
        )
        .issues
        .into_iter()
        .filter(|issue| issue.rule_key == "ruby:S1186")
        .map(|issue| {
            let r = issue.range;
            (r.start.line, r.start.column, r.end.line, r.end.column)
        })
        .collect()
    }

    #[test]
    fn reports_empty_instance_and_singleton_methods_over_the_declaration() {
        let source = "# Outside the declaration\ndef ready?(value)\nend\n\n'💎'; def self.ready; end # outside\n";
        assert_eq!(empty_methods(source), vec![(2, 0, 3, 3), (5, 5, 5, 24)]);
    }

    #[test]
    fn documented_or_implemented_methods_are_not_empty() {
        let source = "def documented\n  # No teardown needed.\nend\ndef value = nil\ndef unused; return; end\ndef computed; []; end\n";
        assert!(empty_methods(source).is_empty());
    }
    #[test]
    fn matches_captured_comment_scopes_and_declaration_forms() {
        let cases: &[(&str, &str, &[u32])] = &[
            (
                "syntax",
                include_str!("../tests/fixtures/empty-methods/syntax.rb"),
                &[16, 20, 21, 33, 34, 36, 37],
            ),
            (
                "context",
                include_str!("../tests/fixtures/empty-methods/context.rb"),
                &[4, 6, 11, 13, 16, 18, 19],
            ),
            (
                "parent",
                include_str!("../tests/fixtures/empty-methods/parent.rb"),
                &[3, 10, 14, 19, 24, 28, 31],
            ),
            (
                "scope",
                include_str!("../tests/fixtures/empty-methods/scope.rb"),
                &[6, 9, 18, 18, 20],
            ),
        ];
        for &(name, source, expected) in cases {
            let mut expected = expected.to_vec();
            expected.sort_unstable();
            let mut lines: Vec<_> = empty_methods(source).into_iter().map(|r| r.0).collect();
            lines.sort_unstable();
            assert_eq!(lines, expected, "{name}");
        }
    }
}
