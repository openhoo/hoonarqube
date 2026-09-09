use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::token::{Tokens, parentheses_iterator};
use ruff_python_ast::visitor::source_order::{SourceOrderVisitor, TraversalSignal, walk_body};
use ruff_python_ast::{AnyNodeRef, ModModule};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{TextRange, TextSize};

// --- python:S1110 — redundant pairs of parentheses -----------------------------
//
// Ruff intentionally drops grouping nodes from its AST.  The expression range
// and `parentheses_iterator` retain enough syntax to recover those groups
// without reparsing source text.  The iterator is parent-aware: when the
// expression is a direct call argument it excludes the call's own required
// delimiters, so `foo((value))` is not mistaken for a redundant pair.

const MESSAGE: &str = "Remove those redundant parentheses.";

pub(crate) fn check_redundant_parentheses(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut visitor = S1110Visitor {
        tokens: parsed.tokens(),
        parents: Vec::new(),
        anchors: Some(Vec::new()),
        target: None,
        match_pair: None,
    };
    walk_body(&mut visitor, parsed.suite());

    let mut anchors = visitor
        .anchors
        .expect("S1110 detector visitor collects anchors");
    anchors.sort_unstable();
    anchors.dedup();
    anchors
        .into_iter()
        .map(|open| {
            issue_at(
                "python:S1110",
                MESSAGE,
                TextRange::at(open, TextSize::new(1)),
                index,
                source,
            )
        })
        .collect()
}

/// Returns the exact optional parenthesis pair represented by an S1110 issue
/// anchor.  Quick-fix planning uses this locator so it cannot drift from the
/// detector's parent-aware AST/token interpretation; collection nodes retain
/// their required inner pair while this returns only the removable outer pair.
pub(crate) fn redundant_parentheses_range(
    parsed: &Parsed<ModModule>,
    anchor: TextSize,
) -> Option<TextRange> {
    let mut visitor = S1110Visitor {
        tokens: parsed.tokens(),
        parents: Vec::new(),
        anchors: None,
        target: Some(anchor),
        match_pair: None,
    };
    walk_body(&mut visitor, parsed.suite());
    visitor.match_pair
}

struct S1110Visitor<'a> {
    tokens: &'a Tokens,
    parents: Vec<AnyNodeRef<'a>>,
    anchors: Option<Vec<TextSize>>,
    target: Option<TextSize>,
    match_pair: Option<TextRange>,
}

impl<'a> SourceOrderVisitor<'a> for S1110Visitor<'a> {
    fn enter_node(&mut self, node: AnyNodeRef<'a>) -> TraversalSignal {
        if let Some(expression) = node.as_expr_ref() {
            let parent = self.parents.last().copied();
            // Tuple/generator ranges include their own required delimiters.
            // `parentheses_iterator` therefore returns only optional outer
            // pairs for these nodes.  Other expression ranges exclude all
            // grouping pairs; retain the nearest one and report only the
            // redundant outer pairs.
            let parenthesized_collection = matches!(
                node,
                AnyNodeRef::ExprTuple(tuple) if tuple.parenthesized
            ) || matches!(
                node,
                AnyNodeRef::ExprGenerator(generator) if generator.parenthesized
            );

            let pairs = parentheses_iterator(expression, parent, self.tokens);
            let pairs = if parenthesized_collection {
                pairs.collect::<Vec<_>>()
            } else {
                pairs.skip(1).collect::<Vec<_>>()
            };
            for pair in pairs {
                if self.target == Some(pair.start()) {
                    self.match_pair = Some(pair);
                }
                if let Some(anchors) = &mut self.anchors {
                    anchors.push(pair.start());
                }
            }
        }
        self.parents.push(node);
        TraversalSignal::Traverse
    }

    fn leave_node(&mut self, _node: AnyNodeRef<'a>) {
        let _ = self.parents.pop();
    }
}
