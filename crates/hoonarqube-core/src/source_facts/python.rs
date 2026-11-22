//! Python CPD compares lexical images exposed by the reference syntax tree.
//! Keep strings, indentation boundaries and omitted punctuation in this
//! language-specific walk; the shared detector still owns matching and limits.

use super::{FactCollector, Node, TreeCursor};

enum Event<'tree> {
    Node(Node<'tree>),
    Image(usize, usize),
    Dedent,
}

impl FactCollector<'_> {
    pub(super) fn walk_python(&mut self, root: Node<'_>) {
        let mut stack = vec![Event::Node(root)];
        let mut cursor = root.walk();
        while let Some(event) = stack.pop() {
            if self.stopped {
                break;
            }
            match event {
                Event::Dedent => self.python_dedent(),
                Event::Image(start, end) => self.python_image(start, end),
                Event::Node(node) if self.visit_tree_node() && !node.is_missing() => {
                    self.python_node(node, &mut cursor, &mut stack);
                }
                Event::Node(_) => {}
            }
        }
    }

    fn python_node<'tree>(
        &mut self,
        node: Node<'tree>,
        cursor: &mut TreeCursor<'tree>,
        stack: &mut Vec<Event<'tree>>,
    ) {
        let kind = node.kind();
        if node.is_extra() || kind == "comment" {
            return;
        }
        if kind == "block" && is_indented_suite(node) {
            stack.push(Event::Dedent);
        }
        let literal = kind == "string" && !is_formatted(node, self.source);
        if literal || matches!(kind, "string_start" | "string_content" | "string_end") {
            self.python_image(node.start_byte(), node.end_byte());
        } else if node.child_count() == 0 {
            self.python_leaf(node);
        } else {
            push_children(node, cursor, stack);
        }
    }

    fn python_leaf(&mut self, node: Node<'_>) {
        let kind = node.kind();
        if matches!(kind, "," | "(" | ")") && delimiter_omitted(node) {
            return;
        }
        let start = node.start_byte();
        let end = node.end_byte();
        if matches!(kind, "->" | "ellipsis" | "type_conversion") {
            // The reference emits the dots, arrow and !r/!s/!a as separate
            // tokens, which matters for the minimum token count of a clone.
            for pos in start..end {
                self.python_image(pos, pos + 1);
            }
        } else if start < end {
            self.python_image(start, end);
        }
    }

    fn python_image(&mut self, start: usize, end: usize) {
        if self.stopped {
            return;
        }
        self.key_buffer.clear();
        self.key_buffer.push_str(&self.source[start..end]);
        self.emit_buffered_byte_range(start, end);
    }

    fn python_dedent(&mut self) {
        let Some(last) = self.tokens.last() else {
            return;
        };
        if last.start_byte == last.end_byte {
            return;
        }
        // Comments and empty lines do not move the preceding logical newline.
        // Nested suites ending together have a single newline before the
        // first DEDENT. Keep it zero-width so clone spans end on source text.
        let end = last.end_byte as usize;
        let row = last.end_line;
        self.key_buffer.clear();
        self.key_buffer.push('\n');
        self.emit_buffered_byte_range(end, end);
        if let Some(marker) = self
            .tokens
            .last_mut()
            .filter(|t| t.start_byte == t.end_byte)
        {
            marker.start_line = row;
            marker.end_line = row;
        }
    }
}

fn is_formatted(node: Node<'_>, source: &str) -> bool {
    node.child(0).is_some_and(|start| {
        source[start.byte_range()]
            .bytes()
            .take_while(u8::is_ascii_alphabetic)
            .any(|b| matches!(b, b'f' | b'F' | b't' | b'T'))
    })
}

fn is_indented_suite(node: Node<'_>) -> bool {
    // Compare with the colon, since a multiline header can have its simple
    // suite on the same physical line as the colon.
    let mut prev = node.prev_sibling();
    while prev.is_some_and(|n| n.is_extra()) {
        prev = prev.and_then(|n| n.prev_sibling());
    }
    prev.is_some_and(|n| node.start_position().row > n.end_position().row)
}

fn delimiter_omitted(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| match parent.kind() {
        "import_statement" | "import_from_statement" | "future_import_statement" => true,
        "assert_statement" => node.kind() == ",",
        _ => false,
    })
}

fn push_children<'tree>(
    node: Node<'tree>,
    cursor: &mut TreeCursor<'tree>,
    stack: &mut Vec<Event<'tree>>,
) {
    let format = node.kind() == "format_specifier";
    let mut end = node.end_byte();
    cursor.reset(node);
    if cursor.goto_last_child() {
        loop {
            let child = cursor.node();
            // Format text between fields has no named tree-sitter node.
            if format && child.end_byte() < end {
                stack.push(Event::Image(child.end_byte(), end));
            }
            stack.push(Event::Node(child));
            end = child.start_byte();
            if !cursor.goto_previous_sibling() {
                break;
            }
        }
    }
}
