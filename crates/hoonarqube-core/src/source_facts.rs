//! Syntax-aware source facts shared by project measurement and duplication.
//!
//! This module deliberately has no rule-engine dependencies.  Tree-sitter's
//! concrete syntax trees provide enough structure to keep comments, literal
//! delimiters, interpolation, and layout-sensitive Python constructs apart
//! while a single iterative walk collects both tokens and line metrics.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

use hoonarqube_ir::FileMetrics;
use tree_sitter::{Node, Parser};

use crate::Language;

/// A normalized syntax token.  Lines are one-based and inclusive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedToken {
    pub symbol: u32,
    pub start_line: u32,
    pub end_line: u32,
    pub start_byte: u32,
    pub end_byte: u32,
}

/// Facts collected from one source snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFacts {
    pub metrics: FileMetrics,
    pub tokens: Vec<NormalizedToken>,
    pub symbols: Vec<String>,
    /// Exact compositional definitions of Java statement units; empty for
    /// other languages and Razor.  See [`UnitDefinition`].
    pub units: Vec<UnitDefinition>,
    pub error: Option<String>,
    pub language: Language,
}

/// Exact compositional definition of one Java statement unit.
///
/// `token` is the index of the unit's emitted [`NormalizedToken`]; `symbol`
/// is the interned own-parts signature: the unit's normalized content with
/// the reserved `<unit>` marker (plus nested unit kind) recorded at exactly
/// the positions where the historical flattened signature carried them, but
/// without re-traversing nested unit subtrees.  `children` are indices into
/// the same vector and are strictly smaller than the definition's own index,
/// so the vector is a post-order forest.  Expanding a definition over its
/// children reproduces the complete normalized nested content byte-for-byte;
/// equality of two units is exact structural equality over interned strings
/// and no hash participates in that decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitDefinition {
    pub token: u32,
    pub symbol: u32,
    pub children: Vec<u32>,
}

/// Adapts complete compiler-backed Razor measurements to the project facts
/// shape without pretending that Razor has a tree-sitter token stream.
///
/// The returned facts are intentionally not suitable for duplication on their
/// own.  Callers must mark the owning project input as duplication-excluded;
/// Razor is a compiler-only dialect rather than a ninth CPD grammar.
#[must_use]
pub fn compiler_razor_facts(path: &Path, metrics: FileMetrics) -> Option<SourceFacts> {
    crate::is_razor_path(path).then_some(SourceFacts {
        metrics,
        tokens: Vec::new(),
        symbols: Vec::new(),
        units: Vec::new(),
        error: None,
        language: Language::CSharp,
    })
}

// Parsing is deliberately bounded before handing input to a grammar.  The
// limit is large enough for ordinary repositories and makes a hostile single
// file fail closed instead of reserving unbounded parser/tree memory.
const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SOURCE_LINES: usize = 4 * 1024 * 1024;
const MAX_TREE_NODES: usize = 8 * 1024 * 1024;
const MAX_FACT_TOKENS: usize = 2 * 1024 * 1024;
const MAX_INTERPOLATION_SCAN_NODES: usize = 100_000;
const MAX_SIGNATURE_BYTES: usize = 32 * 1024 * 1024;
/// Returns whether a registered source would be rejected before parser
/// construction.  Project orchestration uses this cheap preflight to avoid
/// handing resource-sized input to native analyzers first.
pub(crate) fn source_exceeds_limits(path: &Path, source: &str) -> bool {
    let Some(language) = crate::language_for_path(path) else {
        return false;
    };
    source.len() > MAX_SOURCE_BYTES || semantic_line_count(source, language) > MAX_SOURCE_LINES
}

/// Collect syntax facts for a supported source path.
///
/// `None` means that the extension is not one of the registered language
/// families.  Razor is registered with the C# family but is deliberately
/// represented as an incomplete fact set here: only a complete trusted
/// compiler context can provide its source classification and metrics.
/// Parser, grammar, input-limit, and traversal failures are represented in
/// [`SourceFacts::error`] so callers cannot mistake a partial stream for a
/// complete measurement.
#[must_use]
pub fn collect_source_facts(path: &Path, source: &str) -> Option<SourceFacts> {
    let language = crate::language_for_path(path)?;
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    if crate::is_razor_path(path) {
        return Some(SourceFacts {
            metrics: FileMetrics {
                lines: 0,
                code_lines: 0,
                comment_lines: 0,
            },
            tokens: Vec::new(),
            symbols: Vec::new(),
            units: Vec::new(),
            error: Some(
                "Razor source facts require a complete trusted C# compiler context".to_owned(),
            ),
            language,
        });
    }
    // Count before retaining one byte offset per line.  Rejected inputs can
    // be tens of megabytes of newline-only text, so they must not allocate a
    // line-start map just to produce fallback metrics.
    if source.len() > MAX_SOURCE_BYTES {
        let physical_lines = semantic_line_count(source, language);
        return Some(SourceFacts {
            metrics: fallback_metrics(source, language),
            tokens: Vec::new(),
            symbols: Vec::new(),
            units: Vec::new(),
            error: Some(format!(
                "source exceeds bounded facts input ({} bytes, {} lines)",
                source.len(),
                physical_lines
            )),
            language,
        });
    }
    let physical_lines = semantic_line_count(source, language);
    if physical_lines > MAX_SOURCE_LINES {
        return Some(SourceFacts {
            metrics: fallback_metrics(source, language),
            tokens: Vec::new(),
            symbols: Vec::new(),
            units: Vec::new(),
            error: Some(format!(
                "source exceeds bounded facts input ({} bytes, {} lines)",
                source.len(),
                physical_lines
            )),
            language,
        });
    }
    let line_starts = semantic_line_starts(source, language);

    let mut parser = Parser::new();
    if let Err(error) = set_parser_language(&mut parser, language, extension) {
        return Some(SourceFacts {
            metrics: fallback_metrics(source, language),
            tokens: Vec::new(),
            symbols: Vec::new(),
            units: Vec::new(),
            error: Some(error),
            language,
        });
    }
    let parser_source = if language == Language::Java {
        normalize_java_parser_source(source)
    } else {
        Cow::Borrowed(source)
    };
    let Some(tree) = parser.parse(parser_source.as_ref(), None) else {
        return Some(SourceFacts {
            metrics: fallback_metrics(source, language),
            tokens: Vec::new(),
            symbols: Vec::new(),
            units: Vec::new(),
            error: Some("tree-sitter returned no syntax tree".to_owned()),
            language,
        });
    };
    let parse_error = tree
        .root_node()
        .has_error()
        .then(|| "syntax tree contains recovered or missing nodes".to_owned());
    let mut collector = FactCollector::new(source, language, physical_lines, line_starts);
    collector.walk(tree.root_node());
    let metrics = collector.metrics();
    let error = collector.error.or(parse_error);

    Some(SourceFacts {
        metrics,
        tokens: collector.tokens,
        symbols: collector.symbols,
        units: collector.java_definitions,
        error,
        language,
    })
}

fn set_parser_language(
    parser: &mut Parser,
    language: Language,
    extension: &str,
) -> Result<(), String> {
    let result = match language {
        Language::Python => parser.set_language(&tree_sitter_python::LANGUAGE.into()),
        Language::JavaScript => parser.set_language(&tree_sitter_javascript::LANGUAGE.into()),
        Language::TypeScript => {
            if extension.eq_ignore_ascii_case("tsx") {
                parser.set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
            } else {
                parser.set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            }
        }
        Language::CSharp => parser.set_language(&tree_sitter_c_sharp::LANGUAGE.into()),
        Language::Go => parser.set_language(&tree_sitter_go::LANGUAGE.into()),
        Language::Java => parser.set_language(&tree_sitter_java::LANGUAGE.into()),
        Language::Rust => parser.set_language(&tree_sitter_rust::LANGUAGE.into()),
        Language::Ruby => parser.set_language(&tree_sitter_ruby::LANGUAGE.into()),
    };
    result.map_err(|_| "tree-sitter grammar is unavailable or incompatible".to_owned())
}
/// Tree-sitter Java's line-comment grammar only recognizes LF.  Java source
/// semantics also treat a lone CR as a line terminator, so normalize only the
/// parser view while retaining the original byte-identical source for facts.
fn normalize_java_parser_source(source: &str) -> Cow<'_, str> {
    let bytes = source.as_bytes();
    let mut normalized = None;
    let mut segment_start = 0;
    for (offset, character) in source.char_indices() {
        if character == '\r' && bytes.get(offset + 1) != Some(&b'\n') {
            let output = normalized.get_or_insert_with(|| String::with_capacity(source.len()));
            output.push_str(&source[segment_start..offset]);
            output.push('\n');
            segment_start = offset + 1;
        }
    }
    if let Some(mut output) = normalized {
        output.push_str(&source[segment_start..]);
        Cow::Owned(output)
    } else {
        Cow::Borrowed(source)
    }
}

struct RowFlags {
    code: Vec<bool>,
    comment: Vec<bool>,
}

impl RowFlags {
    fn new(lines: usize) -> Self {
        Self {
            code: vec![false; lines],
            comment: vec![false; lines],
        }
    }

    fn mark(&mut self, start_line: u32, end_line: u32, code: bool) {
        if self.code.is_empty() {
            return;
        }
        let last = saturating_u32(self.code.len());
        let mut start = start_line.max(1).min(last);
        let end = end_line.max(start).min(last);
        let rows = if code {
            &mut self.code
        } else {
            &mut self.comment
        };
        while start <= end {
            rows[start as usize - 1] = true;
            if start == u32::MAX {
                break;
            }
            start += 1;
        }
    }

    fn metrics(&self, lines: usize) -> FileMetrics {
        let code_lines = self.code.iter().filter(|value| **value).count();
        let comment_lines = self
            .comment
            .iter()
            .zip(self.code.iter())
            .filter(|(comment, code)| **comment && !**code)
            .count();
        FileMetrics {
            lines: saturating_u32(lines),
            code_lines: saturating_u32(code_lines),
            comment_lines: saturating_u32(comment_lines),
        }
    }
}

struct FactCollector<'source> {
    source: &'source str,
    language: Language,
    physical_lines: usize,
    line_starts: Vec<usize>,
    rows: RowFlags,
    tokens: Vec<NormalizedToken>,
    symbols: Vec<String>,
    interned: HashMap<u64, Vec<u32>>,
    key_buffer: String,
    visited_nodes: usize,
    signature_nodes: usize,
    java_units: Vec<JavaUnitRecord>,
    java_unit_index: HashMap<usize, usize>,
    java_unit_parent: HashMap<usize, usize>,
    java_unit_children: Vec<usize>,
    java_definitions: Vec<UnitDefinition>,
    error: Option<String>,
    stopped: bool,
}
struct JavaStream<'tree> {
    id: usize,
    start_byte: usize,
    units: Vec<Node<'tree>>,
}

/// One collected Java unit awaiting its children's definitions.  `children`
/// holds nested unit node IDs in `<unit>` marker visit order; `pending`
/// bounds the definition ordering work in `finish_java_units`.
struct JavaUnitRecord {
    node_id: usize,
    token: u32,
    symbol: u32,
    children: Vec<usize>,
    pending: usize,
}

impl<'source> FactCollector<'source> {
    fn new(
        source: &'source str,
        language: Language,
        physical_lines: usize,
        line_starts: Vec<usize>,
    ) -> Self {
        Self {
            source,
            language,
            physical_lines,
            line_starts,
            rows: RowFlags::new(physical_lines),
            tokens: Vec::with_capacity(source.len().min(4096) / 8),
            symbols: Vec::new(),
            interned: HashMap::new(),
            key_buffer: String::with_capacity(256),
            visited_nodes: 0,
            signature_nodes: 0,
            java_units: Vec::new(),
            java_unit_index: HashMap::new(),
            java_unit_parent: HashMap::new(),
            java_unit_children: Vec::new(),
            java_definitions: Vec::new(),
            error: None,
            stopped: false,
        }
    }

    fn visit_signature_node(&mut self) -> bool {
        self.signature_nodes = self.signature_nodes.saturating_add(1);
        if self.signature_nodes > MAX_TREE_NODES {
            self.fail("normalized signature traversal exceeds bounded size");
            return false;
        }
        true
    }
    fn metrics(&self) -> FileMetrics {
        self.rows.metrics(self.physical_lines)
    }

    fn walk(&mut self, root: Node<'_>) {
        match self.language {
            Language::Python => self.walk_python(root),
            Language::Java => self.walk_java(root),
            _ => self.walk_generic(root),
        }
    }

    fn walk_generic(&mut self, root: Node<'_>) {
        // An explicit node stack avoids recursion on adversarially deep trees.
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if self.stopped {
                break;
            }
            if !self.visit_tree_node() {
                break;
            }
            if node.is_missing() {
                continue;
            }
            if self.emit_special_node(node) {
                continue;
            }
            self.emit_generic_marker(node);
            self.visit_generic_node(&mut stack, node);
        }
    }

    fn visit_tree_node(&mut self) -> bool {
        self.visited_nodes = self.visited_nodes.saturating_add(1);
        if self.visited_nodes > MAX_TREE_NODES {
            self.fail("syntax tree exceeds bounded traversal size");
            self.stopped = true;
            return false;
        }
        true
    }

    fn emit_special_node(&mut self, node: Node<'_>) -> bool {
        let kind = node.kind();
        if is_comment_kind(kind) {
            self.mark_node(node, false);
            return true;
        }
        if is_string_root_kind(kind) {
            self.emit_string_token(node);
            return true;
        }
        if is_atomic_literal_kind(kind) {
            self.emit_atomic_literal(node);
            return true;
        }
        false
    }

    fn emit_string_token(&mut self, node: Node<'_>) {
        let kind = node.kind();
        let interpolated =
            is_interpolated_kind(kind) || (kind == "string" && contains_interpolation(node));
        if interpolated {
            self.emit_interpolated(node);
        } else {
            self.mark_node(node, true);
            self.key_buffer.clear();
            append_part(&mut self.key_buffer, "string");
            append_part(&mut self.key_buffer, kind);
            append_part(&mut self.key_buffer, "normalized");
            self.emit_buffered_token(node);
        }
    }

    fn emit_atomic_literal(&mut self, node: Node<'_>) {
        let kind = node.kind();
        self.mark_node(node, true);
        let text = node.utf8_text(self.source.as_bytes()).unwrap_or(kind);
        self.key_buffer.clear();
        append_part(&mut self.key_buffer, "literal");
        append_part(&mut self.key_buffer, kind);
        append_part(&mut self.key_buffer, text);
        self.emit_buffered_token(node);
    }

    fn emit_generic_marker(&mut self, node: Node<'_>) {
        let kind = node.kind();
        match self.language {
            Language::JavaScript | Language::TypeScript if is_javascript_boundary_kind(kind) => {
                // JavaScript and TypeScript omit many newlines from their
                // CST.  Statement markers retain automatic-semicolon
                // insertion semantics (notably `return\nvalue` versus
                // `return value`) without preserving formatting whitespace.
                self.emit_marker("javascript:boundary:", kind, node);
            }
            Language::Ruby if is_ruby_boundary_kind(kind) => {
                self.emit_marker("ruby:boundary:", kind, node);
            }
            _ => {}
        }
    }

    fn visit_generic_node<'tree>(&mut self, stack: &mut Vec<Node<'tree>>, node: Node<'tree>) {
        if node.child_count() == 0 {
            self.emit_leaf(node);
        } else {
            push_children(stack, node);
        }
    }
    fn walk_python(&mut self, root: Node<'_>) {
        let mut stack = vec![(root, false)];
        while let Some((node, exiting)) = stack.pop() {
            if self.stopped {
                return;
            }
            if exiting {
                self.emit_python_exit(node);
                continue;
            }
            if !self.visit_tree_node() {
                return;
            }
            if node.is_missing() {
                continue;
            }
            if self.emit_special_node(node) {
                continue;
            }
            self.emit_python_start(node, &mut stack);
            self.visit_python_node(&mut stack, node);
        }
    }

    fn emit_python_exit(&mut self, node: Node<'_>) {
        if is_python_structure_kind(node.kind()) {
            self.emit_marker_end("python:exit:", node.kind(), node);
        }
    }

    fn emit_python_start<'tree>(
        &mut self,
        node: Node<'tree>,
        stack: &mut Vec<(Node<'tree>, bool)>,
    ) {
        let kind = node.kind();
        if is_python_statement_kind(kind) {
            self.emit_marker("python:statement:", kind, node);
        }
        if is_python_structure_kind(kind) {
            self.emit_marker("python:enter:", kind, node);
            stack.push((node, true));
        }
    }

    fn visit_python_node<'tree>(
        &mut self,
        stack: &mut Vec<(Node<'tree>, bool)>,
        node: Node<'tree>,
    ) {
        if node.child_count() == 0 {
            self.emit_leaf(node);
        } else {
            push_children_with_root_flag(stack, node);
        }
    }
    fn walk_java(&mut self, root: Node<'_>) {
        let mut streams = self.collect_java_streams(root);
        streams.sort_by_key(|stream| (stream.start_byte, stream.id));
        self.emit_java_streams(streams);
        self.finish_java_units();
    }

    fn collect_java_streams<'tree>(&mut self, root: Node<'tree>) -> Vec<JavaStream<'tree>> {
        let mut stack = vec![root];
        let mut stream_indices: HashMap<usize, usize> = HashMap::new();
        let mut streams = Vec::new();
        while let Some(node) = stack.pop() {
            if self.stopped {
                return streams;
            }
            if !self.visit_tree_node() {
                return streams;
            }
            if node.is_missing() {
                continue;
            }
            if self.collect_java_node(node, &mut stream_indices, &mut streams) {
                continue;
            }
            if node.child_count() > 0 {
                push_children(&mut stack, node);
            }
        }
        streams
    }

    fn collect_java_node<'tree>(
        &mut self,
        node: Node<'tree>,
        stream_indices: &mut HashMap<usize, usize>,
        streams: &mut Vec<JavaStream<'tree>>,
    ) -> bool {
        let kind = node.kind();
        if is_comment_kind(kind) {
            self.mark_node(node, false);
            return true;
        }
        if is_java_unit_kind(kind) {
            Self::add_java_unit(node, stream_indices, streams);
        } else if node.child_count() == 0 && !node.is_extra() && !is_string_content_kind(kind) {
            // Canonical statement signatures mark their own leaves; this
            // covers declarations/wrappers that contain no statement
            // unit while keeping physical metrics complete.
            self.mark_node(node, true);
        }
        false
    }

    fn add_java_unit<'tree>(
        node: Node<'tree>,
        stream_indices: &mut HashMap<usize, usize>,
        streams: &mut Vec<JavaStream<'tree>>,
    ) {
        let stream_id = java_stream_id(node);
        let index = if let Some(index) = stream_indices.get(&stream_id) {
            *index
        } else {
            let index = streams.len();
            stream_indices.insert(stream_id, index);
            streams.push(JavaStream {
                id: stream_id,
                start_byte: node.start_byte(),
                units: Vec::new(),
            });
            index
        };
        streams[index].units.push(node);
    }

    fn emit_java_streams(&mut self, streams: Vec<JavaStream<'_>>) {
        let mut first_stream = true;
        for stream in streams {
            if self.stopped {
                return;
            }
            if !first_stream && let Some(first_unit) = stream.units.first() {
                self.emit_java_stream_barrier(*first_unit);
            }
            first_stream = false;
            self.emit_java_units(stream.units);
            if self.stopped {
                return;
            }
        }
    }

    fn emit_java_units(&mut self, units: Vec<Node<'_>>) {
        for unit in units {
            self.emit_java_unit_token(unit);
            if self.stopped {
                return;
            }
        }
    }

    /// Orders the recorded unit definitions children-first and freezes them
    /// into [`SourceFacts::units`].  A unit becomes ready exactly when all
    /// nested units recorded inside it are defined, so the loop performs
    /// constant work per unit and per child edge and terminates on any tree.
    fn finish_java_units(&mut self) {
        if self.stopped {
            self.java_units.clear();
            self.java_unit_index.clear();
            self.java_unit_parent.clear();
            self.java_unit_children.clear();
            return;
        }
        let mut records = std::mem::take(&mut self.java_units);
        let index_by_node = std::mem::take(&mut self.java_unit_index);
        let parent_of = std::mem::take(&mut self.java_unit_parent);
        self.java_unit_children.clear();
        let mut definitions = Vec::with_capacity(records.len());
        let mut definition_of_record = vec![0_u32; records.len()];
        let mut ready: Vec<usize> = records
            .iter()
            .enumerate()
            .filter(|(_, record)| record.pending == 0)
            .map(|(index, _)| index)
            .collect();
        let mut cursor = 0;
        while cursor < ready.len() {
            let record_index = ready[cursor];
            cursor += 1;
            let record = &records[record_index];
            let mut children = Vec::with_capacity(record.children.len());
            for child in &record.children {
                let Some(&child_record) = index_by_node.get(child) else {
                    self.fail("java unit definition references an unknown child");
                    self.java_definitions.clear();
                    return;
                };
                children.push(definition_of_record[child_record]);
            }
            definition_of_record[record_index] = saturating_u32(definitions.len());
            definitions.push(UnitDefinition {
                token: record.token,
                symbol: record.symbol,
                children,
            });
            if let Some(&parent) = parent_of.get(&record.node_id) {
                let Some(parent_record) = records.get_mut(parent) else {
                    self.fail("java unit definition references an unknown parent");
                    self.java_definitions.clear();
                    return;
                };
                if parent_record.pending == 0 {
                    self.fail("java unit definition child count underflow");
                    self.java_definitions.clear();
                    return;
                }
                parent_record.pending -= 1;
                if parent_record.pending == 0 {
                    ready.push(parent);
                }
            }
        }
        if definitions.len() != records.len() {
            self.fail("java unit definitions are cyclic or incomplete");
            self.java_definitions.clear();
            return;
        }
        self.java_definitions = definitions;
    }

    fn emit_java_stream_barrier(&mut self, node: Node<'_>) {
        self.key_buffer.clear();
        self.key_buffer.push_str("\0barrier:java-stream");
        self.emit_buffered_token_start(node);
    }

    fn emit_leaf(&mut self, node: Node<'_>) {
        let kind = node.kind();
        if node.is_extra() || is_comment_kind(kind) || is_string_content_kind(kind) {
            return;
        }
        let text = node.utf8_text(self.source.as_bytes()).unwrap_or(kind);
        if text.is_empty() && node.start_byte() == node.end_byte() {
            return;
        }
        self.key_buffer.clear();
        if is_layout_kind(kind) {
            self.key_buffer.push_str("layout:");
            self.key_buffer.push_str(kind);
        } else {
            append_part(&mut self.key_buffer, "leaf");
            append_part(&mut self.key_buffer, kind);
            append_part(&mut self.key_buffer, text);
        }
        self.mark_node(node, true);
        self.emit_buffered_token(node);
    }

    fn emit_marker(&mut self, prefix: &str, kind: &str, node: Node<'_>) {
        // A boundary marker is a zero-width semantic event for line metrics;
        // marking the full statement would turn comment-only rows in a block
        // into code rows.
        self.mark_start(node, true);
        self.key_buffer.clear();
        self.key_buffer.push_str(prefix);
        self.key_buffer.push_str(kind);
        self.emit_buffered_token_start(node);
    }
    fn emit_interpolated(&mut self, node: Node<'_>) {
        self.key_buffer.clear();
        self.key_buffer.push_str("interp:");
        append_part(&mut self.key_buffer, node.kind());
        let mut stack = vec![(node, false, true)];
        while let Some((current, in_expression, is_root)) = stack.pop() {
            if !self.check_signature_budget("interpolated syntax exceeds bounded facts size") {
                return;
            }
            if self.stopped {
                return;
            }
            self.visit_interpolated_node(current, in_expression, is_root, &mut stack);
        }
        if !self.check_signature_size("interpolated syntax exceeds bounded facts size") {
            return;
        }
        self.emit_buffered_token(node);
    }

    fn check_signature_budget(&mut self, message: &str) -> bool {
        if self.visit_signature_node() && self.key_buffer.len() <= MAX_SIGNATURE_BYTES {
            return true;
        }
        if self.error.is_none() {
            self.fail(message);
        }
        self.stopped = true;
        false
    }

    fn check_signature_size(&mut self, message: &str) -> bool {
        if self.key_buffer.len() <= MAX_SIGNATURE_BYTES {
            return true;
        }
        if self.error.is_none() {
            self.fail(message);
        }
        self.stopped = true;
        false
    }

    fn visit_interpolated_node<'tree>(
        &mut self,
        current: Node<'tree>,
        in_expression: bool,
        is_root: bool,
        stack: &mut Vec<(Node<'tree>, bool, bool)>,
    ) {
        let kind = current.kind();
        if !is_root && is_comment_kind(kind) {
            self.mark_node(current, false);
            return;
        }
        if !is_root && is_string_root_kind(kind) {
            // A nested plain literal in an interpolation remains a
            // literal, but its spelling must not erase the expression's
            // surrounding structure.
            append_part(&mut self.key_buffer, "<string-literal>");
            self.mark_node(current, true);
            return;
        }
        let boundary = is_interpolation_boundary(kind);
        let child_expression = in_expression || boundary;
        if !is_root && boundary {
            append_part(&mut self.key_buffer, "<interpolation>");
        }
        if current.child_count() == 0 {
            self.emit_interpolated_leaf(current, in_expression);
        } else {
            push_children_with_context(stack, current, child_expression);
        }
    }

    fn emit_interpolated_leaf(&mut self, current: Node<'_>, in_expression: bool) {
        let kind = current.kind();
        if is_string_content_kind(kind) {
            if !in_expression {
                self.mark_node(current, true);
                append_part(&mut self.key_buffer, "<text>");
            }
            return;
        }
        let text = current.utf8_text(self.source.as_bytes()).unwrap_or(kind);
        if is_interpolation_delimiter(current, text) {
            self.mark_node(current, true);
            return;
        }
        self.mark_node(current, true);
        append_part(&mut self.key_buffer, kind);
        append_part(
            &mut self.key_buffer,
            if is_layout_kind(kind) {
                "<layout>"
            } else {
                text
            },
        );
    }
    fn emit_java_unit_token(&mut self, node: Node<'_>) {
        self.key_buffer.clear();
        self.key_buffer.push_str("java-unit");
        append_part(&mut self.key_buffer, node.kind());
        self.java_unit_children.clear();
        let mut stack = vec![(node, true)];
        let mut saw_code = false;
        while let Some((current, is_root)) = stack.pop() {
            if !self.check_signature_budget("java statement exceeds bounded facts size") {
                return;
            }
            if self.stopped {
                return;
            }
            self.visit_java_signature_node(current, is_root, &mut stack, &mut saw_code);
        }
        if !self.check_signature_size("java statement exceeds bounded facts size") {
            return;
        }
        if !saw_code {
            self.mark_start(node, true);
        }
        let token_index = saturating_u32(self.tokens.len());
        self.emit_buffered_token(node);
        if self.stopped {
            return;
        }
        self.record_java_unit(node, token_index);
    }

    /// Records one unit's exact compositional definition after its token was
    /// interned.  The definition carries the own-parts signature symbol plus
    /// the nested unit nodes recorded at their `<unit>` marker positions;
    /// the parent links let `finish_java_units` order definitions
    /// children-first without re-traversing any subtree.
    fn record_java_unit(&mut self, node: Node<'_>, token: u32) {
        if self.java_units.len() >= MAX_FACT_TOKENS {
            self.fail("java unit definitions exceed bounded size");
            return;
        }
        let node_id = node.id();
        let symbol = self.tokens[token as usize].symbol;
        let children = std::mem::take(&mut self.java_unit_children);
        let pending = children.len();
        let record_index = self.java_units.len();
        for child in &children {
            if self.java_unit_parent.insert(*child, record_index).is_some() {
                self.fail("java unit child has multiple parents");
                return;
            }
        }
        self.java_units.push(JavaUnitRecord {
            node_id,
            token,
            symbol,
            children,
            pending,
        });
        self.java_unit_index.insert(node_id, record_index);
    }

    fn visit_java_signature_node<'tree>(
        &mut self,
        current: Node<'tree>,
        is_root: bool,
        stack: &mut Vec<(Node<'tree>, bool)>,
        saw_code: &mut bool,
    ) {
        let kind = current.kind();
        if !is_root && is_comment_kind(kind) {
            self.mark_node(current, false);
            return;
        }
        if !is_root && is_java_unit_kind(kind) {
            append_part(&mut self.key_buffer, "<unit>");
            append_part(&mut self.key_buffer, kind);
            *saw_code = true;
            // The nested unit keeps its own independently emitted token and
            // definition.  Recording its node at this exact marker position
            // preserves the historical flattened marker ordering while the
            // enclosing signature stops re-traversing nested content, so
            // every node's normalized parts are emitted exactly once.
            self.java_unit_children.push(current.id());
            return;
        }
        if !is_root && is_string_root_kind(kind) {
            self.mark_node(current, true);
            if is_interpolated_kind(kind) || (kind == "string" && contains_interpolation(current)) {
                append_part(&mut self.key_buffer, "<interpolated-string>");
            } else {
                append_part(&mut self.key_buffer, "<string-literal>");
            }
            return;
        }
        if !is_root && is_atomic_literal_kind(kind) {
            self.mark_node(current, true);
            let text = current.utf8_text(self.source.as_bytes()).unwrap_or(kind);
            append_part(&mut self.key_buffer, kind);
            append_part(&mut self.key_buffer, text);
            return;
        }
        if current.child_count() == 0 {
            if current.is_extra() || is_comment_kind(kind) || is_string_content_kind(kind) {
                return;
            }
            let text = current.utf8_text(self.source.as_bytes()).unwrap_or(kind);
            if text.is_empty() && current.start_byte() == current.end_byte() {
                return;
            }
            self.mark_node(current, true);
            *saw_code = true;
            append_part(&mut self.key_buffer, kind);
            append_part(
                &mut self.key_buffer,
                if is_layout_kind(kind) {
                    "<layout>"
                } else {
                    text
                },
            );
        } else {
            push_children_with_root_flag(stack, current);
        }
    }

    fn emit_buffered_token(&mut self, node: Node<'_>) {
        self.emit_buffered_token_with_span(node, false);
    }

    fn emit_buffered_token_start(&mut self, node: Node<'_>) {
        self.emit_buffered_token_with_span(node, true);
    }

    fn emit_buffered_token_end(&mut self, node: Node<'_>) {
        if self.tokens.len() >= MAX_FACT_TOKENS {
            self.fail("normalized token stream exceeds bounded size");
            self.stopped = true;
            return;
        }
        let Some(symbol) = self.intern_buffered() else {
            self.stopped = true;
            return;
        };
        let (_, end_line) = line_span(node, &self.line_starts);
        let end_byte = saturating_u32(node.end_byte());
        self.tokens.push(NormalizedToken {
            symbol,
            start_line: end_line,
            end_line,
            start_byte: end_byte,
            end_byte,
        });
    }

    fn emit_buffered_token_with_span(&mut self, node: Node<'_>, start_only: bool) {
        if self.tokens.len() >= MAX_FACT_TOKENS {
            self.fail("normalized token stream exceeds bounded size");
            self.stopped = true;
            return;
        }
        let Some(symbol) = self.intern_buffered() else {
            self.stopped = true;
            return;
        };
        let (start_line, full_end_line) = line_span(node, &self.line_starts);
        let start_byte = saturating_u32(node.start_byte());
        let full_end_byte = saturating_u32(node.end_byte());
        self.tokens.push(NormalizedToken {
            symbol,
            start_line,
            end_line: if start_only {
                start_line
            } else {
                full_end_line
            },
            start_byte,
            end_byte: if start_only {
                start_byte
            } else {
                full_end_byte
            },
        });
    }

    fn emit_marker_end(&mut self, prefix: &str, kind: &str, node: Node<'_>) {
        self.key_buffer.clear();
        self.key_buffer.push_str(prefix);
        self.key_buffer.push_str(kind);
        self.emit_buffered_token_end(node);
    }

    fn intern_buffered(&mut self) -> Option<u32> {
        let hash = symbol_hash(self.key_buffer.as_bytes());
        if let Some(symbols) = self.interned.get(&hash) {
            for symbol in symbols {
                let index = usize::try_from(*symbol).ok()?;
                if self
                    .symbols
                    .get(index)
                    .is_some_and(|existing| existing.as_bytes() == self.key_buffer.as_bytes())
                {
                    return Some(*symbol);
                }
            }
        }
        let Ok(symbol) = u32::try_from(self.symbols.len()) else {
            self.fail("interned symbol table exceeds u32 capacity");
            return None;
        };
        // The scratch buffer is reused for every occurrence.  Only a new
        // symbol clones its canonical spelling into the public table.
        self.symbols.push(self.key_buffer.clone());
        self.interned.entry(hash).or_default().push(symbol);
        Some(symbol)
    }

    fn mark_node(&mut self, node: Node<'_>, code: bool) {
        // A multiline literal or block comment can contain physically blank
        // rows.  Mark only rows that contain a non-whitespace source byte;
        // counting the entire syntax-node span would report literal padding
        // as executable code (and empty comment rows as comments).
        let start = node.start_byte().min(self.source.len());
        let end = node.end_byte().min(self.source.len()).max(start);
        let mut row = line_number_at_byte(&self.line_starts, start);
        let mut has_non_whitespace = false;
        let bytes = self.source.as_bytes();
        let mut offset = start;
        while offset < end {
            if let Some(width) = line_break_width(bytes, offset, self.language)
                && offset.saturating_add(width) <= end
            {
                if has_non_whitespace {
                    self.rows.mark(row, row, code);
                }
                row = row.saturating_add(1);
                has_non_whitespace = false;
                offset = offset.saturating_add(width);
            } else {
                if !bytes[offset].is_ascii_whitespace() {
                    has_non_whitespace = true;
                }
                offset += 1;
            }
        }
        if has_non_whitespace {
            self.rows.mark(row, row, code);
        } else if start == end {
            let line = line_number_at_byte(&self.line_starts, start);
            self.rows.mark(line, line, code);
        }
    }

    fn mark_start(&mut self, node: Node<'_>, code: bool) {
        let (start, _) = line_span(node, &self.line_starts);
        self.rows.mark(start, start, code);
    }

    fn fail(&mut self, message: &str) {
        if self.error.is_none() {
            self.error = Some(message.to_owned());
        }
    }
}

fn push_children<'tree>(stack: &mut Vec<Node<'tree>>, node: Node<'tree>) {
    let mut cursor = node.walk();
    if cursor.goto_last_child() {
        loop {
            stack.push(cursor.node());
            if !cursor.goto_previous_sibling() {
                break;
            }
        }
    }
}

fn push_children_with_root_flag<'tree>(stack: &mut Vec<(Node<'tree>, bool)>, node: Node<'tree>) {
    let mut cursor = node.walk();
    if cursor.goto_last_child() {
        loop {
            stack.push((cursor.node(), false));
            if !cursor.goto_previous_sibling() {
                break;
            }
        }
    }
}

fn push_children_with_context<'tree>(
    stack: &mut Vec<(Node<'tree>, bool, bool)>,
    node: Node<'tree>,
    in_expression: bool,
) {
    let mut cursor = node.walk();
    if cursor.goto_last_child() {
        loop {
            stack.push((cursor.node(), in_expression, false));
            if !cursor.goto_previous_sibling() {
                break;
            }
        }
    }
}

fn line_span(node: Node<'_>, line_starts: &[usize]) -> (u32, u32) {
    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    let start_line = line_number_at_byte(line_starts, start_byte);
    if end_byte <= start_byte {
        return (start_line, start_line);
    }
    let mut end_line = line_number_at_byte(line_starts, end_byte);
    // A half-open node ending at a line start belongs to the preceding line.
    // This matches tree-sitter's end-position convention while also handling
    // ECMAScript separators that tree-sitter does not count as rows.
    if line_starts.binary_search(&end_byte).is_ok() {
        end_line = end_line.saturating_sub(1).max(start_line);
    }
    (start_line, end_line.max(start_line))
}

fn line_number_at_byte(line_starts: &[usize], byte: usize) -> u32 {
    let line = match line_starts.binary_search(&byte) {
        Ok(index) => index.saturating_add(1),
        Err(index) => index.max(1),
    };
    saturating_u32(line).max(1)
}

fn semantic_line_count(source: &str, language: Language) -> usize {
    if source.is_empty() {
        return 0;
    }
    let bytes = source.as_bytes();
    let mut lines: usize = 1;
    let mut offset = 0;
    while offset < bytes.len() {
        if let Some(width) = line_break_width(bytes, offset, language) {
            offset = offset.saturating_add(width);
            if offset < bytes.len() {
                lines = lines.saturating_add(1);
            }
        } else {
            offset += 1;
        }
    }
    lines
}

fn semantic_line_starts(source: &str, language: Language) -> Vec<usize> {
    if source.is_empty() {
        return Vec::new();
    }
    let bytes = source.as_bytes();
    let mut starts = Vec::with_capacity(source.len().min(4096) / 8);
    starts.push(0);
    let mut offset = 0;
    while offset < bytes.len() {
        if let Some(width) = line_break_width(bytes, offset, language) {
            offset += width;
            if offset < bytes.len() {
                starts.push(offset);
            }
        } else {
            offset += 1;
        }
    }
    starts
}

fn line_break_width(bytes: &[u8], offset: usize, language: Language) -> Option<usize> {
    if bytes.get(offset) == Some(&b'\n') {
        return Some(1);
    }
    if !matches!(
        language,
        Language::JavaScript | Language::TypeScript | Language::Java
    ) {
        return None;
    }
    if bytes.get(offset) == Some(&b'\r') {
        return Some(if bytes.get(offset + 1) == Some(&b'\n') {
            2
        } else {
            1
        });
    }
    if matches!(language, Language::JavaScript | Language::TypeScript)
        && bytes.get(offset) == Some(&0xe2)
        && bytes.get(offset + 1) == Some(&0x80)
        && bytes
            .get(offset + 2)
            .is_some_and(|byte| matches!(*byte, 0xa8 | 0xa9))
    {
        return Some(3);
    }
    None
}

fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn append_part(output: &mut String, part: &str) {
    let _ = write!(output, "{}:", part.len());
    output.push_str(part);
    output.push('|');
}

fn symbol_hash(bytes: &[u8]) -> u64 {
    // FNV-1a is only a bucket index; equality against `symbols` below makes
    // the interner collision-safe without allocating a lookup key.
    let mut hash = 14_695_981_039_346_656_037u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(1_099_511_628_211);
    }
    hash
}

fn is_comment_kind(kind: &str) -> bool {
    kind == "comment"
        || kind.ends_with("_comment")
        || matches!(
            kind,
            "line_comment" | "block_comment" | "documentation_comment"
        )
}

fn is_java_block_kind(kind: &str) -> bool {
    kind == "block"
        || kind.ends_with("_body")
        || matches!(kind, "switch_block" | "switch_rule" | "lambda_expression")
}

fn java_stream_id(node: Node<'_>) -> usize {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if is_java_block_kind(current.kind()) {
            return current.id();
        }
        if is_java_unit_kind(current.kind()) {
            return current.id();
        }
        ancestor = current.parent();
    }
    0
}

fn is_layout_kind(kind: &str) -> bool {
    matches!(
        kind,
        "indent" | "dedent" | "newline" | "_newline" | "line_continuation"
    )
}

fn is_string_content_kind(kind: &str) -> bool {
    matches!(
        kind,
        "string_content"
            | "string_fragment"
            | "template_chars"
            | "heredoc_body"
            | "heredoc_content"
            | "heredoc_beginning"
            | "heredoc_end"
            | "escape_sequence"
            | "string_start"
            | "string_end"
    )
}

fn is_string_root_kind(kind: &str) -> bool {
    if is_string_content_kind(kind)
        || kind.contains("character")
        || kind.contains("char_literal")
        || kind.contains("regex")
    {
        return false;
    }
    matches!(
        kind,
        "string"
            | "concatenated_string"
            | "string_literal"
            | "raw_string_literal"
            | "interpreted_string_literal"
            | "verbatim_string_literal"
            | "text_block"
            | "template_string"
            | "template_literal"
            | "heredoc"
    ) || kind.contains("interpolated_string")
        || (kind.ends_with("_string_literal") && !kind.contains("character"))
}

fn is_interpolated_kind(kind: &str) -> bool {
    kind.contains("interpolated")
        || matches!(
            kind,
            "template_string" | "template_literal" | "template_substitution"
        )
}

fn is_interpolation_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "interpolation" | "template_substitution" | "substitution" | "interpolation_expression"
    ) || (kind.contains("interpolation") && !kind.contains("string"))
}

fn is_interpolation_delimiter(node: Node<'_>, text: &str) -> bool {
    if !matches!(text, "{" | "}" | "${" | "#{" | "`" | "\"") {
        return false;
    }
    node.parent()
        .is_some_and(|parent| is_interpolation_boundary(parent.kind()))
}

fn is_atomic_literal_kind(kind: &str) -> bool {
    kind.contains("character")
        || kind.contains("char_literal")
        || kind.contains("rune_literal")
        || kind == "regex"
        || kind == "regex_literal"
}

fn is_python_statement_kind(kind: &str) -> bool {
    kind.ends_with("_statement") || matches!(kind, "simple_statement" | "future_import_statement")
}

fn is_python_structure_kind(kind: &str) -> bool {
    matches!(
        kind,
        "block"
            | "elif_clause"
            | "else_clause"
            | "except_clause"
            | "finally_clause"
            | "case_clause"
    )
}

fn is_javascript_boundary_kind(kind: &str) -> bool {
    kind.ends_with("_statement")
        || matches!(
            kind,
            "lexical_declaration"
                | "variable_declaration"
                | "function_declaration"
                | "class_declaration"
                | "import_statement"
                | "export_statement"
                | "statement_block"
                | "switch_case"
                | "catch_clause"
        )
}

fn is_ruby_boundary_kind(kind: &str) -> bool {
    kind == "_statement"
        || kind == "body_statement"
        || kind.ends_with("_modifier")
        || matches!(
            kind,
            "if" | "unless"
                | "while"
                | "until"
                | "for"
                | "case"
                | "begin"
                | "rescue"
                | "ensure"
                | "else"
                | "elsif"
                | "do_block"
                | "method"
                | "singleton_method"
                | "class"
                | "module"
        )
}

fn is_java_unit_kind(kind: &str) -> bool {
    kind.ends_with("_statement")
        || matches!(
            kind,
            "local_variable_declaration"
                | "field_declaration"
                | "constant_declaration"
                | "enum_constant"
        )
}

fn contains_interpolation(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    let mut visited = 0usize;
    while let Some(current) = stack.pop() {
        visited = visited.saturating_add(1);
        if visited > MAX_INTERPOLATION_SCAN_NODES {
            // A huge string with an unbounded number of descendants is safer
            // treated as interpolated than flattened as a plain literal.
            return true;
        }
        if current.id() != node.id() && is_interpolation_boundary(current.kind()) {
            return true;
        }
        push_children(&mut stack, current);
    }
    false
}

fn fallback_metrics(source: &str, language: Language) -> FileMetrics {
    let lines = semantic_line_count(source, language);
    let mut code_lines = 0usize;
    let mut comment_lines = 0usize;
    let mut in_block_comment = false;
    let mut process_line = |line: &str| {
        let text = line.trim();
        if text.is_empty() {
            return;
        }
        let (has_code, has_comment) = fallback_line_flags(text, language, &mut in_block_comment);
        if has_code {
            code_lines = code_lines.saturating_add(1);
        } else if has_comment {
            comment_lines = comment_lines.saturating_add(1);
        }
    };
    let bytes = source.as_bytes();
    let mut line_start = 0;
    let mut offset = 0;
    while offset < bytes.len() {
        if let Some(width) = line_break_width(bytes, offset, language) {
            process_line(&source[line_start..offset]);
            offset += width;
            line_start = offset;
        } else {
            offset += 1;
        }
    }
    if line_start < source.len() {
        process_line(&source[line_start..]);
    }
    FileMetrics {
        lines: saturating_u32(lines),
        code_lines: saturating_u32(code_lines),
        comment_lines: saturating_u32(comment_lines),
    }
}

fn fallback_line_flags(
    mut text: &str,
    language: Language,
    in_block_comment: &mut bool,
) -> (bool, bool) {
    let mut has_code = false;
    let mut has_comment = false;
    while !text.is_empty() {
        if let Some(rest) = consume_fallback_comment(text, language, in_block_comment) {
            has_comment = true;
            text = rest;
            continue;
        }
        has_code = true;
        text = "";
    }
    (has_code, has_comment)
}

fn consume_fallback_comment<'source>(
    text: &'source str,
    language: Language,
    in_block_comment: &mut bool,
) -> Option<&'source str> {
    if *in_block_comment {
        if let Some(end) = text.find("*/") {
            *in_block_comment = false;
            return Some(text[end + 2..].trim_start());
        }
        return Some("");
    }
    let line_comment = match language {
        Language::Python | Language::Ruby => text.starts_with('#'),
        _ => text.starts_with("//"),
    };
    if line_comment {
        return Some("");
    }
    if let Some(rest) = text.strip_prefix("/*") {
        *in_block_comment = true;
        return Some(rest);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(path: &str, source: &str) -> SourceFacts {
        collect_source_facts(Path::new(path), source).expect("supported extension")
    }

    fn stream(facts: &SourceFacts) -> Vec<&str> {
        facts
            .tokens
            .iter()
            .map(|token| facts.symbols[token.symbol as usize].as_str())
            .collect()
    }

    #[test]
    fn all_supported_languages_produce_facts() {
        let samples = [
            ("sample.py", "x = 1\n"),
            ("sample.js", "const x = 1;\n"),
            ("sample.tsx", "const x: number = 1;\n"),
            ("sample.cs", "class C { int x = 1; }\n"),
            ("sample.go", "package p\nvar x = 1\n"),
            ("sample.java", "class C { int x = 1; }\n"),
            ("sample.rs", "fn main() { let x = 1; }\n"),
            ("sample.rb", "x = 1\n"),
        ];
        for (path, source) in samples {
            let facts = facts(path, source);
            assert!(facts.language == crate::language_for_path(Path::new(path)).unwrap());
            assert!(!facts.tokens.is_empty(), "{path}");
            assert!(facts.error.is_none(), "{path}: {:?}", facts.error);
        }
    }

    #[test]
    fn typescript_import_types_are_complete() {
        let source = r#"type Options = Parameters<import("@playwright/test").Browser["newContext"]>[0];
type ImportedMember = import("./module").Widget["value"];
type GenericImported = import("./module").Widget<Argument>;
type ImportedKeys = keyof import("./module").Widget;
"#;
        for path in ["sample.ts", "sample.tsx"] {
            let facts = facts(path, source);
            assert!(!facts.tokens.is_empty(), "{path}");
            assert!(facts.error.is_none(), "{path}: {:?}", facts.error);
        }
    }

    #[test]
    fn malformed_typescript_import_type_is_incomplete() {
        let facts = facts(
            "sample.ts",
            r#"type Options = Parameters<import("@playwright/test").Browser["newContext"]>[0;
"#,
        );
        assert!(facts.error.is_some());
    }

    #[test]
    fn jsx_reserved_attribute_names_produce_complete_original_ranges() {
        let source = r#"const el = <div class="x" foo="1"></div>;"#;
        let facts = facts("sample.jsx", source);
        assert_eq!(facts.language, Language::JavaScript);
        assert_eq!(facts.metrics.lines, 1);
        assert_eq!(facts.metrics.code_lines, 1);
        assert_eq!(facts.metrics.comment_lines, 0);
        assert!(facts.error.is_none(), "{:?}", facts.error);
        for name in ["class", "foo"] {
            let start = source.find(name).expect("reserved JSX attribute");
            let end = start + name.len();
            assert!(facts.tokens.iter().any(|token| {
                token.start_byte as usize == start
                    && token.end_byte as usize == end
                    && token.start_line == 1
                    && token.end_line == 1
            }));
        }
    }

    #[test]
    fn malformed_jsx_with_reserved_attribute_remains_incomplete() {
        let facts = facts("sample.jsx", r#"const el = <div class="x" foo="1">"#);
        assert!(facts.error.is_some(), "{:?}", facts.error);
        assert_eq!(facts.metrics.lines, 1);
    }

    #[test]
    fn jsx_reserved_element_member_and_namespace_names_are_complete() {
        let source = r#"const el = <><class import="x" /><import:default for="y" /><for.import await="z" /></>;"#;
        let facts = facts("sample.jsx", source);
        assert_eq!(facts.language, Language::JavaScript);
        assert_eq!(facts.metrics.lines, 1);
        assert_eq!(facts.metrics.code_lines, 1);
        assert_eq!(facts.metrics.comment_lines, 0);
        assert!(facts.error.is_none(), "{:?}", facts.error);
        for name in ["class", "import", "for", "await"] {
            let start = source.find(name).expect("reserved JSX name");
            let end = start + name.len();
            assert!(facts.tokens.iter().any(|token| {
                token.start_byte as usize == start
                    && token.end_byte as usize == end
                    && token.start_line == 1
                    && token.end_line == 1
            }));
        }
    }

    #[test]
    fn csharp_contextual_identifiers_produce_complete_facts() {
        let source =
            "class C { private int async; private int Get() { int await = async; return await; } }";
        let facts = facts("sample.cs", source);
        assert_eq!(facts.language, Language::CSharp);
        assert!(facts.error.is_none(), "{:?}", facts.error);
        assert!(!facts.tokens.is_empty());
        assert!(facts.tokens.iter().all(|token| {
            let start = token.start_byte as usize;
            let end = token.end_byte as usize;
            start <= end && end <= source.len()
        }));
    }

    #[test]
    fn csharp_local_function_modifiers_produce_complete_facts() {
        let source = "using System.Threading.Tasks;\nclass C { void M() { static int A() => 1; static async Task<int> B() => await Work(); async static Task<int> D() => await Work(); async Task<int> E() => await Work(); } System.Func<Task<int>> f = async () => await Work(); System.Func<Task> g = async delegate { await Work(); }; static Task<int> Work() => Task.FromResult(1); string S(int x) => $\"{x}\"; }";
        let facts = facts("sample.cs", source);
        assert_eq!(facts.language, Language::CSharp);
        assert!(facts.error.is_none(), "{:?}", facts.error);
        assert!(!facts.tokens.is_empty());
        assert!(facts.tokens.iter().all(|token| {
            let start = token.start_byte as usize;
            let end = token.end_byte as usize;
            start <= end && end <= source.len()
        }));
    }

    #[test]
    fn malformed_csharp_contextual_identifier_initializer_is_incomplete() {
        let facts = facts(
            "sample.cs",
            "class C { private int async; private int Get() { int await = ; return await; } }",
        );
        assert!(facts.error.is_some(), "{:?}", facts.error);
        assert_eq!(facts.metrics.lines, 1);
    }

    #[test]
    fn comments_are_not_confused_with_markers_inside_strings() {
        let facts = facts(
            "sample.js",
            "const text = \"// not a comment\"; // trailing\n// only\n",
        );
        assert_eq!(facts.metrics.lines, 2);
        assert_eq!(facts.metrics.code_lines, 1);
        assert_eq!(facts.metrics.comment_lines, 1);
        assert!(facts.symbols.iter().any(|symbol| symbol.contains("string")));
        assert!(
            !facts
                .symbols
                .iter()
                .any(|symbol| symbol.contains("trailing"))
        );
    }
    #[test]
    fn javascript_line_terminators_keep_metrics_and_token_positions() {
        for path in ["sample.js", "sample.ts"] {
            for separator in ["\r", "\r\n", "\u{2028}", "\u{2029}"] {
                let source = format!("// comment{separator}let x = 1;{separator}let y = 2;");
                let facts = facts(path, &source);
                assert_eq!(facts.metrics.lines, 3, "{path} {separator:?}");
                assert_eq!(facts.metrics.code_lines, 2, "{path} {separator:?}");
                assert_eq!(facts.metrics.comment_lines, 1, "{path} {separator:?}");
                assert!(facts.error.is_none(), "{path}: {:?}", facts.error);
                for (needle, line) in [("let x", 2), ("let y", 3)] {
                    let start = source.find(needle).expect("statement");
                    let keyword_end = start + "let".len();
                    assert!(facts.tokens.iter().any(|token| {
                        token.start_byte as usize == start
                            && token.end_byte as usize == keyword_end
                            && token.start_line == line
                            && token.end_line == line
                    }));
                }

                let fallback = fallback_metrics(&source, Language::JavaScript);
                assert_eq!(fallback.lines, 3, "{separator:?}");
                assert_eq!(fallback.code_lines, 2, "{separator:?}");
                assert_eq!(fallback.comment_lines, 1, "{separator:?}");
            }
        }

        let java_facts = facts(
            "sample.java",
            "// comment\rclass A { int f() { return 1; } }\r",
        );
        assert_eq!(java_facts.metrics.lines, 2);
        assert_eq!(java_facts.metrics.code_lines, 1);
        assert_eq!(java_facts.metrics.comment_lines, 1);
        assert!(java_facts.error.is_none(), "{:?}", java_facts.error);

        let java_crlf = facts(
            "sample.java",
            "// comment\r\nclass A { int f() { return 1; } }\r\n",
        );
        assert_eq!(java_crlf.metrics.lines, 2);
        assert_eq!(java_crlf.metrics.code_lines, 1);
        assert_eq!(java_crlf.metrics.comment_lines, 1);
        assert!(java_crlf.error.is_none(), "{:?}", java_crlf.error);
        for (facts, source) in [
            (
                &java_facts,
                "// comment\rclass A { int f() { return 1; } }\r",
            ),
            (
                &java_crlf,
                "// comment\r\nclass A { int f() { return 1; } }\r\n",
            ),
        ] {
            let start = source.find("return").expect("return statement");
            assert!(facts.tokens.iter().any(|token| {
                token.start_byte as usize == start && token.start_line == 2 && token.end_line == 2
            }));
        }

        let java = fallback_metrics("/* comment */\rclass C {}\r", Language::Java);
        assert_eq!(java.lines, 2);
        assert_eq!(java.code_lines, 1);
        assert_eq!(java.comment_lines, 1);

        let non_javascript = fallback_metrics("x = 1\u{2028}y = 2", Language::Python);
        assert_eq!(non_javascript.lines, 1);
        assert_eq!(non_javascript.code_lines, 1);
    }
    #[test]
    fn interpolated_template_comments_keep_comment_only_rows() {
        let facts = facts("sample.js", "const s = `${\n// comment\nvalue\n}`;\n");
        assert_eq!(facts.metrics.lines, 4);
        assert_eq!(facts.metrics.code_lines, 3);
        assert_eq!(facts.metrics.comment_lines, 1);
    }

    #[test]
    fn plain_and_interpolated_literals_have_distinct_semantics() {
        let facts = facts("sample.py", "a = \"name\"\nb = f\"{name}\"\n");
        assert!(
            facts
                .symbols
                .iter()
                .any(|symbol| symbol.contains("string|"))
        );
        assert!(
            facts
                .symbols
                .iter()
                .any(|symbol| symbol.starts_with("interp:"))
        );
        assert!(facts.symbols.iter().any(|symbol| symbol.contains("name")));
    }

    #[test]
    fn python_layout_is_semantic_but_indent_spelling_is_not() {
        let spaces = facts("sample.py", "if ready:\n    value = 1\nvalue = 2\n");
        let tabs = facts("sample.py", "if ready:\n\tvalue = 1\nvalue = 2\n");
        assert_eq!(stream(&spaces), stream(&tabs));
        assert!(
            spaces
                .symbols
                .iter()
                .any(|symbol| symbol == "python:exit:block")
        );

        let nested = facts("sample.py", "if ready:\n    value = 1\n    value = 2\n");
        assert_ne!(stream(&spaces), stream(&nested));
    }

    #[test]
    fn java_uses_ten_statement_units_on_one_line() {
        let source = "class C { void f() { int a=0; int b=1; int c=2; int d=3; int e=4; int f=5; int g=6; int h=7; int i=8; int j=9; } }";
        let facts = facts("sample.java", source);
        assert_eq!(facts.language, Language::Java);
        assert_eq!(facts.tokens.len(), 10);
        assert!(facts.tokens.iter().all(|token| token.start_line == 1));
    }

    #[test]
    fn java_nested_statement_stream_keeps_inner_units() {
        let source = "class C { void f() { for (int i = 0; i < 2; i++) { int a = 1; int b = 2; } int c = 3; } }";
        let facts = facts("sample.java", source);
        assert!(facts.tokens.len() >= 5);
        assert!(
            facts
                .symbols
                .iter()
                .any(|symbol| symbol == "\0barrier:java-stream")
        );
        assert!(
            facts
                .symbols
                .iter()
                .any(|symbol| symbol.contains("for_statement"))
        );
    }

    #[test]
    fn java_deep_nested_signatures_remain_complete() {
        let depth = 1_500;
        let mut source = String::from("class C { void f(boolean x) {\n");
        source.push_str(&"if (x) {\n".repeat(depth));
        source.push_str("System.out.println(x);\n");
        source.push_str(&"}\n".repeat(depth));
        source.push_str("} }\n");

        let facts = facts("deep.java", &source);
        assert!(facts.error.is_none(), "{:?}", facts.error);
        assert_eq!(facts.units.len(), depth + 1);
    }

    fn legacy_java_parts(source: &str, node: Node<'_>) -> Vec<String> {
        let mut parts = vec![node.kind().to_owned()];
        let mut stack = vec![(node, true)];
        while let Some((current, is_root)) = stack.pop() {
            let kind = current.kind();
            if !is_root && legacy_push_marked_node(&mut parts, source, current, kind) {
                continue;
            }
            if current.child_count() == 0 {
                legacy_push_leaf_parts(&mut parts, source, current, kind);
            } else {
                push_children_with_root_flag(&mut stack, current);
            }
        }
        parts
    }

    /// Pushes the encoded marker parts for a non-root marked node; returns
    /// `true` when traversal must stop at this node (string or literal leaf).
    fn legacy_push_marked_node(
        parts: &mut Vec<String>,
        source: &str,
        current: Node<'_>,
        kind: &str,
    ) -> bool {
        if is_comment_kind(kind) {
            return true;
        }
        if is_java_unit_kind(kind) {
            parts.push("<unit>".to_owned());
            parts.push(kind.to_owned());
            return false;
        }
        if is_string_root_kind(kind) {
            let interpolated =
                is_interpolated_kind(kind) || (kind == "string" && contains_interpolation(current));
            parts.push(
                if interpolated {
                    "<interpolated-string>"
                } else {
                    "<string-literal>"
                }
                .to_owned(),
            );
            return true;
        }
        if is_atomic_literal_kind(kind) {
            parts.push(kind.to_owned());
            parts.push(
                current
                    .utf8_text(source.as_bytes())
                    .unwrap_or(kind)
                    .to_owned(),
            );
            return true;
        }
        false
    }

    /// Pushes the leaf parts for a childless node, preserving the legacy
    /// skip rules for extra, comment, string-content, and empty nodes.
    fn legacy_push_leaf_parts(
        parts: &mut Vec<String>,
        source: &str,
        current: Node<'_>,
        kind: &str,
    ) {
        if current.is_extra() || is_comment_kind(kind) || is_string_content_kind(kind) {
            return;
        }
        let text = current.utf8_text(source.as_bytes()).unwrap_or(kind);
        if text.is_empty() && current.start_byte() == current.end_byte() {
            return;
        }
        parts.push(kind.to_owned());
        parts.push(if is_layout_kind(kind) {
            "<layout>".to_owned()
        } else {
            text.to_owned()
        });
    }

    fn encoded_parts(symbol: &str) -> Vec<String> {
        let bytes = symbol.as_bytes();
        let mut offset = "java-unit".len();
        let mut parts = Vec::new();
        while offset < bytes.len() {
            let Some(colon) = bytes[offset..].iter().position(|byte| *byte == b':') else {
                panic!("malformed encoded Java unit symbol");
            };
            let colon = offset + colon;
            let length = std::str::from_utf8(&bytes[offset..colon])
                .expect("ASCII encoded part length")
                .parse::<usize>()
                .expect("encoded part length");
            let start = colon + 1;
            let end = start + length;
            parts.push(
                std::str::from_utf8(&bytes[start..end])
                    .expect("encoded Java unit part")
                    .to_owned(),
            );
            offset = end + 1;
        }
        parts
    }

    fn expanded_java_parts(facts: &SourceFacts, definition_index: usize) -> Vec<String> {
        fn expand_tail(
            facts: &SourceFacts,
            parts: &[String],
            children: &[u32],
            output: &mut Vec<String>,
        ) {
            let mut child_index = 0;
            let mut index = 0;
            while index < parts.len() {
                let part = &parts[index];
                output.push(part.clone());
                index += 1;
                if part == "<unit>" {
                    let kind = parts.get(index).expect("unit marker kind");
                    output.push(kind.clone());
                    index += 1;
                    let child = children
                        .get(child_index)
                        .copied()
                        .expect("child for unit marker") as usize;
                    child_index += 1;
                    let child_definition = &facts.units[child];
                    let child_parts =
                        encoded_parts(&facts.symbols[child_definition.symbol as usize]);
                    assert_eq!(child_parts.first(), Some(kind));
                    expand_tail(facts, &child_parts[1..], &child_definition.children, output);
                }
            }
            assert_eq!(child_index, children.len());
        }

        let definition = &facts.units[definition_index];
        let parts = encoded_parts(&facts.symbols[definition.symbol as usize]);
        let mut output = Vec::new();
        expand_tail(facts, &parts, &definition.children, &mut output);
        output
    }

    #[test]
    fn java_composition_matches_independent_legacy_normalizer() {
        let source = "class C { void f() { if (ready) { // ignored\n String value = \"literal\"; alpha(value); } if (other) { beta(); } } }";
        let facts = facts("legacy.java", source);
        assert!(facts.error.is_none(), "{:?}", facts.error);
        let mut parser = Parser::new();
        set_parser_language(&mut parser, Language::Java, "java").expect("Java parser");
        let tree = parser
            .parse(normalize_java_parser_source(source).as_ref(), None)
            .expect("Java tree");
        let mut stack = vec![tree.root_node()];
        let mut compared = 0;
        while let Some(node) = stack.pop() {
            if is_java_unit_kind(node.kind()) {
                let token = facts
                    .tokens
                    .iter()
                    .position(|token| {
                        token.start_byte as usize == node.start_byte()
                            && token.end_byte as usize == node.end_byte()
                    })
                    .expect("unit token");
                let definition_index = facts
                    .units
                    .iter()
                    .position(|definition| definition.token as usize == token)
                    .expect("unit definition");
                assert_eq!(
                    expanded_java_parts(&facts, definition_index),
                    legacy_java_parts(source, node),
                    "compositional expansion must preserve every legacy marker position"
                );
                compared += 1;
            }
            push_children(&mut stack, node);
        }
        assert_eq!(compared, facts.units.len());
    }

    #[test]
    fn java_nested_units_keep_exact_marker_order_and_children() {
        let facts = facts(
            "nested.java",
            "class C { void f() { if (a) { alpha(); } if (b) { beta(); } } }",
        );
        assert!(facts.error.is_none(), "{:?}", facts.error);
        assert_eq!(facts.units.len(), 4);
        let mut parents = facts.units.iter().filter(|unit| unit.children.len() == 1);
        let first = parents.next().expect("first nested parent");
        let second = parents.next().expect("second nested parent");
        assert!(parents.next().is_none());
        assert_ne!(first.token, second.token);
        let first_symbol = &facts.symbols[first.symbol as usize];
        let second_symbol = &facts.symbols[second.symbol as usize];
        let first_marker = first_symbol.find("<unit>").expect("first marker");
        let second_marker = second_symbol.find("<unit>").expect("second marker");
        assert!(first_marker < first_symbol.len());
        assert!(second_marker < second_symbol.len());
        let first_child = &facts.units[first.children[0] as usize];
        let second_child = &facts.units[second.children[0] as usize];
        assert_ne!(
            facts.symbols[first_child.symbol as usize],
            facts.symbols[second_child.symbol as usize]
        );
    }

    #[test]
    fn java_same_line_units_keep_distinct_byte_occurrences() {
        let facts = facts(
            "same-line.java",
            "class C { void f() { if (a) { alpha(); } if (b) { beta(); } } }",
        );
        let spans: Vec<(u32, u32)> = facts
            .units
            .iter()
            .map(|unit| {
                let token = &facts.tokens[unit.token as usize];
                (token.start_byte, token.end_byte)
            })
            .collect();
        assert_eq!(facts.units.len(), 4);
        assert!(spans.iter().all(|(_, end)| *end > 0));
        assert_eq!(
            spans
                .iter()
                .map(|(start, _)| *start)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            spans.len()
        );
        assert!(facts.tokens.iter().all(|token| token.start_line == 1));
    }

    #[test]
    fn malformed_input_is_explicitly_incomplete() {
        let facts = facts("sample.go", "package {\n");
        assert!(facts.error.is_some());
        assert_eq!(facts.metrics.lines, 1);
    }

    #[test]
    fn mixed_comment_metrics_count_only_comment_rows() {
        let facts = facts(
            "sample.rs",
            "let x = 1; // trailing\n/* only */\nlet y = 2;\n",
        );
        assert_eq!(facts.metrics.lines, 3);
        assert_eq!(facts.metrics.code_lines, 2);
        assert_eq!(facts.metrics.comment_lines, 1);
    }
    #[test]
    fn bounded_inputs_use_fallback_metrics_without_start_map() {
        let oversized = "x".repeat(MAX_SOURCE_BYTES + 1);
        let oversized_facts = facts("oversized.js", &oversized);
        assert!(oversized_facts.error.is_some());
        assert_eq!(oversized_facts.metrics.lines, 1);
        assert_eq!(oversized_facts.metrics.code_lines, 1);
        assert_eq!(oversized_facts.metrics.comment_lines, 0);
        assert!(oversized_facts.tokens.is_empty());
        assert!(oversized_facts.symbols.is_empty());
        drop(oversized);

        let line_limited = "\n".repeat(MAX_SOURCE_LINES + 1);
        let facts = facts("too-many-lines.js", &line_limited);
        assert!(facts.error.is_some());
        assert_eq!(
            facts.metrics.lines,
            u32::try_from(MAX_SOURCE_LINES).expect("source line limit fits u32") + 1
        );
        assert_eq!(facts.metrics.code_lines, 0);
        assert_eq!(facts.metrics.comment_lines, 0);
        assert!(facts.tokens.is_empty());
        assert!(facts.symbols.is_empty());
    }
}
