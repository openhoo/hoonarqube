//! Bounded intraprocedural control-flow, reaching-definition, and liveness facts.

use std::collections::BTreeSet;

use hoonarqube_ir::{FlowLocation, Issue, Range};
use tree_sitter::Node;

use crate::context::{ReferenceFact, SemanticIndex, SymbolKind};
use crate::support::{LineIndex, node_text, range_of, walk_all};

pub type NodeId = usize;

const MAX_CFG_DEPTH: usize = 128;
const MAX_CFG_NODES: usize = 4096;
const MAX_CFG_WORK: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Definition {
    pub variable: String,
    pub site: NodeId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgNode {
    pub id: NodeId,
    pub kind: String,
    pub range: Range,
    pub successors: Vec<NodeId>,
    pub predecessors: Vec<NodeId>,
    pub reads: BTreeSet<String>,
    pub writes: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFlowGraph {
    pub nodes: Vec<CfgNode>,
    pub entry: NodeId,
    pub exit: NodeId,
}

impl ControlFlowGraph {
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&CfgNode> {
        self.nodes.get(id)
    }

    #[must_use]
    pub fn reachable(&self) -> BTreeSet<NodeId> {
        let mut seen = BTreeSet::new();
        let mut pending = vec![self.entry];
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            if let Some(node) = self.node(id) {
                pending.extend(node.successors.iter().rev().copied());
            }
        }
        seen
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataflowSummary {
    pub reaching_in: Vec<BTreeSet<Definition>>,
    pub reaching_out: Vec<BTreeSet<Definition>>,
    pub live_in: Vec<BTreeSet<String>>,
    pub live_out: Vec<BTreeSet<String>>,
    pub iterations: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodFlow {
    pub name: String,
    pub range: Range,
    pub cfg: ControlFlowGraph,
    pub facts: DataflowSummary,
}

struct Builder<'source, 'index> {
    source: &'source str,
    index: &'index LineIndex,
    semantics: &'index SemanticIndex,
    nodes: Vec<CfgNode>,
    break_targets: Vec<(Option<String>, NodeId)>,
    continue_targets: Vec<(Option<String>, NodeId)>,
    work_items: usize,
    budget_exhausted: bool,
    budget_node: Option<NodeId>,
}

impl<'source, 'index> Builder<'source, 'index> {
    fn new(
        source: &'source str,
        index: &'index LineIndex,
        semantics: &'index SemanticIndex,
    ) -> Self {
        Self {
            source,
            index,
            semantics,
            nodes: Vec::new(),
            break_targets: Vec::new(),
            continue_targets: Vec::new(),
            work_items: 0,
            budget_exhausted: false,
            budget_node: None,
        }
    }

    fn budget_node(&mut self, node: Option<Node<'_>>) -> NodeId {
        if let Some(id) = self.budget_node {
            return id;
        }
        if self.nodes.len() >= MAX_CFG_NODES {
            return self.nodes.len().saturating_sub(1);
        }
        let id = self.nodes.len();
        let range = node.map_or_else(
            || self.index.range(self.source, 0, 0),
            |node| range_of(node, self.source, self.index),
        );
        self.nodes.push(CfgNode {
            id,
            kind: "budget_limit".to_owned(),
            range,
            successors: Vec::new(),
            predecessors: Vec::new(),
            reads: BTreeSet::new(),
            writes: BTreeSet::new(),
        });
        self.budget_node = Some(id);
        id
    }

    fn add(&mut self, kind: impl Into<String>, node: Option<Node<'_>>) -> NodeId {
        if self.budget_exhausted || self.nodes.len() + 1 >= MAX_CFG_NODES {
            return self.budget_node(node);
        }
        self.work_items = self.work_items.saturating_add(1);
        let (start, end, range) = self.node_details(node);
        let (reads, writes) = self.node_facts(start, end);
        let id = self.nodes.len();
        self.nodes.push(CfgNode {
            id,
            kind: kind.into(),
            range,
            successors: Vec::new(),
            predecessors: Vec::new(),
            reads,
            writes,
        });
        id
    }

    fn node_details(&self, node: Option<Node<'_>>) -> (usize, usize, Range) {
        node.map_or((0, 0, self.index.range(self.source, 0, 0)), |node| {
            (
                node.start_byte(),
                node.end_byte(),
                range_of(node, self.source, self.index),
            )
        })
    }

    fn node_facts(&mut self, start: usize, end: usize) -> (BTreeSet<String>, BTreeSet<String>) {
        let mut reads = BTreeSet::new();
        let mut writes = BTreeSet::new();
        let outer = self.index.range(self.source, start, end);
        Self::collect_reference_facts(
            &self.semantics.references,
            &outer,
            &mut self.work_items,
            &mut self.budget_exhausted,
            &mut reads,
            &mut writes,
        );
        if !self.budget_exhausted {
            Self::collect_symbol_writes(
                &self.semantics.symbols,
                start,
                end,
                &mut self.work_items,
                &mut self.budget_exhausted,
                &mut writes,
            );
        }
        (reads, writes)
    }

    fn consume_work(work_items: &mut usize, budget_exhausted: &mut bool) -> bool {
        *work_items = work_items.saturating_add(1);
        if *work_items >= MAX_CFG_WORK {
            *budget_exhausted = true;
            false
        } else {
            true
        }
    }

    fn collect_reference_facts(
        references: &[crate::context::ReferenceFact],
        outer: &Range,
        work_items: &mut usize,
        budget_exhausted: &mut bool,
        reads: &mut BTreeSet<String>,
        writes: &mut BTreeSet<String>,
    ) {
        for reference in references {
            if !Self::consume_work(work_items, budget_exhausted) {
                break;
            }
            let position = reference.range.start;
            if position >= outer.start && position <= outer.end {
                if reference.is_write {
                    writes.insert(reference.name.clone());
                } else {
                    reads.insert(reference.name.clone());
                }
            }
        }
    }

    fn collect_symbol_writes(
        symbols: &[crate::context::Symbol],
        start: usize,
        end: usize,
        work_items: &mut usize,
        budget_exhausted: &mut bool,
        writes: &mut BTreeSet<String>,
    ) {
        for symbol in symbols {
            if !Self::consume_work(work_items, budget_exhausted) {
                break;
            }
            if symbol.byte_start() >= start
                && symbol.byte_start() <= end
                && matches!(
                    symbol.kind,
                    crate::context::SymbolKind::Local
                        | crate::context::SymbolKind::Parameter
                        | crate::context::SymbolKind::Field
                )
            {
                writes.insert(symbol.canonical_name.clone());
            }
        }
    }

    fn edge(&mut self, from: NodeId, to: NodeId) {
        if from == to && self.nodes.get(from).is_none() {
            return;
        }
        if !self.nodes[from].successors.contains(&to) {
            self.nodes[from].successors.push(to);
            self.nodes[to].predecessors.push(from);
        }
    }

    fn connect(&mut self, from: &[NodeId], to: NodeId) {
        for &id in from {
            self.edge(id, to);
        }
    }

    fn sequence(&mut self, node: Node<'_>, incoming: Vec<NodeId>, depth: usize) -> Vec<NodeId> {
        if depth >= MAX_CFG_DEPTH {
            let current = self.add("depth_limit", Some(node));
            self.connect(&incoming, current);
            return vec![current];
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        if children.is_empty() {
            if matches!(node.kind(), "block" | "constructor_body") {
                return incoming;
            }
            return self.statement(node, incoming, depth);
        }
        let mut frontier = incoming;
        for child in children {
            frontier = self.statement(child, frontier, depth + 1);
        }
        frontier
    }

    fn statement(&mut self, node: Node<'_>, incoming: Vec<NodeId>, depth: usize) -> Vec<NodeId> {
        if depth >= MAX_CFG_DEPTH {
            let current = self.add("depth_limit", Some(node));
            self.connect(&incoming, current);
            return vec![current];
        }
        match node.kind() {
            "block" | "constructor_body" => self.sequence(node, incoming, depth + 1),
            "if_statement" => {
                let condition = node.child_by_field_name("condition").unwrap_or(node);
                let cond = self.add("condition", Some(condition));
                self.connect(&incoming, cond);
                let join = self.add("join", None);
                let then_end = node.child_by_field_name("consequence").map_or_else(
                    || vec![cond],
                    |body| self.statement(body, vec![cond], depth + 1),
                );
                self.connect(&then_end, join);
                if let Some(body) = node.child_by_field_name("alternative") {
                    let else_end = self.statement(body, vec![cond], depth + 1);
                    self.connect(&else_end, join);
                } else {
                    self.edge(cond, join);
                }
                vec![join]
            }
            "while_statement" => self.while_loop(node, &incoming, depth),
            "do_statement" => self.do_loop(node, &incoming, depth),
            "for_statement" | "enhanced_for_statement" => self.for_loop(node, incoming, depth),
            "labeled_statement" => {
                let after = self.add("label_join", None);
                let label = node
                    .named_child(0)
                    .map(|child| node_text(child, self.source).to_owned());
                self.break_targets.push((label, after));
                let body = node.named_child(1).or_else(|| node.named_child(0));
                let ends = body.map_or_else(
                    || vec![after],
                    |body| self.statement(body, incoming, depth + 1),
                );
                self.break_targets.pop();
                self.connect(&ends, after);
                vec![after]
            }
            "break_statement" => {
                let jump = self.add("break", Some(node));
                self.connect(&incoming, jump);
                let label = node
                    .named_child(0)
                    .map(|child| node_text(child, self.source));
                if let Some((_, target)) = self
                    .break_targets
                    .iter()
                    .rev()
                    .find(|(name, _)| name.as_deref() == label)
                {
                    self.edge(jump, *target);
                }
                Vec::new()
            }
            "continue_statement" => {
                let jump = self.add("continue", Some(node));
                self.connect(&incoming, jump);
                let label = node
                    .named_child(0)
                    .map(|child| node_text(child, self.source));
                if let Some((_, target)) = self
                    .continue_targets
                    .iter()
                    .rev()
                    .find(|(name, _)| label.is_none() || name.as_deref() == label)
                {
                    self.edge(jump, *target);
                }
                Vec::new()
            }
            "return_statement" | "throw_statement" => {
                let jump = self.add(node.kind(), Some(node));
                self.connect(&incoming, jump);
                if self.nodes.len() > 1 {
                    self.edge(jump, 1);
                }
                Vec::new()
            }
            _ => {
                let current = self.add(node.kind(), Some(node));
                self.connect(&incoming, current);
                vec![current]
            }
        }
    }

    fn loop_label(&self, node: Node<'_>) -> Option<String> {
        node.parent()
            .filter(|parent| parent.kind() == "labeled_statement")
            .and_then(|parent| parent.named_child(0))
            .map(|label| node_text(label, self.source).to_owned())
    }

    fn while_loop(&mut self, node: Node<'_>, incoming: &[NodeId], depth: usize) -> Vec<NodeId> {
        let condition = node.child_by_field_name("condition").unwrap_or(node);
        let cond = self.add("condition", Some(condition));
        self.connect(incoming, cond);
        let after = self.add("loop_join", None);
        self.edge(cond, after);
        self.break_targets.push((None, after));
        self.continue_targets.push((self.loop_label(node), cond));
        if let Some(body) = node.child_by_field_name("body") {
            let ends = self.statement(body, vec![cond], depth + 1);
            self.connect(&ends, cond);
        }
        self.continue_targets.pop();
        self.break_targets.pop();
        vec![after]
    }

    fn do_loop(&mut self, node: Node<'_>, incoming: &[NodeId], depth: usize) -> Vec<NodeId> {
        let after = self.add("loop_join", None);
        self.break_targets.push((None, after));
        let condition = node.child_by_field_name("condition").unwrap_or(node);
        let cond = self.add("condition", Some(condition));
        self.continue_targets.push((self.loop_label(node), cond));
        // A separate entry works for empty blocks and nested control flow,
        // whose first allocated node may be a join rather than its entry.
        let body_start = self.add("loop_body", None);
        self.connect(incoming, body_start);
        let ends = node
            .child_by_field_name("body")
            .map_or(vec![body_start], |body| {
                self.statement(body, vec![body_start], depth + 1)
            });
        self.connect(&ends, cond);
        self.edge(cond, after);
        self.edge(cond, body_start);
        self.continue_targets.pop();
        self.break_targets.pop();
        vec![after]
    }

    fn for_loop(&mut self, node: Node<'_>, incoming: Vec<NodeId>, depth: usize) -> Vec<NodeId> {
        let (_, frontier) = self.statement_fields(node, "init", incoming, depth);
        let condition = node
            .child_by_field_name("condition")
            .or_else(|| node.child_by_field_name("value"));
        let cond = self.add("condition", condition);
        self.connect(&frontier, cond);
        let after = self.add("loop_join", None);
        if condition.is_some() {
            self.edge(cond, after);
        }
        self.break_targets.push((None, after));

        // Both normal completion and continue execute the entire update list,
        // left to right, before testing the condition again.
        let (update_start, update_end) = self.statement_fields(node, "update", Vec::new(), depth);
        let update_start = update_start.unwrap_or(cond);
        self.connect(&update_end, cond);
        self.continue_targets
            .push((self.loop_label(node), update_start));
        let body_end = node.child_by_field_name("body").map_or(vec![cond], |body| {
            self.statement(body, vec![cond], depth + 1)
        });
        self.connect(&body_end, update_start);
        self.continue_targets.pop();
        self.break_targets.pop();
        vec![after]
    }

    fn statement_fields(
        &mut self,
        node: Node<'_>,
        field: &str,
        mut frontier: Vec<NodeId>,
        depth: usize,
    ) -> (Option<NodeId>, Vec<NodeId>) {
        let mut first = None;
        let mut cursor = node.walk();
        for statement in node.children_by_field_name(field, &mut cursor) {
            let start = self.nodes.len();
            frontier = self.statement(statement, frontier, depth + 1);
            if first.is_none() {
                first = self
                    .nodes
                    .get(start)
                    .map(|node| node.id)
                    .or_else(|| frontier.first().copied());
            }
        }
        (first, frontier)
    }

    fn finish(self, entry: NodeId, exit: NodeId) -> ControlFlowGraph {
        ControlFlowGraph {
            nodes: self.nodes,
            entry,
            exit,
        }
    }
}

/// Builds one method/body CFG. Unsupported or malformed statements become
/// ordinary sequential nodes; they never make the graph builder panic.
#[must_use]
pub fn build_cfg(
    body: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> ControlFlowGraph {
    let mut builder = Builder::new(source, index, semantics);
    let entry = builder.add("entry", None);
    let exit = builder.add("exit", None);
    let frontier = builder.sequence(body, vec![entry], 0);
    builder.connect(&frontier, exit);
    builder.finish(entry, exit)
}

/// Computes reaching definitions and liveness on entry-reachable nodes only.
/// Unreachable nodes retain empty facts, including loop updates bypassed by
/// unconditional exits from the body.
#[must_use]
pub fn solve_dataflow(cfg: &ControlFlowGraph) -> DataflowSummary {
    let count = cfg.nodes.len();
    let reachable = cfg.reachable();
    let mut reaching_in = vec![BTreeSet::new(); count];
    let mut reaching_out = vec![BTreeSet::new(); count];
    let mut live_in = vec![BTreeSet::new(); count];
    let mut live_out = vec![BTreeSet::new(); count];
    let mut iterations = 0;
    let limit = count.saturating_mul(8).max(8);
    for iteration in 0..limit {
        iterations = iteration + 1;
        let changed = reaching_pass(cfg, &reachable, &mut reaching_in, &mut reaching_out)
            | liveness_pass(cfg, &reachable, &mut live_in, &mut live_out);
        if !changed {
            break;
        }
    }
    DataflowSummary {
        reaching_in,
        reaching_out,
        live_in,
        live_out,
        iterations,
    }
}

fn reaching_pass(
    cfg: &ControlFlowGraph,
    reachable: &BTreeSet<NodeId>,
    reaching_in: &mut [BTreeSet<Definition>],
    reaching_out: &mut [BTreeSet<Definition>],
) -> bool {
    let mut changed = false;
    for node in cfg.nodes.iter().filter(|node| reachable.contains(&node.id)) {
        let mut input = BTreeSet::new();
        for &predecessor in &node.predecessors {
            input.extend(reaching_out[predecessor].iter().cloned());
        }
        let mut output = input.clone();
        output.retain(|definition: &Definition| !node.writes.contains(&definition.variable));
        for variable in &node.writes {
            output.insert(Definition {
                variable: variable.clone(),
                site: node.id,
            });
        }
        changed |= input != reaching_in[node.id] || output != reaching_out[node.id];
        reaching_in[node.id] = input;
        reaching_out[node.id] = output;
    }
    changed
}

fn liveness_pass(
    cfg: &ControlFlowGraph,
    reachable: &BTreeSet<NodeId>,
    live_in: &mut [BTreeSet<String>],
    live_out: &mut [BTreeSet<String>],
) -> bool {
    let mut changed = false;
    for node in cfg
        .nodes
        .iter()
        .rev()
        .filter(|node| reachable.contains(&node.id))
    {
        let mut output = BTreeSet::new();
        for &successor in &node.successors {
            output.extend(live_in[successor].iter().cloned());
        }
        let mut input = output.clone();
        for variable in &node.writes {
            input.remove(variable);
        }
        input.extend(node.reads.iter().cloned());
        changed |= input != live_in[node.id] || output != live_out[node.id];
        live_in[node.id] = input;
        live_out[node.id] = output;
    }
    changed
}

#[must_use]
pub fn method_flows(
    root: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> Vec<MethodFlow> {
    let mut flows = Vec::new();
    walk_all(root, &mut |node| {
        if !matches!(
            node.kind(),
            "method_declaration" | "constructor_declaration" | "compact_constructor_declaration"
        ) {
            return;
        }
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        let cfg = build_cfg(body, source, index, semantics);
        let name = node.child_by_field_name("name").map_or_else(
            || "<constructor>".to_owned(),
            |name| node_text(name, source).to_owned(),
        );
        flows.push(MethodFlow {
            name,
            range: range_of(node, source, index),
            facts: solve_dataflow(&cfg),
            cfg,
        });
    });
    flows
}

/// Runs the exact, syntax-provable subset of the pinned Java `CodeQL` queries.
#[must_use]
pub fn github_quality_issues(root: Node<'_>, source: &str, index: &LineIndex) -> Vec<Issue> {
    if root.has_error() {
        return Vec::new();
    }
    let mut issues = Vec::new();
    let semantics = SemanticIndex::build(root, source, index);
    let nodes = crate::support::collect_kinds(
        root,
        &[
            "class_declaration",
            "interface_declaration",
            "enum_declaration",
            "record_declaration",
            "annotation_type_declaration",
            "assignment_expression",
            "method_declaration",
            "method_invocation",
            "constructor_declaration",
            "compact_constructor_declaration",
            "object_creation_expression",
            "labeled_statement",
            "string_literal",
            "text_block",
            "binary_expression",
            "if_statement",
            "while_statement",
            "for_statement",
            "enhanced_for_statement",
            "do_statement",
            "local_variable_declaration",
            "field_declaration",
            "constant_declaration",
            "formal_parameter",
            "spread_parameter",
            "catch_formal_parameter",
            "resource",
            "lambda_expression",
            "package_declaration",
            "enum_constant",
            "type_pattern",
        ],
    );

    for node in nodes.iter().copied() {
        collect_node_issues(root, node, source, index, &semantics, &mut issues);
    }

    issues.extend(javadoc_issues(root, source, index));
    issues.extend(method_name_issues(root, source, index));
    issues.extend(method_signature_issues(root, source, index));
    issues.extend(unread_local_issues(root, source, index, &semantics));
    issues.extend(gcq_batch2_issues(root, source, index, &semantics));
    hoonarqube_ir::sort_issues(&mut issues);
    issues.dedup();
    issues
}

fn collect_node_issues(
    root: Node<'_>,
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    collect_declaration_issues(root, node, source, index, semantics, issues);
    collect_underscore_issue(node, source, index, issues);
    collect_expression_issues(node, source, index, semantics, issues);
    collect_indentation_issue(node, source, index, issues);
    collect_gcq_batch_issues(node, source, index, semantics, issues);
}

fn collect_declaration_issues(
    root: Node<'_>,
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    match node.kind() {
        "class_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "record_declaration"
        | "annotation_type_declaration" => {
            class_issues(root, node, source, index, semantics, issues);
        }
        "object_creation_expression" => {
            object_creation_issues(node, source, index, semantics, issues);
        }
        "labeled_statement" => label_issues(node, source, index, issues),
        _ => {}
    }
}

fn collect_underscore_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    issues: &mut Vec<Issue>,
) {
    if is_underscore_declaration(node, source) {
        issues.push(issue(
            "java/underscore-identifier",
            "Use of underscore as a one-character identifier",
            node,
            source,
            index,
        ));
    }
}

fn collect_expression_issues(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    match node.kind() {
        "string_literal" | "text_block" => literal_issues(node, source, index, semantics, issues),
        "binary_expression" => {
            binary_issues(node, source, index, issues);
            gcq_comparison_issues(node, source, index, semantics, issues);
        }
        _ => {}
    }
}

fn collect_indentation_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    issues: &mut Vec<Issue>,
) {
    if is_indentation_control(node.kind()) && misleading_indentation(node, source) {
        indentation_issue(node, source, index, issues);
    }
}

fn is_indentation_control(kind: &str) -> bool {
    matches!(
        kind,
        "if_statement"
            | "while_statement"
            | "for_statement"
            | "enhanced_for_statement"
            | "do_statement"
    )
}

fn push_supertype_nodes<'tree>(node: Node<'tree>, result: &mut Vec<Node<'tree>>) {
    if matches!(
        node.kind(),
        "superclass" | "super_interfaces" | "extends_interfaces" | "type_list"
    ) {
        for child in direct_named_children(node) {
            push_supertype_nodes(child, result);
        }
    } else {
        result.push(node);
    }
}

fn direct_supertype_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let mut result = Vec::new();
    for field in ["superclass", "interfaces"] {
        if let Some(value) = node.child_by_field_name(field) {
            push_supertype_nodes(value, &mut result);
        }
    }
    for child in direct_named_children(node) {
        if child.kind() == "extends_interfaces" {
            push_supertype_nodes(child, &mut result);
        }
    }
    result
}

fn simple_supertype_name<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    crate::support::simple_name(
        node_text(node, source)
            .trim_start_matches("extends")
            .trim_start_matches("implements")
            .trim(),
    )
}

fn class_issues(
    root: Node<'_>,
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    if let Some(name) = node.child_by_field_name("name") {
        let name_text = node_text(name, source);
        for supertype in direct_supertype_nodes(node) {
            if simple_supertype_name(supertype, source) != name_text {
                continue;
            }
            let mut finding = issue(
                "java/class-name-matches-super-class",
                &format!("{name_text} has the same name as its supertype $@."),
                node,
                source,
                index,
            );
            finding = finding.with_flow(vec![FlowLocation::in_primary_file(
                node_text(supertype, source)
                    .trim_start_matches("extends")
                    .trim_start_matches("implements")
                    .trim(),
                range_of(supertype, source, index),
            )]);
            issues.push(finding);
        }
    }
    if is_nested_test_class(node, source, semantics)
        && !has_junit_annotation(node, source, semantics, "Nested")
    {
        issues.push(issue(
            "java/junit5-missing-nested-annotation",
            "This JUnit 5 inner test class lacks a '@Nested' annotation.",
            node,
            source,
            index,
        ));
    }
    if let Some(name) = node.child_by_field_name("name")
        && let Some(comment) = doc_comment_before(node, source)
    {
        issues.extend(javadoc_param_issues(
            node,
            name,
            comment,
            source,
            index,
            node.kind() == "record_declaration",
        ));
    }
    if is_constant_only_type(node, source) {
        return;
    }
    constant_only_supertype_issues(root, node, source, index, semantics, issues);
}

fn constant_only_supertype_issues(
    root: Node<'_>,
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    for supertype in direct_supertype_nodes(node) {
        let supertype_text = node_text(supertype, source)
            .trim_start_matches("extends")
            .trim_start_matches("implements")
            .trim();
        let qualified_base = supertype_text
            .split('<')
            .next()
            .unwrap_or(supertype_text)
            .trim();
        if qualified_base.contains('.')
            && !qualified_name_resolves_locally(
                qualified_base,
                semantics.package_name(),
                root,
                source,
            )
        {
            // Without a classpath a dotted external supertype cannot be
            // resolved; reporting an unrelated local same-named declaration
            // would be a guess, so withhold this local-only finding.
            continue;
        }
        let interface_name = simple_supertype_name(supertype, source);
        let Some(super_decl) = find_unique_type(root, interface_name, source) else {
            continue;
        };
        if !is_constant_only_type(super_decl, source) {
            continue;
        }
        let kind = if super_decl.kind() == "interface_declaration" {
            "interface"
        } else {
            "class"
        };
        let mut finding = issue(
            "java/constants-only-interface",
            &format!(
                "Type {} implements constant {kind} $@.",
                node.child_by_field_name("name")
                    .map_or("", |value| node_text(value, source))
            ),
            node,
            source,
            index,
        );
        finding = finding.with_flow(vec![FlowLocation::in_primary_file(
            interface_name,
            range_of(super_decl, source, index),
        )]);
        issues.push(finding);
    }
}

/// Whether a dotted type reference can denote a declaration inside this file:
/// its qualification must equal the file package or a local owner chain.
fn qualified_name_resolves_locally(
    qualified: &str,
    package: Option<&str>,
    root: Node<'_>,
    source: &str,
) -> bool {
    let mut parts = qualified.split('.').collect::<Vec<_>>();
    let package_qualified = if let Some(package) = package {
        let package_parts = package.split('.').collect::<Vec<_>>();
        if parts.starts_with(&package_parts) {
            parts.drain(..package_parts.len());
            true
        } else {
            false
        }
    } else {
        false
    };
    let Some(name) = parts.pop() else {
        return false;
    };
    let owner_parts = parts;
    let first = owner_parts.first().copied().unwrap_or(name);
    let Some(mut owner) = (if package_qualified {
        top_level_type(root, first, source)
    } else {
        find_unique_type(root, first, source)
    }) else {
        return false;
    };
    for part in owner_parts.iter().skip(1) {
        let Some(next) = nested_type_child(owner, part, source) else {
            return false;
        };
        owner = next;
    }
    if owner_parts.is_empty() {
        true
    } else {
        nested_type_child(owner, name, source).is_some()
    }
}

fn top_level_type<'tree>(root: Node<'tree>, name: &str, source: &str) -> Option<Node<'tree>> {
    let matches = direct_named_children(root)
        .into_iter()
        .filter(|node| {
            matches!(
                node.kind(),
                "interface_declaration"
                    | "class_declaration"
                    | "record_declaration"
                    | "enum_declaration"
            ) && node
                .child_by_field_name("name")
                .is_some_and(|value| node_text(value, source) == name)
        })
        .collect::<Vec<_>>();
    (matches.len() == 1).then(|| matches[0])
}

fn nested_type_child<'tree>(owner: Node<'tree>, name: &str, source: &str) -> Option<Node<'tree>> {
    let body = owner.child_by_field_name("body")?;
    direct_named_children(body).into_iter().find(|child| {
        matches!(
            child.kind(),
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
        ) && child
            .child_by_field_name("name")
            .is_some_and(|value| node_text(value, source) == name)
    })
}

fn object_creation_issues(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let Some(ty) = node.child_by_field_name("type") else {
        return;
    };
    let type_name = crate::support::simple_name(node_text(ty, source));
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let Some(first) = args.named_child(0) else {
        return;
    };
    if type_name == "String"
        && expression_is_type(first, semantics, source, index, "String")
        && is_jdk_type(semantics, ty, source, "String")
    {
        issues.push(issue(
            "java/inefficient-string-constructor",
            "Inefficient new String(String) constructor.",
            node,
            source,
            index,
        ));
    } else if matches!(type_name, "StringBuffer" | "StringBuilder")
        && expression_is_type(first, semantics, source, index, "char")
        && is_jdk_type(semantics, ty, source, type_name)
    {
        issues.push(issue(
            "java/string-buffer-char-init",
            &format!(
                "A character value passed to 'new {type_name}' is interpreted as the buffer capacity."
            ),
            node,
            source,
            index,
        ));
    }
}

fn expression_is_type(
    expression: Node<'_>,
    semantics: &SemanticIndex,
    source: &str,
    lines: &LineIndex,
    expected: &str,
) -> bool {
    if expected == "String" && matches!(expression.kind(), "string_literal" | "text_block") {
        return true;
    }
    if expected == "char" && expression.kind() == "character_literal" {
        return true;
    }
    if expression.kind() == "parenthesized_expression"
        && let Some(inner) = expression.named_child(0)
    {
        return expression_is_type(inner, semantics, source, lines, expected);
    }
    if expected == "String"
        && expression.kind() == "binary_expression"
        && expression
            .child_by_field_name("operator")
            .is_some_and(|operator| node_text(operator, source) == "+")
        && expression
            .child_by_field_name("left")
            .is_some_and(|left| expression_is_type(left, semantics, source, lines, expected))
        && expression
            .child_by_field_name("right")
            .is_some_and(|right| expression_is_type(right, semantics, source, lines, expected))
    {
        return true;
    }
    if expression.kind() != "identifier" {
        return false;
    }
    let position = lines.position(source, expression.start_byte());
    semantics
        .references
        .iter()
        .find(|reference| {
            reference.range.start == position && reference.name == node_text(expression, source)
        })
        .and_then(|reference| reference.symbol)
        .and_then(|symbol| semantics.symbols.get(symbol.0))
        .and_then(|symbol| symbol.type_fact.as_ref())
        .is_some_and(|type_fact| match type_fact {
            crate::context::TypeFact::Primitive(name)
            | crate::context::TypeFact::LocalType(name)
            | crate::context::TypeFact::JavaLang(name) => name == expected,
        })
}

fn find_unique_type<'tree>(root: Node<'tree>, name: &str, source: &str) -> Option<Node<'tree>> {
    let matches = crate::support::collect_kinds(
        root,
        &[
            "interface_declaration",
            "class_declaration",
            "record_declaration",
            "enum_declaration",
        ],
    )
    .into_iter()
    .filter(|node| {
        node.child_by_field_name("name")
            .is_some_and(|value| node_text(value, source) == name)
    })
    .collect::<Vec<_>>();
    (matches.len() == 1).then(|| matches[0])
}

fn label_issues(node: Node<'_>, source: &str, index: &LineIndex, issues: &mut Vec<Issue>) {
    let label = node.named_child(0).map_or("", |n| node_text(n, source));
    let used = jump_targets_label(node, label, source);
    if nearest_control(node, "switch_expression").is_some() {
        let message = if used {
            "Confusing non-case label in switch statement."
        } else {
            "Possibly erroneous non-case label in switch statement. The case keyword might be missing."
        };
        issues.push(issue("java/label-in-switch", message, node, source, index));
    }
    if !used {
        issues.push(issue(
            "java/unused-label",
            &format!("Label '{label}' is not used."),
            node,
            source,
            index,
        ));
    }
}

fn literal_issues(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    if is_likely_test_literal(node, source, semantics) {
        return;
    }
    for (offset, code) in literal_controls(node, source) {
        issues.push(issue(
            "java/non-explicit-control-and-whitespace-chars-in-literals",
            &format!(
                "Literal value contains control or non-printable whitespace character(s) starting with Unicode code point {code} at index {offset}."
            ),
            node,
            source,
            index,
        ));
    }
}

fn is_likely_test_literal(node: Node<'_>, source: &str, index: &SemanticIndex) -> bool {
    let Some(method) = ancestor(node, "method_declaration") else {
        return false;
    };
    let method_name = method
        .child_by_field_name("name")
        .map_or("", |name| node_text(name, source));
    let junit_annotation = [
        "Test",
        "RepeatedTest",
        "ParameterizedTest",
        "TestFactory",
        "TestTemplate",
    ]
    .iter()
    .any(|name| has_junit_annotation(method, source, index, name));
    let junit3_shape = method_name.starts_with("test")
        && has_modifier(method, source, "public")
        && method
            .child_by_field_name("type")
            .is_some_and(|ty| node_text(ty, source) == "void")
        && method
            .child_by_field_name("parameters")
            .is_some_and(|parameters| parameters.named_child_count() == 0);
    junit_annotation
        || junit3_shape
        || ancestor(method, "class_declaration")
            .and_then(|class| class.child_by_field_name("name"))
            .is_some_and(|name| is_test_class_name(node_text(name, source)))
}

fn is_test_class_name(name: &str) -> bool {
    name == "Test"
        || name == "Tests"
        || name.starts_with("Test")
        || name.ends_with("Test")
        || name.ends_with("Tests")
}

fn binary_issues(node: Node<'_>, source: &str, index: &LineIndex, issues: &mut Vec<Issue>) {
    if let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) && matches!(left.kind(), "string_literal" | "text_block")
        && matches!(right.kind(), "string_literal" | "text_block")
        && missing_space(left, right, source)
    {
        let finding = issue(
            "java/missing-space-in-concatenation",
            &format!(
                "This string appears to be missing a space after '{}'.",
                string_tail(left, source)
            ),
            left,
            source,
            index,
        );
        issues.push(finding);
    }
    if whitespace_contradicts(node, source) {
        issues.push(issue(
            "java/whitespace-contradicts-precedence",
            "Whitespace around nested operators contradicts precedence.",
            node,
            source,
            index,
        ));
    }
}

fn indentation_issue(node: Node<'_>, source: &str, index: &LineIndex, issues: &mut Vec<Issue>) {
    let body = node
        .child_by_field_name("body")
        .or_else(|| node.child_by_field_name("consequence"));
    let Some(body) = body else { return };
    let Some(next) = next_named_sibling(node) else {
        return;
    };
    let mut finding = issue(
        "java/misleading-indentation",
        "Indentation suggests that $@ belongs to $@, but this is not the case; consider adding braces or adjusting indentation.",
        body,
        source,
        index,
    );
    finding = finding.with_flow(vec![
        FlowLocation::in_primary_file("the next statement", range_of(next, source, index)),
        FlowLocation::in_primary_file("the control structure", range_of(node, source, index)),
    ]);
    issues.push(finding);
}

fn issue(key: &str, message: &str, node: Node<'_>, source: &str, index: &LineIndex) -> Issue {
    Issue::new(key, message, range_of(node, source, index))
}

fn ancestor<'tree>(mut node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == kind {
            return Some(parent);
        }
        node = parent;
    }
    None
}
fn declaring_type(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        // Members of an enum-constant class body belong to that constant's
        // anonymous subclass, not to the enum type shared with every other
        // constant.
        if parent.kind() == "enum_constant" {
            return Some(parent);
        }
        // Members of an anonymous class body belong to that anonymous
        // class, not to the named type the body happens to sit inside.
        if parent.kind() == "class_body"
            && parent
                .parent()
                .is_some_and(|grand| grand.kind() == "object_creation_expression")
        {
            return Some(parent);
        }
        if matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn declaring_type_label(owner: Node<'_>, source: &str) -> String {
    if let Some(name) = owner.child_by_field_name("name") {
        return node_text(name, source).to_owned();
    }
    // Anonymous class bodies have no name; label them by the instantiated
    // type instead of falling back to the enclosing type's name.
    if owner.kind() == "class_body"
        && let Some(creation) = owner.parent()
        && creation.kind() == "object_creation_expression"
        && let Some(ty) = creation.child_by_field_name("type")
    {
        return format!("new {}", node_text(ty, source));
    }
    String::new()
}

fn next_named_sibling(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    let mut cursor = parent.walk();
    let mut found = false;
    for child in parent.named_children(&mut cursor) {
        if found {
            return Some(child);
        }
        found = child.id() == node.id();
    }
    None
}

fn line_indent(source: &str, byte: usize) -> usize {
    let start = source[..byte.min(source.len())]
        .rfind('\n')
        .map_or(0, |offset| offset + 1);
    source[start..]
        .chars()
        .take_while(|ch| matches!(ch, ' ' | '\t'))
        .count()
}

fn nearest_control<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == kind {
            return Some(parent);
        }
        if matches!(
            parent.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "class_declaration"
                | "lambda_expression"
        ) {
            return None;
        }
        current = parent;
    }
    None
}

fn has_modifier(node: Node<'_>, source: &str, wanted: &str) -> bool {
    direct_named_children(node)
        .into_iter()
        .find(|child| child.kind() == "modifiers")
        .is_some_and(|modifiers| {
            node_text(modifiers, source)
                .split_whitespace()
                .any(|modifier| modifier == wanted)
        })
}

fn has_annotation(node: Node<'_>, source: &str, wanted: &str) -> bool {
    direct_named_children(node)
        .into_iter()
        .find(|child| child.kind() == "modifiers")
        .into_iter()
        .flat_map(|modifiers| {
            crate::support::collect_kinds(modifiers, &["marker_annotation", "annotation"])
        })
        .any(|annotation| {
            annotation.child_by_field_name("name").is_some_and(|name| {
                let spelling = node_text(name, source);
                spelling == wanted || spelling == format!("java.lang.{wanted}")
            })
        })
}

fn has_junit_annotation(node: Node<'_>, source: &str, index: &SemanticIndex, wanted: &str) -> bool {
    let qualified = format!("org.junit.jupiter.api.{wanted}");
    let imported = index.imports.iter().any(|import| {
        (!import.wildcard && import.path == qualified)
            || (import.wildcard && import.path == "org.junit.jupiter.api")
    });
    direct_named_children(node)
        .into_iter()
        .find(|child| child.kind() == "modifiers")
        .into_iter()
        .flat_map(|modifiers| {
            crate::support::collect_kinds(modifiers, &["marker_annotation", "annotation"])
        })
        .filter_map(|annotation| annotation.child_by_field_name("name"))
        .any(|name| {
            let spelling = node_text(name, source);
            spelling == qualified || (imported && spelling == wanted)
        })
}

fn is_nested_test_class(node: Node<'_>, source: &str, index: &SemanticIndex) -> bool {
    let mut current = node;
    let mut member_class = false;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "class_declaration" => {
                member_class = true;
                break;
            }
            "method_declaration" | "constructor_declaration" | "lambda_expression" => return false,
            _ => current = parent,
        }
    }
    if !member_class
        || ["static", "private", "abstract"]
            .iter()
            .any(|modifier| has_modifier(node, source, modifier))
    {
        return false;
    }
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    direct_named_children(body)
        .into_iter()
        .filter(|member| member.kind() == "method_declaration")
        .any(|method| {
            [
                "Test",
                "RepeatedTest",
                "ParameterizedTest",
                "TestFactory",
                "TestTemplate",
            ]
            .iter()
            .any(|name| has_junit_annotation(method, source, index, name))
        })
}

fn is_jdk_type(index: &SemanticIndex, node: Node<'_>, source: &str, expected: &str) -> bool {
    let spelling = node_text(node, source)
        .split_whitespace()
        .collect::<String>();
    spelling == format!("java.lang.{expected}")
        || (spelling == expected && !index.type_name_is_shadowed_at(expected, node.start_byte()))
}

fn direct_named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn is_constant_only_type(node: Node<'_>, source: &str) -> bool {
    let is_interface = node.kind() == "interface_declaration";
    let is_abstract_class =
        node.kind() == "class_declaration" && has_modifier(node, source, "abstract");
    if !is_interface && !is_abstract_class {
        return false;
    }
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    let mut has_constant = false;
    for member in direct_named_children(body) {
        match member.kind() {
            "constant_declaration" | "field_declaration" if is_interface => has_constant = true,
            "field_declaration"
                if has_modifier(member, source, "static")
                    && has_modifier(member, source, "final") =>
            {
                has_constant = true;
            }
            "static_initializer" => {}
            _ => return false,
        }
    }
    has_constant
}

fn jump_targets_label(label_node: Node<'_>, label: &str, source: &str) -> bool {
    crate::support::collect_kinds(label_node, &["break_statement", "continue_statement"])
        .into_iter()
        .filter(|jump| {
            jump.named_child(0)
                .is_some_and(|name| node_text(name, source) == label)
        })
        .any(|jump| {
            let mut current = jump;
            while let Some(parent) = current.parent() {
                if parent.id() == label_node.id() {
                    return true;
                }
                if matches!(
                    parent.kind(),
                    "lambda_expression"
                        | "method_declaration"
                        | "constructor_declaration"
                        | "class_declaration"
                        | "interface_declaration"
                        | "record_declaration"
                        | "enum_declaration"
                ) {
                    return false;
                }
                current = parent;
            }
            false
        })
}

fn is_underscore_declaration(node: Node<'_>, source: &str) -> bool {
    if node.kind() == "package_declaration" {
        return node_text(node, source)
            .trim_end_matches(';')
            .strip_prefix("package")
            .is_some_and(|package| package.split('.').any(|name| name.trim() == "_"));
    }
    let declaration = matches!(
        node.kind(),
        "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration"
            | "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration"
            | "enum_constant"
            | "local_variable_declaration"
            | "field_declaration"
            | "constant_declaration"
            | "formal_parameter"
            | "spread_parameter"
            | "catch_formal_parameter"
            | "resource"
            | "enhanced_for_statement"
            | "lambda_expression"
            | "type_pattern"
    );
    declaration
        && (node
            .child_by_field_name("name")
            .is_some_and(|name| node_text(name, source) == "_")
            || node
                .child_by_field_name("parameters")
                .is_some_and(|parameters| node_text(parameters, source).trim() == "_")
            || crate::support::collect_kinds(node, &["_reserved_identifier", "underscore_pattern"])
                .iter()
                .any(|name| node_text(*name, source) == "_"))
}

fn literal_controls(node: Node<'_>, source: &str) -> Vec<(usize, u32)> {
    let text = node_text(node, source);
    let (start, end) = if text.starts_with("\"\"\"") && text.ends_with("\"\"\"") {
        (3, text.len().saturating_sub(3))
    } else if text.starts_with('"') && text.ends_with('"') {
        (1, text.len().saturating_sub(1))
    } else {
        (0, text.len())
    };
    let value = &text[start.min(text.len())..end.max(start).min(text.len())];
    let mut result = Vec::new();
    let mut escaped = false;
    for (offset, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        let code = ch as u32;
        if (code < 32 && !matches!(code, 9 | 10 | 12 | 13)) || code == 127 || code == 8203 {
            result.push((
                text[..start].chars().count() + value[..offset].chars().count(),
                code,
            ));
        }
    }
    result
}

fn string_tail(node: Node<'_>, source: &str) -> String {
    node_text(node, source)
        .trim_matches('"')
        .trim_matches(|ch| ch == '"')
        .to_owned()
}

fn missing_space(left: Node<'_>, right: Node<'_>, source: &str) -> bool {
    // Java escapes must be decoded before the word tests: a literal ending
    // in a `\n` escape ends in whitespace, not in the raw word characters
    // backslash + `n`.
    let l = decode_java_escapes(&string_tail(left, source));
    let r = decode_java_escapes(&string_tail(right, source));
    if !r.chars().next().is_some_and(char::is_alphabetic) {
        return false;
    }
    // The word must terminate directly before the closing quote, with only
    // grammatical punctuation allowed between the word and the quote.
    let mut word = l.as_str();
    while word
        .chars()
        .last()
        .is_some_and(|ch| matches!(ch, '.' | ':' | ',' | ';' | '!' | '?' | '\''))
    {
        word = word.get(..word.len().saturating_sub(1)).unwrap_or("");
    }
    if !word.chars().last().is_some_and(char::is_alphanumeric) {
        return false;
    }
    // The word must also be preceded by an in-literal space.
    word.contains(' ')
}

fn decode_java_escapes(raw: &str) -> String {
    if !raw.contains('\\') {
        return raw.to_owned();
    }
    let mut decoded = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }
        decode_escape(&mut chars, &mut decoded);
    }
    decoded
}

type EscapeChars<'a> = std::iter::Peekable<std::str::Chars<'a>>;

/// Decodes the escape sequence whose backslash was just consumed.
/// Malformed escapes keep their raw text.
fn decode_escape(chars: &mut EscapeChars<'_>, decoded: &mut String) {
    let Some(escape) = chars.next() else {
        decoded.push('\\');
        return;
    };
    match escape {
        'b' => decoded.push('\u{0008}'),
        't' => decoded.push('\t'),
        'n' => decoded.push('\n'),
        'f' => decoded.push('\u{000C}'),
        'r' => decoded.push('\r'),
        's' => decoded.push(' '),
        '"' => decoded.push('"'),
        '\'' => decoded.push('\''),
        '\\' => decoded.push('\\'),
        'u' => decode_unicode_escape(chars, decoded),
        '0'..='7' => decode_octal_escape(escape, chars, decoded),
        other => {
            decoded.push('\\');
            decoded.push(other);
        }
    }
}

fn decode_unicode_escape(chars: &mut EscapeChars<'_>, decoded: &mut String) {
    while chars.peek() == Some(&'u') {
        chars.next();
    }
    let mut value: u32 = 0;
    let mut digits = 0;
    while digits < 4 {
        let Some(digit) = chars.peek().and_then(|c| c.to_digit(16)) else {
            break;
        };
        value = value * 16 + digit;
        chars.next();
        digits += 1;
    }
    if digits == 4 {
        decoded.push(char::from_u32(value).unwrap_or('\u{FFFD}'));
    } else {
        // Malformed escape: keep the raw text.
        decoded.push('\\');
        decoded.push('u');
    }
}

fn decode_octal_escape(first: char, chars: &mut EscapeChars<'_>, decoded: &mut String) {
    let mut value = first.to_digit(8).unwrap_or(0);
    let max_digits = if matches!(first, '0'..='3') { 3 } else { 2 };
    let mut digits = 1;
    while digits < max_digits {
        let Some(digit) = chars.peek().and_then(|c| c.to_digit(8)) else {
            break;
        };
        value = value * 8 + digit;
        chars.next();
        digits += 1;
    }
    decoded.push(char::from_u32(value).unwrap_or('\u{FFFD}'));
}

fn whitespace_contradicts(node: Node<'_>, source: &str) -> bool {
    let Some(operator) = node.child_by_field_name("operator") else {
        return false;
    };
    let Some(left) = node.child_by_field_name("left") else {
        return false;
    };
    let Some(right) = node.child_by_field_name("right") else {
        return false;
    };
    let outer_op = node_text(operator, source);
    if matches!(outer_op, "=" | "+=" | "-=" | "*=" | "/=" | "%=") {
        return false;
    }
    let Some((inner, inner_op_node)) = [left, right]
        .into_iter()
        .find_map(|child| {
            (child.kind() == "binary_expression")
                .then(|| (child, child.child_by_field_name("operator")))
        })
        .and_then(|(child, op)| op.map(|op| (child, op)))
    else {
        return false;
    };
    if inner
        .parent()
        .is_some_and(|parent| parent.kind() == "parenthesized_expression")
    {
        return false;
    }
    let inner_op = node_text(inner_op_node, source);
    let arithmetic = |op: &str| matches!(op, "+" | "-" | "*" | "/" | "%");
    let shift = |op: &str| matches!(op, "<<" | ">>" | ">>>");
    let relation = |op: &str| matches!(op, "==" | "!=" | "<" | ">" | "<=" | ">=");
    let logical = |op: &str| matches!(op, "&&" | "||");
    let bitwise = |op: &str| matches!(op, "&" | "|" | "^");
    if !(arithmetic(outer_op)
        || shift(outer_op)
        || relation(outer_op)
        || logical(outer_op)
        || bitwise(outer_op))
        || !(arithmetic(inner_op)
            || shift(inner_op)
            || relation(inner_op)
            || logical(inner_op)
            || bitwise(inner_op))
    {
        return false;
    }
    let inner_left = left.id() == inner.id();
    let associative = (matches!(inner_op, "+" | "*" | "&" | "|" | "^" | "&&" | "||")
        && inner_op == outer_op)
        || (relation(inner_op)
            && relation(outer_op)
            && matches!(inner_op, "==" | "!=")
            && matches!(outer_op, "==" | "!="))
        || (inner_left && matches!((inner_op, outer_op), ("*", "/") | ("/", "%") | ("+", "-")));
    let harmless = (relation(outer_op) && (arithmetic(inner_op) || shift(inner_op)))
        || (logical(outer_op) && relation(inner_op));
    if associative || harmless {
        return false;
    }
    whitespace_around(inner, source)
        .zip(whitespace_around(node, source))
        .is_some_and(|(inner_gap, outer_gap)| {
            inner_gap % 2 == 0 && outer_gap % 2 == 0 && inner_gap > outer_gap
        })
}

fn whitespace_around(node: Node<'_>, source: &str) -> Option<usize> {
    let operator = node.child_by_field_name("operator")?;
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    if left.start_position().row != right.start_position().row {
        return None;
    }
    let before = source.get(left.end_byte()..operator.start_byte())?;
    let after = source.get(operator.end_byte()..right.start_byte())?;
    Some(before.chars().count() + after.chars().count())
}

fn misleading_indentation(node: Node<'_>, source: &str) -> bool {
    let Some(body) = node
        .child_by_field_name("body")
        .or_else(|| node.child_by_field_name("consequence"))
    else {
        return false;
    };
    if body.kind() == "block" || node.kind() == "do_statement" {
        return false;
    }
    let Some(next) = next_named_sibling(node) else {
        return false;
    };
    if matches!(
        body.kind(),
        "return_statement" | "break_statement" | "continue_statement" | "throw_statement"
    ) || next.kind() == "empty_statement"
    {
        return false;
    }
    let body_indent = line_indent(source, body.start_byte());
    let next_indent = line_indent(source, next.start_byte());
    let control_indent = line_indent(source, node.start_byte());
    (body_indent == next_indent || same_line(body, next, source))
        && (control_indent < body_indent || body_indent < next_indent)
}

fn same_line(a: Node<'_>, b: Node<'_>, source: &str) -> bool {
    !source[a.start_byte().min(source.len())..b.start_byte().min(source.len())].contains('\n')
}

fn doc_comment_before(node: Node<'_>, source: &str) -> Option<(usize, usize)> {
    let before = &source[..node.start_byte().min(source.len())];
    let end = before.rfind("*/")? + 2;
    let start = before[..end].rfind("/**")?;
    before[end..]
        .chars()
        .all(char::is_whitespace)
        .then_some((start, end))
}

fn javadoc_param_tag<'a>(
    text: &'a str,
    start: usize,
    offset: usize,
    line: &'a str,
) -> Option<(usize, &'a str)> {
    // Only a Javadoc block-tag position may start a parameter tag: after
    // comment decoration (leading whitespace and any leading `*`), the
    // content must begin with the exact `@param` tag. Prose and inline
    // `{@code @param ...}` bodies never create block tags.
    let (content, decoration) = if let Some(after_open) = line.strip_prefix("/**") {
        let content = after_open
            .trim_start_matches([' ', '\t'])
            .trim_start_matches('*')
            .trim_start_matches([' ', '\t']);
        (content, line.len() - content.len())
    } else {
        let content = line
            .trim_start_matches([' ', '\t'])
            .trim_start_matches('*')
            .trim_start_matches([' ', '\t']);
        (content, line.len() - content.len())
    };
    let rest = content.strip_prefix("@param")?;
    if !rest.is_empty() && !rest.chars().next().is_some_and(char::is_whitespace) {
        return None;
    }
    let tag_start = start
        + text
            .split_inclusive('\n')
            .take(offset)
            .map(str::len)
            .sum::<usize>()
        + decoration;
    Some((tag_start, rest.trim_start()))
}

fn javadoc_param_value(rest: &str) -> (bool, &str) {
    let valid = match rest {
        "" => false,
        value if value.starts_with('<') => value.find('>').is_some(),
        _ => true,
    };
    let name_text = rest.split_whitespace().next().unwrap_or("");
    (valid, name_text)
}

fn javadoc_declaration(node: Node<'_>) -> Node<'_> {
    if node.kind() == "compact_constructor_declaration" {
        ancestor(node, "record_declaration").unwrap_or(node)
    } else {
        node
    }
}

fn javadoc_parameter_names<'a>(declaration: Node<'_>, source: &'a str) -> Vec<&'a str> {
    declaration
        .child_by_field_name("parameters")
        .map(|parameters| {
            direct_named_children(parameters)
                .into_iter()
                .filter_map(|parameter| javadoc_parameter_name(parameter, source))
                .collect()
        })
        .unwrap_or_default()
}

/// A formal parameter exposes `name` directly; a `spread_parameter` has no
/// fields and wraps its binding in a `variable_declarator`.
fn javadoc_parameter_name<'source>(
    parameter: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    if let Some(name) = parameter.child_by_field_name("name") {
        return Some(node_text(name, source));
    }
    if parameter.kind() != "spread_parameter" {
        return None;
    }
    let mut cursor = parameter.walk();
    parameter
        .named_children(&mut cursor)
        .find(|child| child.kind() == "variable_declarator")
        .and_then(|declarator| declarator.child_by_field_name("name"))
        .map(|name| node_text(name, source))
}

fn javadoc_type_parameter_names<'a>(declaration: Node<'_>, source: &'a str) -> Vec<&'a str> {
    declaration
        .child_by_field_name("type_parameters")
        .map(|parameters| {
            direct_named_children(parameters)
                .into_iter()
                .filter_map(|parameter| type_parameter_identifier(parameter, source))
                .collect()
        })
        .unwrap_or_default()
}

/// `type_parameter` has no name field: the declared identifier is the first
/// identifier child, before any optional `type_bound`.
fn type_parameter_identifier<'source>(
    parameter: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    let mut cursor = parameter.walk();
    parameter
        .named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "identifier" | "type_identifier"))
        .map(|identifier| node_text(identifier, source))
}

fn javadoc_param_is_known(name_text: &str, params: &[&str], type_params: &[&str]) -> bool {
    if name_text.starts_with('<') {
        // Type-parameter identifiers are compared exactly; a declared name
        // that merely contains the tag text must not accept it.
        let tag = name_text.trim_matches(['<', '>']);
        type_params.contains(&tag)
    } else {
        params.contains(&name_text)
    }
}

fn javadoc_param_message(
    node: Node<'_>,
    name: Node<'_>,
    name_text: &str,
    valid: bool,
    source: &str,
) -> String {
    if !valid {
        return "This @param tag does not have a value.".to_owned();
    }
    let what = if matches!(
        node.kind(),
        "constructor_declaration" | "compact_constructor_declaration"
    ) {
        "constructor"
    } else {
        "method"
    };
    format!(
        "@param tag \"{name_text}\" does not match any actual parameter of {what} \"{}()\".",
        node_text(name, source)
    )
}

fn javadoc_param_issue(
    node: Node<'_>,
    name: Node<'_>,
    rest: &str,
    tag_start: usize,
    source: &str,
    index: &LineIndex,
) -> Option<Issue> {
    let tag_range = index.range(source, tag_start, tag_start + 6);
    let (valid, name_text) = javadoc_param_value(rest);
    let declaration = javadoc_declaration(node);
    let params = javadoc_parameter_names(declaration, source);
    let type_params = javadoc_type_parameter_names(declaration, source);
    if valid && javadoc_param_is_known(name_text, &params, &type_params) {
        return None;
    }
    let message = javadoc_param_message(node, name, name_text, valid, source);
    Some(Issue::new(
        "java/unknown-javadoc-parameter",
        message,
        tag_range,
    ))
}

fn javadoc_param_issues(
    node: Node<'_>,
    name: Node<'_>,
    comment: (usize, usize),
    source: &str,
    index: &LineIndex,
    _is_record: bool,
) -> Vec<Issue> {
    let (start, end) = comment;
    let text = &source[start..end];
    let mut out = Vec::new();
    let mut inline_tag_depth = 0usize;
    for (offset, line) in text.lines().enumerate() {
        if inline_tag_depth == 0
            && let Some((tag_start, rest)) = javadoc_param_tag(text, start, offset, line)
            && let Some(issue) = javadoc_param_issue(node, name, rest, tag_start, source, index)
        {
            out.push(issue);
        }
        inline_tag_depth = javadoc_inline_tag_depth(line, inline_tag_depth);
    }
    out
}

fn javadoc_inline_tag_depth(line: &str, mut depth: usize) -> usize {
    let bytes = line.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if depth == 0 {
            if bytes[index] == b'{' && bytes.get(index + 1) == Some(&b'@') {
                depth = 1;
                index += 2;
            } else {
                index += 1;
            }
        } else if bytes[index] == b'{' {
            depth = depth.saturating_add(1);
            index += 1;
        } else if bytes[index] == b'}' {
            depth -= 1;
            index += 1;
        } else {
            index += 1;
        }
    }
    depth
}

fn javadoc_issues(root: Node<'_>, source: &str, index: &LineIndex) -> Vec<Issue> {
    let mut out = Vec::new();
    for node in crate::support::collect_kinds(
        root,
        &[
            "class_declaration",
            "interface_declaration",
            "record_declaration",
            "method_declaration",
            "constructor_declaration",
            "compact_constructor_declaration",
        ],
    ) {
        let Some(comment) = doc_comment_before(node, source) else {
            continue;
        };
        let name = node.child_by_field_name("name").unwrap_or(node);
        out.extend(javadoc_param_issues(
            node,
            name,
            comment,
            source,
            index,
            node.kind() == "record_declaration",
        ));
    }
    out
}

fn method_name_issues(root: Node<'_>, source: &str, index: &LineIndex) -> Vec<Issue> {
    let methods = crate::support::collect_kinds(root, &["method_declaration"]);
    let mut out = Vec::new();
    for (i, method) in methods.iter().enumerate() {
        let Some(owner) = declaring_type(*method) else {
            continue;
        };
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        if has_annotation(*method, source, "Deprecated") {
            continue;
        }
        for other in methods.iter().skip(i + 1) {
            if declaring_type(*other).is_none_or(|value| value.id() != owner.id())
                || has_annotation(*other, source, "Deprecated")
            {
                continue;
            }
            let Some(other_name) = other.child_by_field_name("name") else {
                continue;
            };
            let left = node_text(name, source);
            let right = node_text(other_name, source);
            if left.to_lowercase() == right.to_lowercase() && left != right {
                let (primary, related, primary_name) = if left < right {
                    (*method, *other, left)
                } else {
                    (*other, *method, right)
                };
                let mut finding = issue(
                    "java/confusing-method-name",
                    &format!("The method '{primary_name}' may be confused with $@."),
                    primary,
                    source,
                    index,
                );
                finding = finding.with_flow(vec![FlowLocation::in_primary_file(
                    node_text(
                        related.child_by_field_name("name").unwrap_or(related),
                        source,
                    ),
                    range_of(related, source, index),
                )]);
                out.push(finding);
            }
        }
    }
    out
}

fn method_signature_issues(root: Node<'_>, source: &str, index: &LineIndex) -> Vec<Issue> {
    let methods = crate::support::collect_kinds(root, &["method_declaration"]);
    let mut out = Vec::new();
    for (i, method) in methods.iter().enumerate() {
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        let Some(owner) = declaring_type(*method) else {
            continue;
        };
        let count = method
            .child_by_field_name("parameters")
            .map_or(0, |p| p.named_child_count());
        for other in methods.iter().skip(i + 1) {
            if declaring_type(*other).is_none_or(|value| value.id() != owner.id()) {
                continue;
            }
            let Some(other_name) = other.child_by_field_name("name") else {
                continue;
            };
            if node_text(name, source) != node_text(other_name, source)
                || count
                    != other
                        .child_by_field_name("parameters")
                        .map_or(0, |p| p.named_child_count())
            {
                continue;
            }
            let left_types = parameter_types(*method, source);
            let right_types = parameter_types(*other, source);
            if left_types.len() != count
                || right_types.len() != count
                || !left_types
                    .iter()
                    .zip(right_types.iter())
                    .all(|(a, b)| potentially_confusing(a, b))
            {
                continue;
            }
            let (primary, related) = if method.start_byte() > other.start_byte() {
                (*method, *other)
            } else {
                (*other, *method)
            };
            let owner_name = declaring_type(primary)
                .map(|owner| declaring_type_label(owner, source))
                .unwrap_or_default();
            let method_name = primary
                .child_by_field_name("name")
                .map_or("", |n| node_text(n, source));
            let mut finding = issue(
                "java/confusing-method-signature",
                &format!(
                    "Method {owner_name}.{method_name}(..) could be confused with overloaded method $@, since dispatch depends on static types."
                ),
                primary,
                source,
                index,
            );
            finding = finding.with_flow(vec![FlowLocation::in_primary_file(
                related
                    .child_by_field_name("name")
                    .map_or("", |n| node_text(n, source)),
                range_of(related, source, index),
            )]);
            out.push(finding);
        }
    }
    out
}

fn parameter_types(method: Node<'_>, source: &str) -> Vec<String> {
    method
        .child_by_field_name("parameters")
        .map(|params| {
            direct_named_children(params)
                .into_iter()
                .filter_map(|p| p.child_by_field_name("type"))
                .map(|t| crate::support::simple_name(node_text(t, source)).to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn potentially_confusing(a: &str, b: &str) -> bool {
    let primitive = |name: &str| {
        matches!(
            name,
            "byte" | "short" | "int" | "long" | "char" | "float" | "double" | "boolean"
        )
    };
    a == b
        || ((!primitive(a) && !primitive(b)) && (a == "Object" || b == "Object"))
        || matches!(
            (a, b),
            ("int", "Integer")
                | ("Integer", "int")
                | ("long", "Long")
                | ("Long", "long")
                | ("boolean", "Boolean")
                | ("Boolean", "boolean")
                | ("double", "Double")
                | ("Double", "double")
                | ("float", "Float")
                | ("Float", "float")
                | ("char", "Character")
                | ("Character", "char")
                | ("short", "Short")
                | ("Short", "short")
                | ("byte", "Byte")
                | ("Byte", "byte")
        )
}

// -------------------------------------------------------------------------
// GitHub Code Quality batch 1 (issue #370). Each rule is grounded in the
// pinned CodeQL source named by `catalog/github-code-quality.json` and uses
// only facts provable from one file: identifier typing goes through the
// `SemanticIndex`, unresolved or shadowed types never match, and recovered
// trees are rejected before any rule runs.
// -------------------------------------------------------------------------

const CALL_TO_THREAD_RUN: &str = "java/call-to-thread-run";
const COMPARISON_IDENTICAL: &str = "java/comparison-of-identical-expressions";
const COMPARISON_WITH_NAN: &str = "java/comparison-with-nan";
const CONSTANT_COMPARISON: &str = "java/constant-comparison";
const CONTINUE_IN_FALSE_LOOP: &str = "java/continue-in-false-loop";
const DO_NOT_CALL_FINALIZE: &str = "java/do-not-call-finalize";
const EQUALS_ON_ARRAYS: &str = "java/equals-on-arrays";
const INEFFICIENT_BOXED_CONSTRUCTOR: &str = "java/inefficient-boxed-constructor";
const INEFFICIENT_EMPTY_STRING_TEST: &str = "java/inefficient-empty-string-test";
const LOCAL_VARIABLE_IS_NEVER_READ: &str = "java/local-variable-is-never-read";
const REDUNDANT_ASSIGNMENT: &str = "java/redundant-assignment";
const REPLACE_ALL_WITH_NON_REGEX: &str = "java/string-replace-all-with-non-regex";
const TEST_NEGATIVE_CONTAINER_SIZE: &str = "java/test-for-negative-container-size";
const USELESS_NULL_CHECK: &str = "java/useless-null-check";
const USELESS_TOSTRING_CALL: &str = "java/useless-tostring-call";

/// `java.lang` wrapper types with their primitive names, mirroring `CodeQL`
/// `BoxedType`.
const BOXED_TYPES: [(&str, &str); 8] = [
    ("Integer", "int"),
    ("Long", "long"),
    ("Short", "short"),
    ("Byte", "byte"),
    ("Character", "char"),
    ("Boolean", "boolean"),
    ("Float", "float"),
    ("Double", "double"),
];

/// `java.util` element containers whose `size()` never goes negative.
const COLLECTION_TYPES: [&str; 17] = [
    "Collection",
    "List",
    "ArrayList",
    "LinkedList",
    "Vector",
    "Stack",
    "Set",
    "HashSet",
    "LinkedHashSet",
    "TreeSet",
    "SortedSet",
    "NavigableSet",
    "Queue",
    "Deque",
    "ArrayDeque",
    "PriorityQueue",
    "BlockingQueue",
];

/// `java.util` key/value containers whose `size()` never goes negative.
const MAP_TYPES: [&str; 11] = [
    "Map",
    "HashMap",
    "LinkedHashMap",
    "TreeMap",
    "SortedMap",
    "NavigableMap",
    "Hashtable",
    "ConcurrentHashMap",
    "ConcurrentMap",
    "WeakHashMap",
    "IdentityHashMap",
];

fn collect_gcq_batch_issues(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    match node.kind() {
        "assignment_expression" => gcq_assignment_issues(node, source, index, semantics, issues),
        "method_invocation" => gcq_method_invocation_issues(node, source, index, semantics, issues),
        "do_statement" => gcq_continue_issues(node, source, index, issues),
        "object_creation_expression" => {
            boxed_constructor_issue(node, source, index, semantics, issues);
        }
        _ => {}
    }
}

fn gcq_assignment_issues(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let Some(operator) = node.child_by_field_name("operator") else {
        return;
    };
    if node_text(operator, source) != "=" {
        return;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    if !same_variable(left, right, source, index, semantics) {
        return;
    }
    let destination = unwrap_parens(left);
    let name = match destination.kind() {
        "field_access" => destination
            .child_by_field_name("field")
            .map_or("", |field| node_text(field, source)),
        _ => node_text(destination, source),
    };
    issues.push(issue(
        REDUNDANT_ASSIGNMENT,
        &format!("This expression assigns {name} to itself."),
        node,
        source,
        index,
    ));
}

/// `CodeQL` treats an unqualified access, its `this`-qualified form, and two
/// `this`-qualified forms of the same field as one variable; identifiers must
/// resolve to the same symbol so shadowing never fabricates a match.
fn same_variable(
    left: Node<'_>,
    right: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> bool {
    let left = unwrap_parens(left);
    let right = unwrap_parens(right);
    let left_symbol = gcq_symbol(left, source, index, semantics);
    let right_symbol = gcq_symbol(right, source, index, semantics);
    if let (Some(left_symbol), Some(right_symbol)) = (left_symbol, right_symbol) {
        return left_symbol.id == right_symbol.id;
    }
    matches_same_field(left, right, left_symbol, source)
        || matches_same_field(right, left, right_symbol, source)
        || same_this_field_access(left, right, source, index, semantics)
        || same_this_field_access(right, left, source, index, semantics)
}

fn matches_same_field(
    named: Node<'_>,
    access: Node<'_>,
    named_symbol: Option<&crate::context::Symbol>,
    source: &str,
) -> bool {
    if named.kind() != "identifier" || access.kind() != "field_access" {
        return false;
    }
    let Some(object) = access.child_by_field_name("object") else {
        return false;
    };
    if object.kind() != "this" {
        return false;
    }
    let Some(field) = access.child_by_field_name("field") else {
        return false;
    };
    node_text(field, source) == node_text(named, source)
        && named_symbol.is_some_and(|symbol| symbol.kind == SymbolKind::Field)
}

fn same_this_field_access(
    left: Node<'_>,
    right: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> bool {
    if left.kind() != "field_access" || right.kind() != "field_access" {
        return false;
    }
    let (Some(left_object), Some(right_object)) = (
        left.child_by_field_name("object"),
        right.child_by_field_name("object"),
    ) else {
        return false;
    };
    if left_object.kind() != "this" || right_object.kind() != "this" {
        return false;
    }
    let (Some(left_field), Some(right_field)) = (
        left.child_by_field_name("field"),
        right.child_by_field_name("field"),
    ) else {
        return false;
    };
    if node_text(left_field, source) != node_text(right_field, source) {
        return false;
    }
    match (
        gcq_symbol(left_field, source, index, semantics),
        gcq_symbol(right_field, source, index, semantics),
    ) {
        (Some(left), Some(right)) => left.id == right.id,
        // Unresolved fields belong to outer classes; the same name is the
        // strongest single-file evidence available.
        (None, None) => true,
        _ => false,
    }
}

/// `java/local-variable-is-never-read`: a plain local whose value is never
/// read. Plain-assignment destinations are pure writes; `x++` and compound
/// assignment read. Try-with-resources, catch parameters, and enhanced-`for`
/// variables are exempt, matching the pinned query's declaration scope.
fn unread_local_issues(
    root: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> Vec<Issue> {
    // References exist only for usages, so declaration sites are matched by
    // position against the local symbols.
    let local_sites: std::collections::BTreeMap<(u32, u32), usize> = semantics
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Local)
        .map(|symbol| {
            (
                (
                    symbol.declared_at.start.line,
                    symbol.declared_at.start.column,
                ),
                symbol.id.0,
            )
        })
        .collect();
    let mut read = BTreeSet::new();
    let mut exempt = BTreeSet::new();
    for identifier in crate::support::collect_kinds(root, &["identifier"]) {
        let position = index.position(source, identifier.start_byte());
        if let Some(&symbol_index) = local_sites.get(&(position.line, position.column)) {
            if declaration_site_is_implicit_use(identifier) {
                exempt.insert(symbol_index);
            }
            continue;
        }
        let Some(reference) = gcq_reference(identifier, source, index, semantics) else {
            continue;
        };
        let Some(symbol_id) = reference.symbol else {
            continue;
        };
        let Some(symbol) = semantics.symbols.get(symbol_id.0) else {
            continue;
        };
        if symbol.kind != SymbolKind::Local {
            continue;
        }
        if !is_plain_assignment_destination(identifier, source) {
            read.insert(symbol_id.0);
        }
    }
    semantics
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Local)
        .filter(|symbol| !read.contains(&symbol.id.0) && !exempt.contains(&symbol.id.0))
        .map(|symbol| {
            Issue::new(
                LOCAL_VARIABLE_IS_NEVER_READ,
                format!("Variable '{}' is never read.", symbol.name),
                symbol.declared_at.clone(),
            )
        })
        .collect()
}

fn declaration_site_is_implicit_use(identifier: Node<'_>) -> bool {
    let mut current = identifier.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "enhanced_for_statement" | "catch_formal_parameter" | "resource"
        ) {
            return true;
        }
        current = parent.parent();
    }
    false
}

/// Only `x = ...` is a pure write; `x++` and `x += ...` also read `x`.
fn is_plain_assignment_destination(identifier: Node<'_>, source: &str) -> bool {
    let Some(parent) = identifier.parent() else {
        return false;
    };
    if parent.kind() != "assignment_expression" {
        return false;
    }
    let Some(operator) = parent.child_by_field_name("operator") else {
        return false;
    };
    parent
        .child_by_field_name("left")
        .is_some_and(|left| left == identifier)
        && node_text(operator, source) == "="
}

fn gcq_comparison_issues(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let Some(operator) = node.child_by_field_name("operator") else {
        return;
    };
    let operator = node_text(operator, source);
    if !matches!(operator, "==" | "!=" | "<" | ">" | "<=" | ">=") {
        return;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    useless_null_check_issue(node, left, right, source, index, issues);
    comparison_with_nan_issue(node, left, right, source, index, semantics, issues);
    identical_expressions_issue(node, left, right, source, index, semantics, issues);
    constant_comparison_issue(node, left, right, operator, source, index, issues);
    test_negative_container_size_issue(node, left, right, source, index, semantics, issues);
}

fn useless_null_check_issue(
    node: Node<'_>,
    left: Node<'_>,
    right: Node<'_>,
    source: &str,
    index: &LineIndex,
    issues: &mut Vec<Issue>,
) {
    let check = if unwrap_parens(left).kind() == "null_literal" {
        right
    } else if unwrap_parens(right).kind() == "null_literal" {
        left
    } else {
        return;
    };
    let check = unwrap_parens(check);
    if !clearly_non_null(check) {
        return;
    }
    issues.push(issue(
        USELESS_NULL_CHECK,
        &format!(
            "This check is useless, since {} always is non-null.",
            node_text(check, source)
        ),
        node,
        source,
        index,
    ));
}

/// Facts that make an expression non-null without classpath knowledge:
/// allocation, array creation, `this`, and string literals (`CodeQL`
/// `clearlyNotNullExpr`, provable subset).
fn clearly_non_null(expression: Node<'_>) -> bool {
    matches!(
        expression.kind(),
        "object_creation_expression"
            | "array_creation_expression"
            | "this"
            | "string_literal"
            | "text_block"
    )
}

fn comparison_with_nan_issue(
    node: Node<'_>,
    left: Node<'_>,
    right: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let Some(operator) = node.child_by_field_name("operator") else {
        return;
    };
    if !matches!(node_text(operator, source), "==" | "!=") {
        return;
    }
    let Some(class_name) = nan_operand(left, source, index, semantics)
        .or(nan_operand(right, source, index, semantics))
    else {
        return;
    };
    issues.push(issue(
        COMPARISON_WITH_NAN,
        &format!(
            "This comparison will always yield the same result since 'NaN != NaN'. \
             Consider using {class_name}.isNaN instead."
        ),
        node,
        source,
        index,
    ));
}

/// Resolves `Double.NaN`/`Float.NaN` and statically imported `NaN`; a local
/// shadowing the wrapper name hides the constant.
fn nan_operand(
    expression: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> Option<&'static str> {
    let expression = unwrap_parens(expression);
    if expression.kind() == "identifier" {
        let imported = semantics
            .resolve_imported_name(node_text(expression, source))?
            .strip_suffix(".NaN")?
            .to_owned();
        return Some(if imported.ends_with("Float") {
            "Float"
        } else {
            "Double"
        });
    }
    if expression.kind() != "field_access" {
        return None;
    }
    let field = expression.child_by_field_name("field")?;
    if node_text(field, source) != "NaN" {
        return None;
    }
    let object = unwrap_parens(expression.child_by_field_name("object")?);
    if object.kind() != "identifier" {
        return None;
    }
    let text = node_text(object, source);
    if (text != "Double" && text != "Float")
        || gcq_symbol(object, source, index, semantics).is_some()
        || semantics.type_name_is_shadowed_at(text, object.start_byte())
    {
        return None;
    }
    Some(if text == "Float" { "Float" } else { "Double" })
}

fn identical_expressions_issue(
    node: Node<'_>,
    left: Node<'_>,
    right: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    if !identical_expressions(left, right, source, index, semantics) {
        return;
    }
    issues.push(issue(
        COMPARISON_IDENTICAL,
        &format!(
            "Comparison of identical values {} and {}.",
            node_text(unwrap_parens(left), source),
            node_text(unwrap_parens(right), source)
        ),
        node,
        source,
        index,
    ));
}

/// Structural equality over literals, resolved variables, and pure
/// arithmetic, mirroring `CodeQL`'s `equal()` recursion.
fn identical_expressions(
    left: Node<'_>,
    right: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> bool {
    let left = unwrap_parens(left);
    let right = unwrap_parens(right);
    if left.kind() != right.kind() {
        return false;
    }
    match left.kind() {
        "identifier" | "field_access" => same_variable(left, right, source, index, semantics),
        kind if is_pure_literal(kind) => node_text(left, source) == node_text(right, source),
        "unary_expression" | "binary_expression" => {
            same_operator(left, right, source)
                && operand_fields(left.kind()).iter().all(|field| {
                    let (Some(left_operand), Some(right_operand)) = (
                        left.child_by_field_name(field),
                        right.child_by_field_name(field),
                    ) else {
                        return false;
                    };
                    identical_expressions(left_operand, right_operand, source, index, semantics)
                })
        }
        _ => false,
    }
}

fn operand_fields(kind: &str) -> &'static [&'static str] {
    if kind == "unary_expression" {
        &["operand"]
    } else {
        &["left", "right"]
    }
}

fn is_pure_literal(kind: &str) -> bool {
    matches!(
        kind,
        "decimal_integer_literal"
            | "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal"
            | "decimal_floating_point_literal"
            | "hex_floating_point_literal"
            | "character_literal"
            | "string_literal"
            | "text_block"
            | "null_literal"
            | "true"
            | "false"
    )
}

fn same_operator(left: Node<'_>, right: Node<'_>, source: &str) -> bool {
    match (
        left.child_by_field_name("operator"),
        right.child_by_field_name("operator"),
    ) {
        (Some(left), Some(right)) => node_text(left, source) == node_text(right, source),
        _ => false,
    }
}

/// `java/constant-comparison`: two numeric literals whose outcome is fixed.
/// The pinned query folds final constants through SSA; single-file facts
/// restrict this batch to literal operands, and `assert` conditions are
/// excluded exactly as in the query.
fn constant_comparison_issue(
    node: Node<'_>,
    left: Node<'_>,
    right: Node<'_>,
    operator: &str,
    source: &str,
    index: &LineIndex,
    issues: &mut Vec<Issue>,
) {
    if ancestor(node, "assert_statement").is_some() {
        return;
    }
    let (Some(left), Some(right)) = (literal_number(left, source), literal_number(right, source))
    else {
        return;
    };
    let truth = match operator {
        "<" => left < right,
        ">" => left > right,
        "<=" => left <= right,
        ">=" => left >= right,
        "==" => left == right,
        "!=" => left != right,
        _ => return,
    };
    issues.push(issue(
        CONSTANT_COMPARISON,
        &format!("Test is always {truth}."),
        node,
        source,
        index,
    ));
}

/// Numeric value of an integer-literal expression, honoring a unary minus.
/// Radix prefixes follow JLS; oversized literals fail closed.
fn literal_number(expression: Node<'_>, source: &str) -> Option<i64> {
    let expression = unwrap_parens(expression);
    let (negative, literal) = if expression.kind() == "unary_expression" {
        let operator = expression.child_by_field_name("operator")?;
        if node_text(operator, source) != "-" {
            return None;
        }
        (
            true,
            unwrap_parens(expression.child_by_field_name("operand")?),
        )
    } else {
        (false, expression)
    };
    if !matches!(
        literal.kind(),
        "decimal_integer_literal"
            | "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal"
    ) {
        return None;
    }
    let mut text: String = node_text(literal, source)
        .chars()
        .filter(|character| *character != '_')
        .collect();
    if text.ends_with('L') || text.ends_with('l') {
        text.pop();
    }
    let (digits, radix) = match text.get(..2) {
        Some("0x" | "0X") => (&text[2..], 16),
        Some("0b" | "0B") => (&text[2..], 2),
        _ if text.len() > 1 && text.starts_with('0') => (&text[1..], 8),
        _ => (&text[..], 10),
    };
    let value = i64::from_str_radix(digits, radix).ok()?;
    if negative {
        value.checked_neg()
    } else {
        Some(value)
    }
}

/// `java/test-for-negative-container-size`: container size against integral
/// zero in the four always-decided directions of the pinned query.
fn test_negative_container_size_issue(
    node: Node<'_>,
    left: Node<'_>,
    right: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let Some(operator) = node.child_by_field_name("operator") else {
        return;
    };
    let operator = node_text(operator, source);
    let (size, zero) = match operator {
        "<" | ">=" => (left, right),
        ">" | "<=" => (right, left),
        _ => return,
    };
    let always_true = matches!(operator, ">=" | "<=");
    if literal_number(zero, source) != Some(0) {
        return;
    }
    let Some(kind) = container_kind(size, source, index, semantics) else {
        return;
    };
    issues.push(issue(
        TEST_NEGATIVE_CONTAINER_SIZE,
        &format!(
            "This expression is always {}, since {kind} can never have negative size.",
            if always_true { "true" } else { "false" }
        ),
        node,
        source,
        index,
    ));
}

/// Container classification: array `.length`, `String` `.length()`,
/// `java.util` collection/map `.size()`. Unknown types never classify.
fn container_kind(
    expression: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> Option<&'static str> {
    let expression = unwrap_parens(expression);
    if expression.kind() == "field_access" {
        let field = expression.child_by_field_name("field")?;
        if node_text(field, source) != "length" {
            return None;
        }
        let object = expression.child_by_field_name("object")?;
        return is_array_typed(object, source, index, semantics).then_some("an array");
    }
    if expression.kind() != "method_invocation" {
        return None;
    }
    let name = expression.child_by_field_name("name")?;
    let object = expression.child_by_field_name("object")?;
    let argument_count = expression
        .child_by_field_name("arguments")
        .map_or(0, |arguments| arguments.named_child_count());
    if argument_count != 0 {
        return None;
    }
    match node_text(name, source) {
        "length" if expression_is_type(object, semantics, source, index, "String") => {
            Some("a string")
        }
        "size" => java_util_container_kind(object, source, index, semantics),
        _ => None,
    }
}

fn java_util_container_kind(
    object: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> Option<&'static str> {
    let (base, is_array) = declared_base_type(object, source, index, semantics)?;
    if is_array {
        return None;
    }
    let simple = base.rsplit('.').next().unwrap_or(&base);
    let qualified = base.starts_with("java.util.");
    let imported = semantics
        .resolve_imported_name(simple)
        .is_some_and(|path| path == format!("java.util.{simple}"));
    if !(qualified || imported) {
        return None;
    }
    if COLLECTION_TYPES.contains(&simple) {
        Some("a collection")
    } else if MAP_TYPES.contains(&simple) {
        Some("a map")
    } else {
        None
    }
}

fn gcq_method_invocation_issues(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let argument_count = node
        .child_by_field_name("arguments")
        .map_or(0, |arguments| arguments.named_child_count());
    let object = node.child_by_field_name("object");
    let method = node_text(name, source);
    match method {
        "hashCode" | "equals" => {
            array_method_issue(
                node,
                object,
                argument_count,
                source,
                index,
                semantics,
                issues,
            );
            if method == "equals" {
                empty_string_equals_issue(
                    node,
                    object,
                    argument_count,
                    source,
                    index,
                    semantics,
                    issues,
                );
            }
        }
        "toString" => {
            useless_tostring_issue(
                node,
                object,
                argument_count,
                source,
                index,
                semantics,
                issues,
            );
        }
        "finalize" => finalize_issue(node, object, argument_count, source, index, issues),
        "run" => thread_run_issue(
            node,
            object,
            argument_count,
            source,
            index,
            semantics,
            issues,
        ),
        "replaceAll" => {
            replace_all_issue(
                node,
                object,
                argument_count,
                source,
                index,
                semantics,
                issues,
            );
        }
        _ => {}
    }
}

/// `java/equals-on-arrays`: `hashCode`/`equals` on array receivers compares
/// identity only. `equals` additionally requires an array argument, matching
/// the query's type-intersection requirement.
fn array_method_issue(
    node: Node<'_>,
    object: Option<Node<'_>>,
    argument_count: usize,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let method = node_text(name, source);
    let expected = usize::from(method != "hashCode");
    if argument_count != expected {
        return;
    }
    let Some(object) = object else {
        return;
    };
    if !is_array_typed(object, source, index, semantics) {
        return;
    }
    if method == "equals" {
        let argument = node
            .child_by_field_name("arguments")
            .and_then(|arguments| arguments.named_child(0));
        let Some(argument) = argument else {
            return;
        };
        if !is_array_typed(argument, source, index, semantics) {
            return;
        }
    }
    issues.push(issue(
        EQUALS_ON_ARRAYS,
        &format!(
            "The {method} method on arrays only considers object identity and ignores array contents."
        ),
        node,
        source,
        index,
    ));
}

fn useless_tostring_issue(
    node: Node<'_>,
    object: Option<Node<'_>>,
    argument_count: usize,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    if argument_count != 0 {
        return;
    }
    let Some(object) = object else {
        return;
    };
    if !expression_is_type(object, semantics, source, index, "String") {
        return;
    }
    issues.push(issue(
        USELESS_TOSTRING_CALL,
        "Redundant call to 'toString' on a String object.",
        node,
        source,
        index,
    ));
}

fn finalize_issue(
    node: Node<'_>,
    object: Option<Node<'_>>,
    argument_count: usize,
    source: &str,
    index: &LineIndex,
    issues: &mut Vec<Issue>,
) {
    if argument_count != 0 {
        return;
    }
    // `super.finalize()` inside an override is the one sanctioned call.
    if object.is_some_and(|object| unwrap_parens(object).kind() == "super") {
        return;
    }
    issues.push(issue(
        DO_NOT_CALL_FINALIZE,
        "Call to 'finalize()'.",
        node,
        source,
        index,
    ));
}

fn thread_run_issue(
    node: Node<'_>,
    object: Option<Node<'_>>,
    argument_count: usize,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    if argument_count != 0 {
        return;
    }
    let Some(object) = object else {
        return;
    };
    let object = unwrap_parens(object);
    let is_thread = declared_type_is_java_lang(object, "Thread", source, index, semantics)
        || (object.kind() == "object_creation_expression"
            && creation_type_is_java_lang(object, "Thread", source, semantics));
    if !is_thread || enclosing_method_is_run(node, source) {
        return;
    }
    issues.push(issue(
        CALL_TO_THREAD_RUN,
        "Calling 'Thread.run()' rather than 'Thread.start()' will not spawn a new thread.",
        node,
        source,
        index,
    ));
}

fn enclosing_method_is_run(node: Node<'_>, source: &str) -> bool {
    ancestor(node, "method_declaration")
        .and_then(|method| method.child_by_field_name("name"))
        .is_some_and(|name| node_text(name, source) == "run")
}

fn replace_all_issue(
    node: Node<'_>,
    object: Option<Node<'_>>,
    argument_count: usize,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    if argument_count != 2 {
        return;
    }
    let Some(object) = object else {
        return;
    };
    if !expression_is_type(object, semantics, source, index, "String") {
        return;
    }
    let Some(first) = node
        .child_by_field_name("arguments")
        .and_then(|arguments| arguments.named_child(0))
    else {
        return;
    };
    if first.kind() != "string_literal" {
        return;
    }
    // `CodeQL` requires `^[a-zA-Z0-9]+$`; escapes stay in the raw text and
    // therefore fail the test, which is the conservative direction.
    let pattern = string_literal_value(first, source);
    if pattern.is_empty()
        || !pattern
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        return;
    }
    let finding = issue(
        REPLACE_ALL_WITH_NON_REGEX,
        "This call to 'replaceAll' should be a call to 'replace' as its first argument is not a regular expression.",
        node,
        source,
        index,
    );
    issues.push(finding.with_flow(vec![FlowLocation::in_primary_file(
        "first argument",
        range_of(first, source, index),
    )]));
}

/// `java/inefficient-empty-string-test`: `equals("")` where the pinned query
/// requires a `String`-typed qualifier and an empty literal on either side.
fn empty_string_equals_issue(
    node: Node<'_>,
    object: Option<Node<'_>>,
    argument_count: usize,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    if argument_count != 1 {
        return;
    }
    let Some(object) = object else {
        return;
    };
    if !expression_is_type(object, semantics, source, index, "String") {
        return;
    }
    let Some(argument) = node
        .child_by_field_name("arguments")
        .and_then(|arguments| arguments.named_child(0))
    else {
        return;
    };
    if !is_empty_string_literal(object, source) && !is_empty_string_literal(argument, source) {
        return;
    }
    issues.push(issue(
        INEFFICIENT_EMPTY_STRING_TEST,
        "Inefficient comparison to empty string, check for zero length instead.",
        node,
        source,
        index,
    ));
}

fn is_empty_string_literal(expression: Node<'_>, source: &str) -> bool {
    let expression = unwrap_parens(expression);
    expression.kind() == "string_literal" && node_text(expression, source) == "\"\""
}

/// `java/inefficient-boxed-constructor`: `new Integer(...)`-style allocation
/// instead of `valueOf`. Shadowed wrapper names are not `java.lang` types.
fn boxed_constructor_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let base = node_text(type_node, source)
        .split(['<', '['])
        .next()
        .unwrap_or("")
        .trim();
    let Some((wrapper, primitive)) = BOXED_TYPES.iter().find(|boxed| boxed.0 == base) else {
        return;
    };
    let argument_count = node
        .child_by_field_name("arguments")
        .map_or(0, |arguments| arguments.named_child_count());
    if argument_count != 1 || semantics.type_name_is_shadowed_at(base, type_node.start_byte()) {
        return;
    }
    issues.push(issue(
        INEFFICIENT_BOXED_CONSTRUCTOR,
        &format!(
            "Inefficient constructor for {primitive} value, use {wrapper}.valueOf(...) instead."
        ),
        node,
        source,
        index,
    ));
}

/// `java/continue-in-false-loop`: an unlabeled `continue` in
/// `do { ... } while (false);` always exits the loop.
fn gcq_continue_issues(node: Node<'_>, source: &str, index: &LineIndex, issues: &mut Vec<Issue>) {
    let Some(condition) = node.child_by_field_name("condition").map(unwrap_parens) else {
        return;
    };
    if condition.kind() != "false" {
        return;
    }
    for continue_node in crate::support::collect_kinds(node, &["continue_statement"]) {
        if continue_node.named_child_count() > 0 || nearest_loop(continue_node) != Some(node) {
            continue;
        }
        issues.push(issue(
            CONTINUE_IN_FALSE_LOOP,
            "This 'continue' never re-runs the loop - the loop condition is always false.",
            continue_node,
            source,
            index,
        ));
    }
}

fn nearest_loop(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "do_statement" | "while_statement" | "for_statement" | "enhanced_for_statement"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn unwrap_parens(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression"
        && let Some(inner) = node.named_child(0)
    {
        node = inner;
    }
    node
}

fn gcq_reference<'a>(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &'a SemanticIndex,
) -> Option<&'a ReferenceFact> {
    let position = index.position(source, node.start_byte());
    let found = semantics
        .references
        .binary_search_by(|reference| reference.range.start.cmp(&position))
        .ok()?;
    let reference = &semantics.references[found];
    (reference.name == node_text(node, source)).then_some(reference)
}

fn gcq_symbol<'a>(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &'a SemanticIndex,
) -> Option<&'a crate::context::Symbol> {
    gcq_reference(node, source, index, semantics)
        .and_then(|reference| reference.symbol)
        .and_then(|id| semantics.symbols.get(id.0))
}

fn is_array_typed(
    expression: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> bool {
    let expression = unwrap_parens(expression);
    if expression.kind() == "array_creation_expression" {
        return true;
    }
    declared_base_type(expression, source, index, semantics).is_some_and(|(_, is_array)| is_array)
}

/// `(base type name, is array)` for an identifier declared in this file.
fn declared_base_type(
    expression: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> Option<(String, bool)> {
    let expression = unwrap_parens(expression);
    if expression.kind() != "identifier" {
        return None;
    }
    let symbol = gcq_symbol(expression, source, index, semantics)?;
    let declared = symbol.declared_type.as_deref()?;
    let is_array = declared.contains('[');
    let base = declared.split(['<', '[']).next()?.trim().to_owned();
    Some((base, is_array))
}

/// Whether an identifier's declared type is an unshadowed `java.lang` type.
fn declared_type_is_java_lang(
    expression: Node<'_>,
    name: &str,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> bool {
    let Some((base, _)) = declared_base_type(expression, source, index, semantics) else {
        return false;
    };
    (base == name || base == format!("java.lang.{name}"))
        && !semantics.type_name_is_shadowed_at(name, expression.start_byte())
}

fn creation_type_is_java_lang(
    creation: Node<'_>,
    name: &str,
    source: &str,
    semantics: &SemanticIndex,
) -> bool {
    let Some(type_node) = creation.child_by_field_name("type") else {
        return false;
    };
    let base = node_text(type_node, source)
        .split(['<', '['])
        .next()
        .unwrap_or("")
        .trim();
    (base == name || base == format!("java.lang.{name}"))
        && !semantics.type_name_is_shadowed_at(name, type_node.start_byte())
}

/// Unescaped inner text of a string literal, escapes left as written.
fn string_literal_value<'source>(literal: Node<'_>, source: &'source str) -> &'source str {
    let text = node_text(literal, source);
    text.strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .unwrap_or(text)
}

// == Batch 2 of the pinned GitHub `CodeQL` Java queries =====================
//
// Grounded in the catalog sources pinned at revision
// `cb55cf1f281101f8e6d1522998e821d1b3547ce4`: RefEqBoxed.ql,
// SynchOnBoxedType.ql, LShiftLargerThanTypeWidth.ql, IterableIterator.ql,
// PrintLnArray.ql, DefaultToString.ql, HashedButNoHash.ql,
// InefficientKeySetIterator.ql, IntMultToLong.ql, JdkInternalAccess.ql,
// SuspiciousDateFormat.ql, SynchSetUnsynchGet.ql, UselessTypeTest.ql,
// UnusedFormatArg.ql, ContainsTypeMismatch.ql, RemoveTypeMismatch.ql, and
// LocalShadowsFieldConfusing.ql. Only single-file-provable facts are used.

const CALL_TO_OBJECT_TOSTRING: &str = "java/call-to-object-tostring";
const HASHING_WITHOUT_HASHCODE: &str = "java/hashing-without-hashcode";
const INEFFICIENT_KEY_SET_ITERATOR: &str = "java/inefficient-key-set-iterator";
const INTEGER_MULT_CAST_TO_LONG: &str = "java/integer-multiplication-cast-to-long";
const ITERATOR_IMPLEMENTS_ITERABLE: &str = "java/iterator-implements-iterable";
const JDK_INTERNAL_API_ACCESS: &str = "java/jdk-internal-api-access";
const LOCAL_SHADOWS_FIELD: &str = "java/local-shadows-field";
const LSHIFT_LARGER_THAN_TYPE_WIDTH: &str = "java/lshift-larger-than-type-width";
const PRINT_ARRAY: &str = "java/print-array";
const REFERENCE_EQUALITY_OF_BOXED_TYPES: &str = "java/reference-equality-of-boxed-types";
const SUSPICIOUS_DATE_FORMAT: &str = "java/suspicious-date-format";
const SYNC_ON_BOXED_TYPES: &str = "java/sync-on-boxed-types";
const TYPE_MISMATCH_ACCESS: &str = "java/type-mismatch-access";
const TYPE_MISMATCH_MODIFICATION: &str = "java/type-mismatch-modification";
const UNSYNCHRONIZED_GETTER: &str = "java/unsynchronized-getter";
const UNUSED_FORMAT_ARGUMENT: &str = "java/unused-format-argument";
const USELESS_TYPE_TEST: &str = "java/useless-type-test";

/// Packages of unsupported JDK-internal APIs, from the pinned
/// `JdkInternals.qll` list (`jdk8_internals.txt`). A package matches when it
/// equals an entry or lives underneath one.
const JDK_INTERNAL_PACKAGE_PREFIXES: [&str; 16] = [
    "apple.applescript",
    "apple.laf",
    "apple.launcher",
    "apple.security",
    "com.apple",
    "com.oracle",
    "com.sun",
    "java.awt.dnd.peer",
    "java.awt.peer",
    "javafx.embed",
    "jdk",
    "oracle.jrockit",
    "org.jcp",
    "org.omg",
    "org.relaxng",
    "sun",
];

/// `java.lang` types that cannot be subclassed, with their fixed supertypes.
const CLOSED_JAVA_LANG_TYPES: [(&str, &[&str]); 9] = [
    ("String", &["CharSequence", "Object"]),
    ("Integer", &["Number", "Object"]),
    ("Long", &["Number", "Object"]),
    ("Short", &["Number", "Object"]),
    ("Byte", &["Number", "Object"]),
    ("Double", &["Number", "Object"]),
    ("Float", &["Number", "Object"]),
    ("Character", &["Object"]),
    ("Boolean", &["Object"]),
];

/// Wrapper types compared by `RefEqBoxed.ql` and synchronized on by
/// `SynchOnBoxedType.ql`.
const BOXED_TYPE_NAMES: [&str; 8] = [
    "Integer",
    "Long",
    "Short",
    "Byte",
    "Character",
    "Boolean",
    "Float",
    "Double",
];

const PRIMITIVE_TYPE_NAMES: [&str; 8] = [
    "int", "long", "short", "byte", "char", "boolean", "float", "double",
];

/// A named type declared in the analyzed file plus its provable supertypes.
#[derive(Debug, Default)]
struct LocalTypeDecl {
    supers: Vec<String>,
    closed: bool,
}

/// Single-file type graph for `notHaveIntersection` decisions.
#[derive(Debug, Default)]
struct LocalTypeGraph {
    decls: std::collections::BTreeMap<String, LocalTypeDecl>,
}

impl LocalTypeGraph {
    fn build(root: Node<'_>, source: &str) -> Self {
        let mut graph = Self::default();
        for declaration in crate::support::collect_kinds(
            root,
            &[
                "class_declaration",
                "interface_declaration",
                "enum_declaration",
                "record_declaration",
            ],
        ) {
            let Some(name) = declaration.child_by_field_name("name") else {
                continue;
            };
            let supers = direct_supertype_nodes(declaration)
                .iter()
                .map(|supertype| simple_supertype_name(*supertype, source).to_owned())
                .collect::<Vec<_>>();
            let closed = has_modifier(declaration, source, "final")
                || declaration.kind() == "record_declaration"
                || declaration.kind() == "enum_declaration";
            graph.decls.insert(
                node_text(name, source).to_owned(),
                LocalTypeDecl { supers, closed },
            );
        }
        graph
    }

    fn push_supertypes(&self, name: &str, pending: &mut Vec<String>) {
        if let Some((_, library_supers)) =
            CLOSED_JAVA_LANG_TYPES.iter().find(|(key, _)| *key == name)
        {
            pending.extend(library_supers.iter().map(std::string::ToString::to_string));
            return;
        }
        if let Some(declaration) = self.decls.get(name) {
            pending.extend(declaration.supers.iter().cloned());
            if !declaration
                .supers
                .iter()
                .any(|supertype| supertype == "Object")
            {
                pending.push("Object".to_owned());
            }
        }
    }

    /// `Some(false)` proves there is no common subtype; `None` means unknown.
    fn may_intersect(&self, left: &str, right: &str) -> Option<bool> {
        if left == right {
            return Some(true);
        }
        let reaches = |from: &str, to: &str| -> bool {
            let mut seen = std::collections::BTreeSet::new();
            let mut pending = vec![from.to_owned()];
            while let Some(current) = pending.pop() {
                if !seen.insert(current.clone()) {
                    continue;
                }
                if current == to {
                    return true;
                }
                self.push_supertypes(&current, &mut pending);
            }
            false
        };
        if reaches(left, right) || reaches(right, left) {
            return Some(true);
        }
        let closed = |name: &str| {
            self.decls
                .get(name)
                .is_some_and(|declaration| declaration.closed)
                || CLOSED_JAVA_LANG_TYPES.iter().any(|(key, _)| *key == name)
        };
        (closed(left) || closed(right)).then_some(false)
    }
}

/// Strips generics from a type node's text.
fn base_type_text(node: Node<'_>, source: &str) -> String {
    node_text(node, source)
        .split('<')
        .next()
        .unwrap_or("")
        .trim()
        .to_owned()
}

/// Short name of a possibly qualified type text.
fn short_type_name(text: &str) -> &str {
    text.rsplit('.').next().unwrap_or(text)
}

/// `(base name, top-level generic arguments)` of a declared type text.
fn split_declared_generics(declared: &str) -> (String, Vec<String>) {
    let (base, rest) = match declared.find('<') {
        Some(index) => (declared[..index].trim(), Some(&declared[index + 1..])),
        None => (declared.trim(), None),
    };
    let mut arguments = Vec::new();
    if let Some(rest) = rest {
        let mut depth = 0usize;
        let mut current = String::new();
        for character in rest.chars() {
            match character {
                '<' => {
                    depth += 1;
                    current.push(character);
                }
                '>' => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    current.push(character);
                }
                ',' if depth == 0 => {
                    arguments.push(current.trim().to_owned());
                    current.clear();
                }
                _ => current.push(character),
            }
        }
        if !current.trim().is_empty() {
            arguments.push(current.trim().to_owned());
        }
    }
    (base.to_owned(), arguments)
}

fn gcq_batch2_issues(
    root: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let graph = LocalTypeGraph::build(root, source);
    walk_all(root, &mut |node| match node.kind() {
        "import_declaration" => {
            jdk_internal_import_issue(node, source, index, semantics, &mut issues);
        }
        "binary_expression" => {
            boxed_reference_equality_issue(node, source, index, semantics, &mut issues);
            left_shift_width_issue(node, source, index, semantics, &mut issues);
            concat_default_to_string_issue(node, source, index, semantics, &mut issues);
        }
        "synchronized_statement" => {
            sync_on_boxed_issue(node, source, index, semantics, &mut issues);
        }
        "instanceof_expression" => {
            useless_type_test_issue(node, source, index, semantics, &mut issues);
        }
        "method_invocation" => {
            print_array_issue(node, source, index, semantics, &mut issues);
            default_to_string_issue(node, source, index, semantics, &mut issues);
            unused_format_argument_issue(node, source, index, semantics, &mut issues);
            container_mismatch_issue(
                node,
                source,
                index,
                semantics,
                &graph,
                TYPE_MISMATCH_ACCESS,
                &mut issues,
            );
            container_mismatch_issue(
                node,
                source,
                index,
                semantics,
                &graph,
                TYPE_MISMATCH_MODIFICATION,
                &mut issues,
            );
            hashing_usage_issue(node, source, index, semantics, root, &mut issues);
        }
        "object_creation_expression" => {
            suspicious_date_format_issue(node, source, index, semantics, &mut issues);
            hashing_constructor_issue(node, source, index, semantics, root, &mut issues);
        }
        "local_variable_declaration" => {
            integer_mult_to_long_declaration_issue(node, source, index, semantics, &mut issues);
            local_shadows_field_issue(node, source, index, semantics, &mut issues);
        }
        "assignment_expression" => {
            integer_mult_to_long_assignment_issue(node, source, index, semantics, &mut issues);
        }
        "return_statement" => {
            integer_mult_to_long_return_issue(node, source, index, semantics, &mut issues);
        }
        _ => {}
    });
    key_set_iterator_issues(root, source, index, &mut issues);
    class_level_gcq_issues(root, source, index, semantics, &mut issues);
    issues
}

// -- java/reference-equality-of-boxed-types ----------------------------------

fn boxed_type_at(
    expression: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> Option<&'static str> {
    let expression = unwrap_parens(expression);
    if expression.kind() == "object_creation_expression" {
        let type_node = expression.child_by_field_name("type")?;
        let text = base_type_text(type_node, source);
        let base = short_type_name(&text);
        return BOXED_TYPE_NAMES
            .iter()
            .find(|boxed| **boxed == base)
            .copied();
    }
    let (base, is_array) = declared_base_type(expression, source, index, semantics)?;
    if is_array {
        return None;
    }
    let base = short_type_name(&base);
    BOXED_TYPE_NAMES
        .iter()
        .find(|boxed| **boxed == base)
        .copied()
}

fn boxed_reference_equality_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let operator = node
        .child_by_field_name("operator")
        .map(|operator| node_text(operator, source));
    if !matches!(operator, Some("==" | "!=")) {
        return;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    // The pinned query compares boxed types on both sides and excludes the
    // reference-comparison-safe `Boolean` type.
    let left_boxed = boxed_type_at(left, source, index, semantics);
    let right_boxed = boxed_type_at(right, source, index, semantics);
    if left_boxed.is_none() || right_boxed.is_none() {
        return;
    }
    if left_boxed == Some("Boolean") || right_boxed == Some("Boolean") {
        return;
    }
    issues.push(issue(
        REFERENCE_EQUALITY_OF_BOXED_TYPES,
        "Suspicious reference comparison of boxed numerical values.",
        node,
        source,
        index,
    ));
}

// -- java/lshift-larger-than-type-width --------------------------------------

fn integral_type_width(
    expression: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> Option<u32> {
    let expression = unwrap_parens(expression);
    if matches!(
        expression.kind(),
        "decimal_integer_literal"
            | "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal"
    ) {
        let text = node_text(expression, source);
        return Some(if text.ends_with('L') || text.ends_with('l') {
            64
        } else {
            32
        });
    }
    let declared = declared_base_type(expression, source, index, semantics)?.0;
    match short_type_name(&declared) {
        "long" | "Long" => Some(64),
        "int" | "Integer" | "short" | "Short" | "byte" | "Byte" | "char" | "Character" => Some(32),
        _ => None,
    }
}

fn left_shift_width_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let operator = node
        .child_by_field_name("operator")
        .map(|operator| node_text(operator, source));
    if operator != Some("<<") {
        return;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    let Some(width) = integral_type_width(left, source, index, semantics) else {
        return;
    };
    let Some(value) = literal_number(right, source) else {
        return;
    };
    if value < 0 || value < i64::from(width) {
        return;
    }
    let declared = declared_base_type(left, source, index, semantics).map_or_else(
        || "int".to_owned(),
        |(base, _)| short_type_name(&base).to_owned(),
    );
    let article = if declared.starts_with(['a', 'e', 'i', 'o', 'u']) {
        "an"
    } else {
        "a"
    };
    let truncated = value % i64::from(width);
    issues.push(issue(
        LSHIFT_LARGER_THAN_TYPE_WIDTH,
        &format!(
            "Left-shifting {article} {declared} by more than {width} truncates the shift amount from {value} to {truncated}."
        ),
        node,
        source,
        index,
    ));
}

// -- java/sync-on-boxed-types ------------------------------------------------

fn synchronized_expression(statement: Node<'_>) -> Option<Node<'_>> {
    let parenthesized = direct_named_children(statement)
        .into_iter()
        .find(|child| child.kind() == "parenthesized_expression")?;
    parenthesized.named_child(0).map(unwrap_parens)
}

fn sync_on_boxed_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let Some(expression) = synchronized_expression(node) else {
        return;
    };
    let type_name = if matches!(expression.kind(), "string_literal" | "text_block")
        || expression_is_type(expression, semantics, source, index, "String")
    {
        Some("String")
    } else {
        boxed_type_at(expression, source, index, semantics)
    };
    let Some(type_name) = type_name else {
        return;
    };
    issues.push(issue(
        SYNC_ON_BOXED_TYPES,
        &format!("Do not synchronize on objects of type {type_name}."),
        expression,
        source,
        index,
    ));
}

// -- java/suspicious-date-format ---------------------------------------------

fn suspicious_date_format_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    if short_type_name(&base_type_text(type_node, source)) != "SimpleDateFormat"
        || semantics.type_name_is_shadowed_at("SimpleDateFormat", type_node.start_byte())
    {
        return;
    }
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    let Some(first) = arguments.named_child(0) else {
        return;
    };
    let first = unwrap_parens(first);
    if !matches!(first.kind(), "string_literal" | "text_block") {
        return;
    }
    let format = string_literal_value(first, source);
    if !(format.contains('Y') && format.contains('M')) {
        return;
    }
    issues.push(issue(
        SUSPICIOUS_DATE_FORMAT,
        &format!("Date formatter is passed a suspicious pattern \"{format}\"."),
        node,
        source,
        index,
    ));
}

// -- java/print-array --------------------------------------------------------

fn print_array_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    if !matches!(node_text(name, source), "println" | "print") {
        return;
    }
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    if arguments.named_child_count() != 1 {
        return;
    }
    let Some(argument) = arguments.named_child(0) else {
        return;
    };
    if !is_array_typed(argument, source, index, semantics) {
        return;
    }
    issues.push(issue(
        PRINT_ARRAY,
        "Implicit conversion from Array to String.",
        argument,
        source,
        index,
    ));
}

// -- java/iterator-implements-iterable + java/unsynchronized-getter ----------

fn class_level_gcq_issues(
    root: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    for declaration in crate::support::collect_kinds(root, &["class_declaration"]) {
        iterator_implements_iterable_issue(declaration, source, index, semantics, issues);
        unsynchronized_getter_issues(declaration, source, index, issues);
    }
}

fn class_methods(declaration: Node<'_>) -> Vec<Node<'_>> {
    let Some(body) = declaration.child_by_field_name("body") else {
        return Vec::new();
    };
    crate::support::collect_kinds(body, &["method_declaration"])
}

fn method_named(method: Node<'_>, source: &str, wanted: &str) -> bool {
    method
        .child_by_field_name("name")
        .is_some_and(|name| node_text(name, source) == wanted)
}

fn returns_this(method: Node<'_>, source: &str) -> bool {
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    crate::support::collect_kinds(body, &["return_statement"])
        .iter()
        .any(|statement| {
            statement
                .named_child(0)
                .is_some_and(|expression| node_text(expression, source) == "this")
        })
}

fn always_returns_false(method: Node<'_>, source: &str) -> bool {
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    let statements = crate::support::collect_kinds(body, &["return_statement"]);
    !statements.is_empty()
        && statements.iter().all(|statement| {
            statement
                .named_child(0)
                .is_some_and(|expression| node_text(expression, source) == "false")
        })
}

fn iterator_implements_iterable_issue(
    declaration: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let mut supertype_nodes = Vec::new();
    if let Some(interfaces) = declaration.child_by_field_name("interfaces") {
        push_supertype_nodes(interfaces, &mut supertype_nodes);
    }
    let interfaces = supertype_nodes
        .iter()
        .map(|node| simple_supertype_name(*node, source).to_owned())
        .collect::<Vec<_>>();
    let implements_both = ["Iterator", "Iterable"].iter().all(|wanted| {
        interfaces.iter().any(|name| name == wanted)
            && !semantics.type_name_is_shadowed_at(wanted, declaration.start_byte())
    });
    if !implements_both {
        return;
    }
    let Some(iterator_method) = class_methods(declaration)
        .into_iter()
        .find(|method| method_named(*method, source, "iterator"))
    else {
        return;
    };
    if !returns_this(iterator_method, source) {
        return;
    }
    // The pinned query excludes iterators whose `hasNext` always returns
    // `false`: reuse of an empty iterator is safe.
    if class_methods(declaration).iter().any(|method| {
        method_named(*method, source, "hasNext") && always_returns_false(*method, source)
    }) {
        return;
    }
    if let Some(name) = declaration.child_by_field_name("name") {
        issues.push(issue(
            ITERATOR_IMPLEMENTS_ITERABLE,
            "This Iterable is its own Iterator, but does not guard against multiple iterations.",
            name,
            source,
            index,
        ));
    }
}

fn is_synchronized_method(method: Node<'_>, source: &str) -> bool {
    if has_modifier(method, source, "synchronized") {
        return true;
    }
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    crate::support::collect_kinds(body, &["synchronized_statement"])
        .iter()
        .any(|statement| {
            synchronized_expression(*statement)
                .is_some_and(|expression| node_text(expression, source) == "this")
        })
}

struct ClassField<'tree> {
    name: String,
    declaration: Node<'tree>,
}

fn class_fields<'tree>(declaration: Node<'tree>, source: &str) -> Vec<ClassField<'tree>> {
    let Some(body) = declaration.child_by_field_name("body") else {
        return Vec::new();
    };
    let mut fields = Vec::new();
    for field in crate::support::collect_kinds(body, &["field_declaration"]) {
        for child in direct_named_children(field) {
            if child.kind() != "variable_declarator" {
                continue;
            }
            let Some(name) = child.child_by_field_name("name") else {
                continue;
            };
            fields.push(ClassField {
                name: node_text(name, source).to_owned(),
                declaration: field,
            });
        }
    }
    fields
}

fn body_mentions_field(method: Node<'_>, field: &str, source: &str) -> bool {
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    crate::support::collect_kinds(body, &["identifier", "field_access"])
        .iter()
        .any(|node| {
            node_text(*node, source)
                .rsplit('.')
                .next()
                .is_some_and(|name| name == field)
        })
}

fn unsynchronized_getter_issues(
    declaration: Node<'_>,
    source: &str,
    index: &LineIndex,
    issues: &mut Vec<Issue>,
) {
    let methods = class_methods(declaration);
    let fields = class_fields(declaration, source);
    for setter in &methods {
        let Some(setter_name) = setter.child_by_field_name("name") else {
            continue;
        };
        let setter_name = node_text(setter_name, source);
        let Some(suffix) = setter_name.strip_prefix("set") else {
            continue;
        };
        if suffix.is_empty() || !is_synchronized_method(*setter, source) {
            continue;
        }
        let field_name = format!("{}{}", suffix[..1].to_ascii_lowercase(), &suffix[1..]);
        let Some(field) = fields.iter().find(|field| field.name == field_name) else {
            continue;
        };
        if has_modifier(field.declaration, source, "volatile") {
            continue;
        }
        let getter_name = format!("get{suffix}");
        let Some(getter) = methods
            .iter()
            .find(|method| method_named(**method, source, &getter_name))
        else {
            continue;
        };
        if is_synchronized_method(*getter, source) {
            continue;
        }
        // The pinned query pairs a getter that reads the field with a setter
        // that writes it.
        if !body_mentions_field(*getter, &field_name, source)
            || !body_mentions_field(*setter, &field_name, source)
        {
            continue;
        }
        if let Some(name) = getter.child_by_field_name("name") {
            issues.push(issue(
                UNSYNCHRONIZED_GETTER,
                "This get method is unsynchronized, but the corresponding set method is synchronized.",
                name,
                source,
                index,
            ));
        }
    }
}

// -- java/jdk-internal-api-access --------------------------------------------

fn jdk_internal_package(package: &str) -> bool {
    JDK_INTERNAL_PACKAGE_PREFIXES
        .iter()
        .any(|prefix| package == *prefix || package.starts_with(&format!("{prefix}.")))
}

fn jdk_internal_import_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let mut path = node_text(node, source)
        .trim()
        .trim_start_matches("import")
        .trim();
    let is_static = path.starts_with("static");
    if is_static {
        path = path.trim_start_matches("static").trim();
    }
    let path = path.trim_end_matches(';').trim();
    let wildcard = path.ends_with(".*");
    let path = path.trim_end_matches(".*").trim();
    let mut segments: Vec<&str> = path.split('.').collect();
    if !wildcard {
        segments.pop();
    }
    if is_static {
        segments.pop();
    }
    let Some(package) = (!segments.is_empty()).then(|| segments.join(".")) else {
        return;
    };
    if !jdk_internal_package(&package) {
        return;
    }
    // Files that already live in an internal package are exempt in the
    // pinned query.
    if semantics.package_name().is_some_and(jdk_internal_package) {
        return;
    }
    issues.push(issue(
        JDK_INTERNAL_API_ACCESS,
        &format!("Access to unsupported JDK-internal API '{path}'."),
        node,
        source,
        index,
    ));
}

// -- java/call-to-object-tostring --------------------------------------------

fn tree_root_of(node: Node<'_>) -> Node<'_> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        current = parent;
    }
    current
}

fn declares_tostring(declaration: Node<'_>, source: &str) -> bool {
    class_methods(declaration)
        .iter()
        .any(|method| method_named(*method, source, "toString"))
}

/// Whether `class_name` (declared once in this file) inherits the default
/// `Object.toString()` through its same-file supertype chain.
fn inherits_object_tostring(class_name: &str, root: Node<'_>, source: &str) -> bool {
    let mut current = class_name.to_owned();
    for _ in 0..16 {
        let Some(declaration) = find_unique_type(root, &current, source) else {
            return true;
        };
        if has_modifier(declaration, source, "abstract") {
            return false;
        }
        if declares_tostring(declaration, source) {
            return false;
        }
        let Some(superclass) = declaration.child_by_field_name("superclass") else {
            return true;
        };
        current = base_type_text(superclass, source);
    }
    true
}

fn local_class_type(
    expression: Node<'_>,
    root: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> Option<String> {
    let expression = unwrap_parens(expression);
    match expression.kind() {
        "identifier" => {
            let (base, is_array) = declared_base_type(expression, source, index, semantics)?;
            let base = short_type_name(&base);
            (!is_array && find_unique_type(root, base, source).is_some()).then(|| base.to_owned())
        }
        "field_access" => {
            let field = expression.child_by_field_name("field")?;
            let declared = gcq_symbol(field, source, index, semantics)?
                .declared_type
                .as_deref()?;
            if declared.contains('[') {
                return None;
            }
            let base = short_type_name(declared.split('<').next()?.trim());
            find_unique_type(root, base, source).map(|_| base.to_owned())
        }
        "this" => {
            let declaration = declaring_type(expression)?;
            let name = declaration.child_by_field_name("name")?;
            Some(node_text(name, source).to_owned())
        }
        _ => None,
    }
}

fn default_to_string_message(class_name: &str) -> String {
    format!(
        "Default toString(): {class_name} inherits toString() from Object, and so is not suitable for printing."
    )
}

fn default_to_string_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    if !method_named(node, source, "toString") {
        return;
    }
    if node
        .child_by_field_name("arguments")
        .is_some_and(|arguments| arguments.named_child_count() != 0)
    {
        return;
    }
    let Some(qualifier) = node.child_by_field_name("object") else {
        return;
    };
    let root = tree_root_of(node);
    let Some(class_name) = local_class_type(qualifier, root, source, index, semantics) else {
        return;
    };
    if !inherits_object_tostring(&class_name, root, source) {
        return;
    }
    issues.push(issue(
        CALL_TO_OBJECT_TOSTRING,
        &default_to_string_message(&class_name),
        qualifier,
        source,
        index,
    ));
}

fn concat_default_to_string_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let operator = node
        .child_by_field_name("operator")
        .map(|operator| node_text(operator, source));
    if operator != Some("+") {
        return;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    let root = tree_root_of(node);
    for operand in [left, right] {
        let Some(class_name) = local_class_type(operand, root, source, index, semantics) else {
            continue;
        };
        if !inherits_object_tostring(&class_name, root, source) {
            continue;
        }
        issues.push(issue(
            CALL_TO_OBJECT_TOSTRING,
            &default_to_string_message(&class_name),
            unwrap_parens(operand),
            source,
            index,
        ));
    }
}

// -- java/hashing-without-hashcode -------------------------------------------

fn equals_without_hashcode_classes(root: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    for declaration in crate::support::collect_kinds(root, &["class_declaration"]) {
        let Some(name) = declaration.child_by_field_name("name") else {
            continue;
        };
        let methods = class_methods(declaration);
        if methods
            .iter()
            .any(|method| method_named(*method, source, "hashCode"))
        {
            continue;
        }
        let has_plain_equals = methods.iter().any(|method| {
            if !method_named(*method, source, "equals") {
                return false;
            }
            let parameter_ok = method
                .child_by_field_name("parameters")
                .and_then(|parameters| parameters.named_child(0))
                .and_then(|parameter| parameter.child_by_field_name("type"))
                .is_some_and(|type_node| {
                    matches!(
                        base_type_text(type_node, source).as_str(),
                        "Object" | "java.lang.Object"
                    )
                });
            parameter_ok
                && method
                    .child_by_field_name("body")
                    .is_some_and(|body| !node_text(body, source).contains("super.equals"))
        });
        if has_plain_equals {
            names.push(node_text(name, source).to_owned());
        }
    }
    names
}

fn hashing_receiver_base(
    qualifier: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> Option<String> {
    let qualifier = unwrap_parens(qualifier);
    match qualifier.kind() {
        "identifier" => {
            declared_base_type(qualifier, source, index, semantics).map(|(base, _)| base)
        }
        "field_access" => {
            let field = qualifier.child_by_field_name("field")?;
            gcq_symbol(field, source, index, semantics)
                .and_then(|symbol| symbol.declared_type.clone())
        }
        _ => None,
    }
}

fn hashing_type_base(base: &str) -> bool {
    let short = short_type_name(base);
    short.contains("Hash") && short != "IdentityHashMap"
}

fn hashing_usage_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    root: Node<'_>,
    issues: &mut Vec<Issue>,
) {
    let classes = equals_without_hashcode_classes(root, source);
    if classes.is_empty() {
        return;
    }
    if !matches!(
        node.child_by_field_name("name")
            .map(|name| node_text(name, source)),
        Some("add" | "contains" | "containsKey" | "get" | "put" | "remove")
    ) {
        return;
    }
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    let Some(first) = arguments.named_child(0) else {
        return;
    };
    let Some(qualifier) = node.child_by_field_name("object") else {
        return;
    };
    let Some(declared) = hashing_receiver_base(qualifier, source, index, semantics) else {
        return;
    };
    if !hashing_type_base(&declared) {
        return;
    }
    let Some(argument_type) = local_class_type(first, root, source, index, semantics) else {
        return;
    };
    if !classes.contains(&argument_type) {
        return;
    }
    issues.push(issue(
        HASHING_WITHOUT_HASHCODE,
        &format!(
            "Type '{argument_type}' does not define hashCode(), but is used in a hashing data-structure."
        ),
        node,
        source,
        index,
    ));
}

fn hashing_constructor_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    _semantics: &SemanticIndex,
    root: Node<'_>,
    issues: &mut Vec<Issue>,
) {
    let classes = equals_without_hashcode_classes(root, source);
    if classes.is_empty() {
        return;
    }
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let type_text = node_text(type_node, source);
    if !type_text.contains('<') || !hashing_type_base(type_text) {
        return;
    }
    let (_, arguments) = split_declared_generics(type_text);
    let Some(first) = arguments.first() else {
        return;
    };
    let element = short_type_name(first.trim());
    if !classes.iter().any(|class| class == element) {
        return;
    }
    issues.push(issue(
        HASHING_WITHOUT_HASHCODE,
        &format!(
            "Type '{element}' does not define hashCode(), but is used in a hashing data-structure."
        ),
        node,
        source,
        index,
    ));
}

// -- java/inefficient-key-set-iterator ---------------------------------------

/// `map.keySet().iterator()` -> `map` text.
fn key_set_iterator_base(value: Node<'_>, source: &str) -> Option<String> {
    let value = unwrap_parens(value);
    if value.kind() != "method_invocation" || !method_named(value, source, "iterator") {
        return None;
    }
    let receiver = unwrap_parens(value.child_by_field_name("object")?);
    if receiver.kind() != "method_invocation" || !method_named(receiver, source, "keySet") {
        return None;
    }
    let base = unwrap_parens(receiver.child_by_field_name("object")?);
    Some(node_text(base, source).to_owned())
}

/// `it.next()` or `(T) it.next()` -> `it` text.
fn iterator_next_base(value: Node<'_>, source: &str) -> Option<String> {
    let mut value = unwrap_parens(value);
    if value.kind() == "cast_expression" {
        value = unwrap_parens(value.child_by_field_name("value")?);
    }
    if value.kind() != "method_invocation" || !method_named(value, source, "next") {
        return None;
    }
    let receiver = unwrap_parens(value.child_by_field_name("object")?);
    Some(node_text(receiver, source).to_owned())
}

fn key_set_iterator_issues(
    root: Node<'_>,
    source: &str,
    index: &LineIndex,
    issues: &mut Vec<Issue>,
) {
    for callable in
        crate::support::collect_kinds(root, &["method_declaration", "constructor_declaration"])
    {
        let Some(body) = callable.child_by_field_name("body") else {
            continue;
        };
        let mut iterators: Vec<(String, String)> = Vec::new();
        let mut keys: Vec<(String, String)> = Vec::new();
        for declaration in crate::support::collect_kinds(body, &["local_variable_declaration"]) {
            for declarator in direct_named_children(declaration) {
                if declarator.kind() != "variable_declarator" {
                    continue;
                }
                let (Some(name), Some(value)) = (
                    declarator.child_by_field_name("name"),
                    declarator.child_by_field_name("value"),
                ) else {
                    continue;
                };
                let name = node_text(name, source).to_owned();
                if let Some(map) = key_set_iterator_base(value, source) {
                    iterators.push((name, map));
                } else if let Some(iterator) = iterator_next_base(value, source) {
                    keys.push((name, iterator));
                }
            }
        }
        if iterators.is_empty() || keys.is_empty() {
            continue;
        }
        for invocation in crate::support::collect_kinds(body, &["method_invocation"]) {
            if !method_named(invocation, source, "get") {
                continue;
            }
            let Some(arguments) = invocation.child_by_field_name("arguments") else {
                continue;
            };
            if arguments.named_child_count() != 1 {
                continue;
            }
            let (Some(argument), Some(qualifier)) = (
                arguments.named_child(0),
                invocation.child_by_field_name("object"),
            ) else {
                continue;
            };
            let map_name = node_text(unwrap_parens(qualifier), source);
            let key_name = node_text(unwrap_parens(argument), source);
            let Some((_, iterator)) = keys.iter().find(|(key, _)| key == key_name) else {
                continue;
            };
            let Some((_, base_map)) = iterators.iter().find(|(name, _)| name == iterator) else {
                continue;
            };
            if base_map == map_name {
                issues.push(issue(
                    INEFFICIENT_KEY_SET_ITERATOR,
                    "Inefficient use of key set iterator instead of entry set iterator.",
                    invocation,
                    source,
                    index,
                ));
            }
        }
    }
}

// -- java/integer-multiplication-cast-to-long --------------------------------

/// Multiplications reachable from `expression` through the pinned query's
/// value-preserving parents (`ArithExpr` and `ConditionalExpr`).
fn integer_mult_candidates<'tree>(
    expression: Node<'tree>,
    source: &str,
    result: &mut Vec<Node<'tree>>,
) {
    let expression = unwrap_parens(expression);
    let operator = expression
        .child_by_field_name("operator")
        .map(|operator| node_text(operator, source));
    match (expression.kind(), operator) {
        ("binary_expression", Some("*")) => {
            result.push(expression);
            for field in ["left", "right"] {
                if let Some(operand) = expression.child_by_field_name(field) {
                    integer_mult_candidates(operand, source, result);
                }
            }
        }
        ("binary_expression", Some("+" | "-" | "/" | "%")) => {
            for field in ["left", "right"] {
                if let Some(operand) = expression.child_by_field_name(field) {
                    integer_mult_candidates(operand, source, result);
                }
            }
        }
        ("ternary_expression", _) => {
            for field in ["consequence", "alternative"] {
                if let Some(branch) = expression.child_by_field_name(field) {
                    integer_mult_candidates(branch, source, result);
                }
            }
        }
        _ => {}
    }
}

fn mult_operands_are_narrow_ints(
    mult: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> bool {
    for field in ["left", "right"] {
        let Some(operand) = mult.child_by_field_name(field) else {
            return false;
        };
        let operand = unwrap_parens(operand);
        if matches!(
            operand.kind(),
            "decimal_integer_literal"
                | "hex_integer_literal"
                | "octal_integer_literal"
                | "binary_integer_literal"
        ) {
            let text = node_text(operand, source);
            if text.ends_with('L') || text.ends_with('l') {
                return false;
            }
            continue;
        }
        if let Some((base, _)) = declared_base_type(operand, source, index, semantics)
            && matches!(
                short_type_name(&base),
                "long" | "Long" | "double" | "Double" | "float" | "Float"
            )
        {
            return false;
        }
    }
    true
}

/// The pinned query skips multiplications provably bounded within `int`.
fn mult_is_provably_small(mult: Node<'_>, source: &str) -> bool {
    let mut product: i128 = 1;
    for field in ["left", "right"] {
        let Some(operand) = mult.child_by_field_name(field) else {
            return false;
        };
        let Some(value) = literal_number(operand, source) else {
            return false;
        };
        product *= i128::from(value);
    }
    product.abs() <= i128::from(i32::MAX)
}

fn integer_mult_issues_at(
    anchor: Node<'_>,
    expression: Node<'_>,
    context: &str,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let mut candidates = Vec::new();
    integer_mult_candidates(expression, source, &mut candidates);
    for mult in candidates {
        if !mult_operands_are_narrow_ints(mult, source, index, semantics)
            || mult_is_provably_small(mult, source)
        {
            continue;
        }
        issues.push(issue(
            INTEGER_MULT_CAST_TO_LONG,
            &format!(
                "Potential overflow in int multiplication before it is converted to long by use in {context}."
            ),
            anchor,
            source,
            index,
        ));
        return;
    }
}

fn declared_type_is_wide_integral(declared: &str) -> bool {
    matches!(
        short_type_name(declared.split('<').next().unwrap_or(declared).trim()),
        "long" | "Long"
    )
}

fn integer_mult_to_long_declaration_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    if !matches!(base_type_text(type_node, source).as_str(), "long" | "Long") {
        return;
    }
    for declarator in direct_named_children(node) {
        if declarator.kind() != "variable_declarator" {
            continue;
        }
        let Some(value) = declarator.child_by_field_name("value") else {
            continue;
        };
        integer_mult_issues_at(
            declarator,
            value,
            "an assignment context",
            source,
            index,
            semantics,
            issues,
        );
    }
}

fn integer_mult_to_long_assignment_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let operator = node
        .child_by_field_name("operator")
        .map(|operator| node_text(operator, source));
    if operator != Some("=") {
        return;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    let left = unwrap_parens(left);
    if left.kind() != "identifier" {
        return;
    }
    let Some(declared) =
        gcq_symbol(left, source, index, semantics).and_then(|symbol| symbol.declared_type.clone())
    else {
        return;
    };
    if !declared_type_is_wide_integral(&declared) {
        return;
    }
    integer_mult_issues_at(
        node,
        right,
        "an assignment context",
        source,
        index,
        semantics,
        issues,
    );
}

fn integer_mult_to_long_return_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let Some(expression) = node.child_by_field_name("expression") else {
        return;
    };
    let mut current = node;
    while let Some(parent) = current.parent() {
        current = parent;
        if matches!(
            current.kind(),
            "method_declaration" | "constructor_declaration"
        ) {
            break;
        }
    }
    if current.kind() != "method_declaration" {
        return;
    }
    let Some(return_type) = current.child_by_field_name("type") else {
        return;
    };
    if !matches!(
        base_type_text(return_type, source).as_str(),
        "long" | "Long"
    ) {
        return;
    }
    integer_mult_issues_at(
        node,
        expression,
        "a return context",
        source,
        index,
        semantics,
        issues,
    );
}

// -- java/useless-type-test --------------------------------------------------

fn supertype_chain_contains(root: Node<'_>, from: &str, wanted: &str, source: &str) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    let mut pending = vec![from.to_owned()];
    while let Some(current) = pending.pop() {
        if !seen.insert(current.clone()) {
            continue;
        }
        if current == wanted {
            return true;
        }
        let Some(declaration) = find_unique_type(root, &current, source) else {
            continue;
        };
        for supertype in direct_supertype_nodes(declaration) {
            pending.push(simple_supertype_name(supertype, source).to_owned());
        }
        pending.push("Object".to_owned());
    }
    false
}

fn useless_type_test_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let (Some(operand), Some(checked)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    let operand = unwrap_parens(operand);
    if operand.kind() != "identifier" {
        return;
    }
    let Some(declared) = gcq_symbol(operand, source, index, semantics)
        .and_then(|symbol| symbol.declared_type.clone())
    else {
        return;
    };
    if declared.contains('[') {
        return;
    }
    let declared_base =
        short_type_name(declared.split('<').next().unwrap_or(&declared).trim()).to_owned();
    let checked_text = base_type_text(checked, source);
    let checked_name = short_type_name(&checked_text).to_owned();
    let always_true = if checked_name == "Object" {
        !semantics.type_name_is_shadowed_at("Object", checked.start_byte())
            && !PRIMITIVE_TYPE_NAMES.contains(&declared_base.as_str())
    } else {
        supertype_chain_contains(tree_root_of(node), &declared_base, &checked_name, source)
    };
    if !always_true {
        return;
    }
    issues.push(issue(
        USELESS_TYPE_TEST,
        &format!(
            "There is no need to test whether an instance of {declared_base} is also an instance of {checked_name} - it always is."
        ),
        node,
        source,
        index,
    ));
}

// -- java/unused-format-argument ---------------------------------------------

/// Referenced 1-based argument indices of a `Formatter`-style format string.
/// `None` means the string has no specifications or cannot be parsed.
fn format_spec_references(format: &str) -> Option<Vec<usize>> {
    let chars: Vec<char> = format.chars().collect();
    let mut references = Vec::new();
    let mut sequential = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '%' {
            i += 1;
            continue;
        }
        i += 1;
        if i >= chars.len() {
            return None;
        }
        if chars[i] == '%' {
            i += 1;
            continue;
        }
        let mut explicit: Option<usize> = None;
        if chars[i] == '<' {
            if sequential == 0 {
                return None;
            }
            explicit = Some(sequential);
            i += 1;
        } else {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            if i > start && i < chars.len() && chars[i] == '$' {
                explicit = chars[start..i].iter().collect::<String>().parse().ok();
                if explicit == Some(0) {
                    return None;
                }
                i += 1;
            } else {
                i = start;
            }
        }
        while i < chars.len() && matches!(chars[i], '-' | '#' | '+' | ' ' | ',' | '(' | '0') {
            i += 1;
        }
        while i < chars.len() && chars[i].is_ascii_digit() {
            i += 1;
        }
        if i < chars.len() && chars[i] == '.' {
            i += 1;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
        }
        if i < chars.len() && (chars[i] == 't' || chars[i] == 'T') {
            i += 1;
        }
        if i >= chars.len() || !chars[i].is_alphabetic() {
            return None;
        }
        i += 1;
        if let Some(index) = explicit {
            references.push(index);
        } else {
            sequential += 1;
            references.push(sequential);
        }
    }
    (!references.is_empty()).then_some(references)
}

fn referenced_format_indices(format: &str) -> Option<usize> {
    let references = format_spec_references(format)?;
    let max = *references.iter().max()?;
    let skipped = (1..=max)
        .filter(|index| !references.contains(index))
        .count();
    Some(max - skipped)
}

fn argument_type_is_throwable(
    expression: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> bool {
    let expression = unwrap_parens(expression);
    let name = match expression.kind() {
        "object_creation_expression" => expression
            .child_by_field_name("type")
            .map(|type_node| short_type_name(&base_type_text(type_node, source)).to_owned()),
        "identifier" => declared_base_type(expression, source, index, semantics)
            .map(|(base, _)| short_type_name(&base).to_owned()),
        _ => None,
    };
    name.is_some_and(|name| {
        name.ends_with("Exception") || name.ends_with("Error") || name == "Throwable"
    })
}

fn unused_format_argument_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    if !matches!(
        node.child_by_field_name("name")
            .map(|name| node_text(name, source)),
        Some("format" | "printf")
    ) {
        return;
    }
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    let count = arguments.named_child_count();
    if count < 2 {
        return;
    }
    let Some(first) = arguments.named_child(0) else {
        return;
    };
    let first = unwrap_parens(first);
    if !matches!(first.kind(), "string_literal" | "text_block") {
        return;
    }
    let Some(referenced) = referenced_format_indices(string_literal_value(first, source)) else {
        return;
    };
    let supplied = count - 1;
    if referenced >= supplied {
        return;
    }
    // The pinned query exempts a trailing throwable argument.
    if referenced + 1 == supplied
        && arguments
            .named_child(count - 1)
            .is_some_and(|last| argument_type_is_throwable(last, source, index, semantics))
    {
        return;
    }
    issues.push(issue(
        UNUSED_FORMAT_ARGUMENT,
        &format!(
            "This format call refers to {referenced} argument(s) but supplies {supplied} argument(s)."
        ),
        node,
        source,
        index,
    ));
}

// -- java/type-mismatch-access / java/type-mismatch-modification -------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContainerFamily {
    Collection,
    List,
    Deque,
    Vector,
    Map,
    Hashtable,
    Dictionary,
}

fn container_family(base: &str) -> Option<ContainerFamily> {
    Some(match short_type_name(base) {
        "Collection"
        | "Set"
        | "HashSet"
        | "LinkedHashSet"
        | "TreeSet"
        | "SortedSet"
        | "NavigableSet"
        | "Queue"
        | "BlockingQueue"
        | "PriorityQueue"
        | "AbstractCollection"
        | "Iterable"
        | "ConcurrentLinkedQueue"
        | "LinkedBlockingQueue" => ContainerFamily::Collection,
        "List" | "ArrayList" | "LinkedList" | "AbstractList" | "CopyOnWriteArrayList" => {
            ContainerFamily::List
        }
        "Deque"
        | "ArrayDeque"
        | "ConcurrentLinkedDeque"
        | "LinkedBlockingDeque"
        | "BlockingDeque" => ContainerFamily::Deque,
        "Vector" | "Stack" => ContainerFamily::Vector,
        "Map"
        | "HashMap"
        | "TreeMap"
        | "LinkedHashMap"
        | "WeakHashMap"
        | "ConcurrentMap"
        | "ConcurrentHashMap"
        | "ConcurrentNavigableMap"
        | "AbstractMap"
        | "SortedMap"
        | "NavigableMap"
        | "EnumMap"
        | "IdentityHashMap" => ContainerFamily::Map,
        "Hashtable" | "Properties" => ContainerFamily::Hashtable,
        "Dictionary" => ContainerFamily::Dictionary,
        _ => return None,
    })
}

fn map_like_family(family: ContainerFamily) -> bool {
    matches!(
        family,
        ContainerFamily::Map | ContainerFamily::Hashtable | ContainerFamily::Dictionary
    )
}

fn receiver_declared_type(
    receiver: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> Option<String> {
    let receiver = unwrap_parens(receiver);
    match receiver.kind() {
        "identifier" => gcq_symbol(receiver, source, index, semantics)
            .and_then(|symbol| symbol.declared_type.clone()),
        "field_access" => {
            let field = receiver.child_by_field_name("field")?;
            gcq_symbol(field, source, index, semantics)
                .and_then(|symbol| symbol.declared_type.clone())
        }
        _ => None,
    }
}

/// `(method, argument count, family, receiver base)` -> generic positions and
/// argument indices to compare, mirroring the pinned `containerAccess` and
/// `containerModification` tables.
fn container_mismatch_checks(
    rule: &str,
    method: &str,
    argument_count: usize,
    family: ContainerFamily,
    receiver_base: &str,
) -> Vec<(usize, usize)> {
    let is_access = matches!(
        method,
        "contains"
            | "get"
            | "getOrDefault"
            | "containsKey"
            | "containsValue"
            | "indexOf"
            | "lastIndexOf"
    );
    let is_modification = matches!(
        method,
        "remove" | "removeFirstOccurrence" | "removeLastOccurrence" | "removeElement"
    );
    if (rule == TYPE_MISMATCH_ACCESS && !is_access)
        || (rule == TYPE_MISMATCH_MODIFICATION && !is_modification)
    {
        return Vec::new();
    }
    let map_like = map_like_family(family);
    match (method, argument_count) {
        ("contains", 1) => {
            if family == ContainerFamily::Hashtable
                || short_type_name(receiver_base) == "ConcurrentHashMap"
            {
                vec![(1, 0)]
            } else if matches!(
                family,
                ContainerFamily::Collection
                    | ContainerFamily::List
                    | ContainerFamily::Deque
                    | ContainerFamily::Vector
            ) {
                vec![(0, 0)]
            } else {
                Vec::new()
            }
        }
        ("get" | "containsKey", 1) | ("getOrDefault", 2) if map_like => vec![(0, 0)],
        ("containsValue", 1) if map_like => vec![(1, 0)],
        ("indexOf" | "lastIndexOf", 1)
            if matches!(family, ContainerFamily::List | ContainerFamily::Vector) =>
        {
            vec![(0, 0)]
        }
        ("remove", 1)
            if map_like
                || matches!(
                    family,
                    ContainerFamily::Collection
                        | ContainerFamily::List
                        | ContainerFamily::Deque
                        | ContainerFamily::Vector
                ) =>
        {
            vec![(0, 0)]
        }
        ("remove", 2) if family == ContainerFamily::Map => vec![(0, 0), (1, 1)],
        ("removeFirstOccurrence" | "removeLastOccurrence", 1)
            if family == ContainerFamily::Deque =>
        {
            vec![(0, 0)]
        }
        ("removeElement", 1) if family == ContainerFamily::Vector => vec![(0, 0)],
        _ => Vec::new(),
    }
}

/// The declared argument type, boxed when primitive, as the pinned query's
/// `getArgumentType` does.
fn container_argument_type(
    expression: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
) -> Option<String> {
    let expression = unwrap_parens(expression);
    let name = match expression.kind() {
        "string_literal" | "text_block" => "String".to_owned(),
        "character_literal" => "Character".to_owned(),
        "true" | "false" => "Boolean".to_owned(),
        "decimal_integer_literal"
        | "hex_integer_literal"
        | "octal_integer_literal"
        | "binary_integer_literal" => {
            let text = node_text(expression, source);
            if text.ends_with('L') || text.ends_with('l') {
                "Long"
            } else {
                "Integer"
            }
            .to_owned()
        }
        "decimal_floating_point_literal" | "hex_floating_point_literal" => {
            let text = node_text(expression, source);
            if text.ends_with('f') || text.ends_with('F') {
                "Float"
            } else {
                "Double"
            }
            .to_owned()
        }
        "unary_expression" => {
            return container_argument_type(
                expression.child_by_field_name("operand")?,
                source,
                index,
                semantics,
            );
        }
        "identifier" => {
            let declared = gcq_symbol(expression, source, index, semantics)?
                .declared_type
                .as_deref()?;
            if declared.contains('[') {
                return None;
            }
            short_type_name(declared.split('<').next()?.trim()).to_owned()
        }
        "object_creation_expression" | "cast_expression" => {
            let type_node = expression.child_by_field_name("type")?;
            short_type_name(&base_type_text(type_node, source)).to_owned()
        }
        _ => return None,
    };
    let boxed = match name.as_str() {
        "int" => "Integer",
        "long" => "Long",
        "short" => "Short",
        "byte" => "Byte",
        "char" => "Character",
        "boolean" => "Boolean",
        "double" => "Double",
        "float" => "Float",
        other => other,
    };
    Some(boxed.to_owned())
}

fn container_mismatch_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    graph: &LocalTypeGraph,
    rule: &str,
    issues: &mut Vec<Issue>,
) {
    let Some(method) = node
        .child_by_field_name("name")
        .map(|name| node_text(name, source))
    else {
        return;
    };
    if !matches!(
        method,
        "contains"
            | "get"
            | "getOrDefault"
            | "containsKey"
            | "containsValue"
            | "indexOf"
            | "lastIndexOf"
            | "remove"
            | "removeFirstOccurrence"
            | "removeLastOccurrence"
            | "removeElement"
    ) {
        return;
    }
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    let argument_count = arguments.named_child_count();
    let Some(qualifier) = node.child_by_field_name("object") else {
        return;
    };
    let Some(declared) = receiver_declared_type(qualifier, source, index, semantics) else {
        return;
    };
    let (base, generics) = split_declared_generics(&declared);
    let Some(family) = container_family(&base) else {
        return;
    };
    for (position, argument_index) in
        container_mismatch_checks(rule, method, argument_count, family, &base)
    {
        let Some(element) = generics.get(position) else {
            continue;
        };
        let element = element.trim();
        if element.is_empty() || element.starts_with('?') {
            continue;
        }
        let element = short_type_name(element);
        let Some(argument) = arguments.named_child(argument_index) else {
            continue;
        };
        let Some(argument_type) = container_argument_type(argument, source, index, semantics)
        else {
            continue;
        };
        // `List.remove(int)` overloads the object removal, so an integer
        // argument on a list is never a type mismatch.
        if rule == TYPE_MISMATCH_MODIFICATION
            && method == "remove"
            && !map_like_family(family)
            && argument_type == "Integer"
        {
            continue;
        }
        if element == "Object" || argument_type == "Object" {
            continue;
        }
        if graph.may_intersect(element, &argument_type) != Some(false) {
            continue;
        }
        issues.push(issue(
            rule,
            &format!(
                "Actual argument type '{argument_type}' is incompatible with expected argument type '{element}'."
            ),
            argument,
            source,
            index,
        ));
    }
}

// -- java/local-shadows-field ------------------------------------------------

fn local_shadows_field_issue(
    node: Node<'_>,
    source: &str,
    index: &LineIndex,
    semantics: &SemanticIndex,
    issues: &mut Vec<Issue>,
) {
    let _ = semantics;
    for declarator in direct_named_children(node) {
        if declarator.kind() != "variable_declarator" {
            continue;
        }
        let Some(name) = declarator.child_by_field_name("name") else {
            continue;
        };
        let name = node_text(name, source);
        let mut current = node;
        loop {
            let Some(parent) = current.parent() else {
                return;
            };
            current = parent;
            if current.kind() == "class_declaration" {
                break;
            }
        }
        let fields = class_fields(current, source);
        if !fields.iter().any(|field| field.name == name) {
            continue;
        }
        let Some(callable) = nearest_callable(node) else {
            continue;
        };
        if !has_confusing_local_use(callable, declarator, name, source) {
            continue;
        }
        let callable_name = callable
            .child_by_field_name("name")
            .map_or("<constructor>", |callable_name| {
                node_text(callable_name, source)
            });
        issues.push(issue(
            LOCAL_SHADOWS_FIELD,
            &format!(
                "Confusing name: method {callable_name} also refers to field {name} (without qualifying it with 'this')."
            ),
            declarator,
            source,
            index,
        ));
    }
}

fn nearest_callable(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        current = parent;
        if matches!(
            current.kind(),
            "method_declaration" | "constructor_declaration"
        ) {
            return Some(current);
        }
    }
    None
}

/// Whether the callable uses the shadowing local outside the pure
/// `this.f = local` / `local = this.f` accessor patterns of the pinned
/// `assignmentToShadowingLocal` / `assignmentFromShadowingLocal` exemptions.
fn has_confusing_local_use(
    callable: Node<'_>,
    declarator: Node<'_>,
    name: &str,
    source: &str,
) -> bool {
    let mut confusing = false;
    walk_all(callable, &mut |node| {
        if node.kind() != "identifier" || node_text(node, source) != name {
            return;
        }
        if declarator.start_byte() <= node.start_byte() && node.end_byte() <= declarator.end_byte()
        {
            return;
        }
        let mut excluded = node
            .parent()
            .is_some_and(|parent| parent.kind() == "field_access");
        if let Some(assignment) = node
            .parent()
            .filter(|parent| parent.kind() == "assignment_expression")
        {
            let left = assignment
                .child_by_field_name("left")
                .map(|left| node_text(left, source));
            let right = assignment
                .child_by_field_name("right")
                .map(|right| node_text(right, source));
            let value = node_text(node, source);
            let qualified = format!("this.{name}");
            if (left == Some(qualified.as_str()) && right == Some(value))
                || (right == Some(qualified.as_str()) && left == Some(value))
            {
                excluded = true;
            }
        }
        if !excluded {
            confusing = true;
        }
    });
    confusing
}

#[cfg(test)]
mod tests {
    use super::{build_cfg, solve_dataflow};
    use crate::context::{SemanticIndex, parse};
    use crate::support::LineIndex;

    #[test]
    fn branches_loops_and_returns_have_bounded_flow() {
        let source = "class A { int f(int x) { int y = 0; while (x > 0) { if (x == 1) return y; y = x; x--; } return y; } }";
        let lines = LineIndex::new(source);
        let tree = parse(source).expect("valid Java fixture");
        let semantics = SemanticIndex::build(tree.root_node(), source, &lines);
        let method = tree
            .root_node()
            .descendant_for_byte_range(0, source.len())
            .unwrap();
        let body = crate::support::collect_kinds(method, &["block"])
            .into_iter()
            .find(|node| node.start_byte() > 20)
            .unwrap();
        let cfg = build_cfg(body, source, &lines, &semantics);
        assert!(cfg.nodes.iter().any(|node| node.kind == "condition"));
        assert!(cfg.nodes.iter().any(|node| node.kind == "return_statement"));
        assert!(
            cfg.nodes
                .iter()
                .any(|node| node.successors.iter().any(|target| *target <= node.id))
        );
        let facts = solve_dataflow(&cfg);
        assert!(facts.iterations <= cfg.nodes.len() * 8 + 8);
    }
    #[test]
    fn for_continue_runs_update_before_condition() {
        let source =
            "class C { void f() { for (int i = 0; i < 2; i++) { if (i == 0) continue; } } }";
        let lines = LineIndex::new(source);
        let tree = parse(source).expect("valid Java fixture");
        let semantics = SemanticIndex::build(tree.root_node(), source, &lines);
        let body = crate::support::collect_kinds(tree.root_node(), &["block"])
            .into_iter()
            .find(|node| node.start_byte() > 15)
            .expect("method body");
        let cfg = build_cfg(body, source, &lines, &semantics);
        let continue_node = cfg
            .nodes
            .iter()
            .find(|node| node.kind == "continue")
            .expect("continue node");
        let update = cfg
            .nodes
            .iter()
            .find(|node| node.kind == "update_expression")
            .expect("for update node");
        assert!(continue_node.successors.contains(&update.id));
        let condition = cfg
            .nodes
            .iter()
            .find(|node| node.kind == "condition")
            .expect("for condition");
        assert!(update.successors.contains(&condition.id));
        assert!(condition.successors.iter().any(|target| {
            cfg.node(*target)
                .is_some_and(|node| node.kind == "loop_join")
        }));
    }

    #[test]
    fn empty_method_blocks_do_not_consume_depth_budget() {
        let source = "class C { void empty() {} }";
        let lines = LineIndex::new(source);
        let tree = parse(source).expect("valid Java fixture");
        let semantics = SemanticIndex::build(tree.root_node(), source, &lines);
        let body = crate::support::collect_kinds(tree.root_node(), &["block"])
            .into_iter()
            .find(|node| node.start_byte() > 15)
            .expect("method body");
        let cfg = build_cfg(body, source, &lines, &semantics);
        assert!(cfg.nodes.iter().all(|node| node.kind != "depth_limit"));
        assert_eq!(cfg.nodes.len(), 2);
    }
    fn github_issues(source: &str) -> Vec<hoonarqube_ir::Issue> {
        let lines = LineIndex::new(source);
        let tree = parse(source).expect("valid Java fixture");
        super::github_quality_issues(tree.root_node(), source, &lines)
    }

    fn count_rule(issues: &[hoonarqube_ir::Issue], rule: &str) -> usize {
        issues.iter().filter(|issue| issue.rule_key == rule).count()
    }

    #[test]
    fn qualified_external_supertype_withholds_constants_only_finding() {
        let source = "package p;\ninterface Constants { int X = 1; }\nclass Uses implements other.Constants { public void f() {} }";
        let issues = github_issues(source);
        assert_eq!(count_rule(&issues, "java/constants-only-interface"), 0);
        let local = "package p;\ninterface Constants { int X = 1; }\nclass Uses implements Constants { public void f() {} }";
        assert_eq!(
            count_rule(&github_issues(local), "java/constants-only-interface"),
            1
        );
        let same_package = "package other;\ninterface Constants { int X = 1; }\nclass Uses implements other.Constants { public void f() {} }";
        assert_eq!(
            count_rule(
                &github_issues(same_package),
                "java/constants-only-interface"
            ),
            1
        );
        let nested_shadow = "package p;\nclass Holder { interface Constants { int X = 1; } }\nclass Uses implements p.Constants { public void f() {} }";
        assert_eq!(
            count_rule(
                &github_issues(nested_shadow),
                "java/constants-only-interface"
            ),
            0
        );
        let relative_nested = "class Outer { static class Inner { interface Constants { int X = 1; } } class Uses implements Inner.Constants { void f() {} } }";
        assert_eq!(
            count_rule(
                &github_issues(relative_nested),
                "java/constants-only-interface"
            ),
            1
        );
    }
    #[test]
    fn enum_constant_override_bodies_are_distinct_declaring_types() {
        let source = r#"
import java.lang.reflect.Field;

interface NamingStrategy {
  String translateName(Field field);
}

enum EnumOverride implements NamingStrategy {
  FIRST() {
    @Override
    public String translateName(Field field) {
      return "first";
    }
  },
  SECOND() {
    @Override
    public String translateName(Field field) {
      return "second";
    }
  };
}

final class OrdinaryOverloads {
  void translateName(Object value) {}
  void translateName(String value) {}
}
"#;
        let issues = github_issues(source);
        let findings: Vec<_> = issues
            .iter()
            .filter(|issue| issue.rule_key == "java/confusing-method-signature")
            .collect();
        assert_eq!(
            findings.len(),
            1,
            "constant-specific overrides must not be reported; only the ordinary overload control remains: {issues:?}"
        );
        let control = findings[0];
        assert_eq!(
            control.range.start.line, 25,
            "the surviving finding must be the OrdinaryOverloads control, not an enum constant body"
        );
        assert!(
            control.message.contains("OrdinaryOverloads"),
            "the surviving finding must be the ordinary overload control: {}",
            control.message
        );
    }

    #[test]
    fn genuine_signature_conflicts_inside_enum_bodies_still_report() {
        let same_constant = "enum MixedBody {\n  A() {\n    void handle(Object value) {}\n    void handle(String value) {}\n  },\n  B()\n}";
        let issues = github_issues(same_constant);
        assert_eq!(count_rule(&issues, "java/confusing-method-signature"), 1);
        assert!(
            issues
                .iter()
                .any(|issue| issue.message.contains("A.handle")),
            "a confusing overload pair inside one constant body reports under that constant: {issues:?}"
        );

        let static_body = "enum StaticBody {\n  X;\n\n  void handle(Object value) {}\n  void handle(String value) {}\n}";
        let issues = github_issues(static_body);
        assert_eq!(count_rule(&issues, "java/confusing-method-signature"), 1);
        assert!(
            issues
                .iter()
                .any(|issue| issue.message.contains("StaticBody.handle")),
            "a confusing overload pair in the enum's own body reports under the enum: {issues:?}"
        );

        let separate_constants = "enum SeparateConstants {\n  FIRST() {\n    public String toUri() { return \"\"; }\n  },\n  SECOND() {\n    public String toURI() { return \"\"; }\n  }\n}";
        assert_eq!(
            count_rule(
                &github_issues(separate_constants),
                "java/confusing-method-name"
            ),
            0
        );
        let same_constant_names = "enum SameConstantNames {\n  A() {\n    public String toUri() { return \"\"; }\n    public String toURI() { return \"\"; }\n  }\n}";
        let issues = github_issues(same_constant_names);
        assert_eq!(count_rule(&issues, "java/confusing-method-name"), 1);
    }
    #[test]
    fn anonymous_class_methods_are_distinct_declaring_types() {
        let source = r"
import java.io.Writer;

interface Op {
  int run(int x);
}

final class Outer {
  int same(int a) { return a; }
  int same(Object a) { return 0; }

  Op first() {
    return new Op() {
      public int run(int x) { return x; }
    };
  }

  Op second() {
    return new Op() {
      public int run(int x) { return x + 1; }
    };
  }

  private final Writer sink = new Writer() {
    public void close() {}
    public void flush() {}
    public void write(char[] cbuf, int off, int len) {}
  };

  public void close() {}
  public void flush() {}
}
";
        let issues = github_issues(source);
        assert_eq!(
            count_rule(&issues, "java/confusing-method-signature"),
            0,
            "methods of distinct anonymous classes, or of an anonymous class and its \
             enclosing type, must not pair as overloads: {issues:?}"
        );
    }
    #[test]
    fn genuine_signature_conflicts_inside_anonymous_bodies_still_report() {
        let source = r"
interface Op {
  void handle(Object value);
}

final class Holder {
  Op make() {
    return new Op() {
      public void handle(Object value) {}
      public void handle(String value) {}
    };
  }
}
";
        let issues = github_issues(source);
        assert_eq!(
            count_rule(&issues, "java/confusing-method-signature"),
            1,
            "a confusing overload pair inside one anonymous body still reports: {issues:?}"
        );
        assert!(
            issues.iter().any(|issue| issue.message.contains("new Op")),
            "the pair must report under the anonymous class, not the enclosing type: {issues:?}"
        );
    }
    #[test]
    fn escape_sequence_tails_are_not_missing_space_word_characters() {
        let source = r#"
final class Messages {
  String gsonIdiom() {
    return "line one ends $\n" + "See https://example.com/troubleshooting";
  }
  String loneNewline() {
    return "\n" + "See https://example.com/troubleshooting";
  }
  String tabTail() {
    return "done\t" + "next";
  }
  String backslashTail() {
    return "dir\\" + "file";
  }
  String escapedRightStart() {
    return "foo" + "\tbar";
  }
  String wordSplitWithoutSpace() {
    return "Hello" + "World";
  }
  String textBlockEndsAtNewline() {
    return """
        done
        """ + "tail";
  }
}
"#;
        let issues = github_issues(source);
        assert_eq!(
            count_rule(&issues, "java/missing-space-in-concatenation"),
            0,
            "escape-sequence tails and word splits without an in-literal space are not \
             missing-space findings: {issues:?}"
        );
    }
    #[test]
    fn genuine_concatenation_missing_space_still_reports() {
        let source = r#"
final class Genuine {
  String split() {
    return "This text is" + "missing a space.";
  }
  String spaced() {
    return "This text is " + "missing a space.";
  }
  String digits() {
    return "line 12" + "column 3";
  }
}
"#;
        let issues = github_issues(source);
        assert_eq!(
            count_rule(&issues, "java/missing-space-in-concatenation"),
            2,
            "the QL-shape split and digit-word controls fire; the space-terminated literal stays quiet: {issues:?}"
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.message.contains("This text is")),
            "the surviving finding points at the split literal: {issues:?}"
        );
    }

    #[test]
    fn type_parameter_javadoc_tags_require_exact_names() {
        let bad = "/**\n * @param <T> wrong type parameter\n */\npublic class Probe<TT> {}";
        assert_eq!(
            count_rule(&github_issues(bad), "java/unknown-javadoc-parameter"),
            1
        );
        let good = "/**\n * @param <TT> declared type parameter\n */\npublic class Probe<TT> {}";
        assert_eq!(
            count_rule(&github_issues(good), "java/unknown-javadoc-parameter"),
            0
        );
        let unrelated =
            "/**\n * @param <Z> unrelated type parameter\n */\npublic class Probe<TT> {}";
        assert_eq!(
            count_rule(&github_issues(unrelated), "java/unknown-javadoc-parameter"),
            1
        );
        let bounded = "/**\n * @param <T> declared bounded type parameter\n */\npublic class Probe<T extends Number> {}";
        assert_eq!(
            count_rule(&github_issues(bounded), "java/unknown-javadoc-parameter"),
            0
        );
    }

    #[test]
    fn inline_param_prose_is_not_a_block_tag() {
        let inline =
            "/**\n * Example prose with {@code @param fake} inline.\n */\npublic class Probe {}";
        assert_eq!(
            count_rule(&github_issues(inline), "java/unknown-javadoc-parameter"),
            0
        );
        let block = "/**\n * @param missing does not exist\n */\npublic class Probe {}";
        assert_eq!(
            count_rule(&github_issues(block), "java/unknown-javadoc-parameter"),
            1
        );
        let gluing = "/**\n * @paramX glued tag text\n */\npublic class Probe {}";
        assert_eq!(
            count_rule(&github_issues(gluing), "java/unknown-javadoc-parameter"),
            0
        );
    }

    #[test]
    fn varargs_parameter_binds_javadoc_param() {
        let source = "class JavadocVarargs {\n    /**\n     * @param values accepted varargs parameter\n     */\n    void accepted(String... values) {}\n\n    /**\n     * @param value unknown parameter\n     */\n    void rejected(String... values) {}\n\n    /**\n     * @param value accepted ordinary parameter\n     */\n    void ordinary(String value) {}\n}";
        let issues = github_issues(source);
        let unknown = count_rule(&issues, "java/unknown-javadoc-parameter");
        assert_eq!(unknown, 1);
        let finding = issues
            .iter()
            .find(|issue| issue.rule_key == "java/unknown-javadoc-parameter")
            .expect("wrong varargs parameter should remain a finding");
        assert_eq!(finding.range.start.line, 8);
    }

    #[test]
    fn multiline_inline_tag_body_is_not_a_block_param() {
        let source = "/**\n * {@code\n * if (x) { run(); }\n * @param fake\n * }\n */\npublic class Probe {}";
        assert_eq!(
            count_rule(&github_issues(source), "java/unknown-javadoc-parameter"),
            0
        );
        let reset = "/**\n * {@code\n * if (x) { run(); }\n * }\n * @param missing real block tag after inline close\n */\npublic class Probe {}";
        assert_eq!(
            count_rule(&github_issues(reset), "java/unknown-javadoc-parameter"),
            1
        );
    }

    #[test]
    fn redundant_assignment_covers_self_and_this_qualified_fields() {
        let source =
            "class C { int f; void m(int x) { x = x; this.f = f; f = this.f; this.f = this.f; } }";
        assert_eq!(
            count_rule(&github_issues(source), "java/redundant-assignment"),
            4
        );
        let distinct = "class C { void m(int x, int y) { x = y; x += x; } }";
        assert_eq!(
            count_rule(&github_issues(distinct), "java/redundant-assignment"),
            0
        );
    }

    #[test]
    fn unread_local_skips_reads_updates_and_implicit_uses() {
        let dead = "class C { void m() { int dead = 1; } }";
        assert_eq!(
            count_rule(&github_issues(dead), "java/local-variable-is-never-read"),
            1
        );
        let reads = "class C { void m() { int used = 1; System.out.println(used); } }";
        assert_eq!(
            count_rule(&github_issues(reads), "java/local-variable-is-never-read"),
            0
        );
        let updates = "class C { void m() { int counter = 0; counter++; counter += 2; } }";
        assert_eq!(
            count_rule(&github_issues(updates), "java/local-variable-is-never-read"),
            0
        );
        let exempt = "class C { void m(java.util.List<String> xs) throws java.io.IOException { for (String s : xs) {} try (C r = new C()) {} catch (java.io.IOException e) {} } }";
        assert_eq!(
            count_rule(&github_issues(exempt), "java/local-variable-is-never-read"),
            0
        );
    }

    #[test]
    fn identical_comparison_covers_variables_literals_and_this_fields() {
        let source = "class C { int f; boolean m(int x) { return x == x && this.f == this.f && 'a' == 'a'; } }";
        assert_eq!(
            count_rule(
                &github_issues(source),
                "java/comparison-of-identical-expressions"
            ),
            3
        );
        let clean = "class C { int f; boolean m(int x, C other) { return x == other.f; } }";
        assert_eq!(
            count_rule(
                &github_issues(clean),
                "java/comparison-of-identical-expressions"
            ),
            0
        );
    }

    #[test]
    fn constant_comparison_decides_literal_tests_but_skips_asserts() {
        let source = "class C { boolean m() { return 1 < 2 && 2 <= 1 && 0x10 == 16; } }";
        assert_eq!(
            count_rule(&github_issues(source), "java/constant-comparison"),
            3
        );
        let asserted = "class C { void m() { assert 1 < 2; } }";
        assert_eq!(
            count_rule(&github_issues(asserted), "java/constant-comparison"),
            0
        );
        let dynamic = "class C { boolean m(int x) { return x < 2; } }";
        assert_eq!(
            count_rule(&github_issues(dynamic), "java/constant-comparison"),
            0
        );
    }

    #[test]
    fn useless_null_check_covers_allocation_and_literals() {
        let source = "class C { boolean m() { return new C() != null && new int[1] == null && \"s\" != null; } }";
        assert_eq!(
            count_rule(&github_issues(source), "java/useless-null-check"),
            3
        );
        let clean = "class C { boolean m(C c) { return c != null; } }";
        assert_eq!(
            count_rule(&github_issues(clean), "java/useless-null-check"),
            0
        );
    }

    #[test]
    fn nan_comparison_names_the_constant_type() {
        let source = "class C { boolean m(double d, float f) { return d == Double.NaN || f != Float.NaN || Float.NaN == f; } }";
        assert_eq!(
            count_rule(&github_issues(source), "java/comparison-with-nan"),
            3
        );
        let clean = "class C { boolean m(double d, double nan) { return d == nan; } }";
        assert_eq!(
            count_rule(&github_issues(clean), "java/comparison-with-nan"),
            0
        );
    }

    #[test]
    fn array_equals_requires_arrays_on_both_sides() {
        let source = "class C { boolean m(int[] xs, int[] ys) { return xs.equals(ys) || xs.hashCode() == 1; } }";
        assert_eq!(
            count_rule(&github_issues(source), "java/equals-on-arrays"),
            2
        );
        let clean =
            "class C { boolean m(int[] xs, java.util.List<Integer> ys) { return xs.equals(ys); } }";
        assert_eq!(
            count_rule(&github_issues(clean), "java/equals-on-arrays"),
            0
        );
    }

    #[test]
    fn tostring_on_strings_is_redundant() {
        let source = "class C { String m(String s) { return s.toString() + \"x\".toString(); } }";
        assert_eq!(
            count_rule(&github_issues(source), "java/useless-tostring-call"),
            2
        );
        let clean = "class C { String m(Object o) { return o.toString(); } }";
        assert_eq!(
            count_rule(&github_issues(clean), "java/useless-tostring-call"),
            0
        );
    }

    #[test]
    fn finalize_calls_are_flagged_except_super() {
        let source = "class C { void m() throws Throwable { finalize(); } void n(Object o) throws Throwable { o.finalize(); } }";
        assert_eq!(
            count_rule(&github_issues(source), "java/do-not-call-finalize"),
            2
        );
        let clean = "class C { protected void finalize() { super.finalize(); } }";
        assert_eq!(
            count_rule(&github_issues(clean), "java/do-not-call-finalize"),
            0
        );
    }

    #[test]
    fn thread_run_needs_a_thread_receiver() {
        let source = "class C { void m() { new Thread().run(); } void n(Thread t) { t.run(); } }";
        assert_eq!(
            count_rule(&github_issues(source), "java/call-to-thread-run"),
            2
        );
        let clean =
            "class C { void m() { new Thread().start(); } void n(Runnable r) { r.run(); } }";
        assert_eq!(
            count_rule(&github_issues(clean), "java/call-to-thread-run"),
            0
        );
        let inside_run = "class C { void run(Thread t) { t.run(); } }";
        assert_eq!(
            count_rule(&github_issues(inside_run), "java/call-to-thread-run"),
            0
        );
    }

    #[test]
    fn empty_string_equals_requires_string_qualifier_and_empty_literal() {
        let source = "class C { boolean m(String s) { return s.equals(\"\") || \"\".equals(s); } }";
        assert_eq!(
            count_rule(&github_issues(source), "java/inefficient-empty-string-test"),
            2
        );
        let clean = "class C { boolean m(String s, Object o) { return s.equals(\"x\") || o.equals(\"\"); } }";
        assert_eq!(
            count_rule(&github_issues(clean), "java/inefficient-empty-string-test"),
            0
        );
    }

    #[test]
    fn replace_all_flags_only_regex_free_literals() {
        let source = "class C { String m(String s) { return s.replaceAll(\"abc\", \"-\"); } }";
        assert_eq!(
            count_rule(
                &github_issues(source),
                "java/string-replace-all-with-non-regex"
            ),
            1
        );
        let clean = "class C { String m(String s) { return s.replaceAll(\"a.c\", \"-\") + s.replace(\"abc\", \"-\"); } }";
        assert_eq!(
            count_rule(
                &github_issues(clean),
                "java/string-replace-all-with-non-regex"
            ),
            0
        );
    }

    #[test]
    fn negative_container_size_covers_arrays_strings_collections_and_maps() {
        let source = "class C { boolean m(int[] xs, String s, java.util.List<String> list, java.util.Map<String, String> map) { return xs.length < 0 || s.length() < 0 || list.size() < 0 || map.size() < 0; } }";
        let issues = github_issues(source);
        assert_eq!(
            count_rule(&issues, "java/test-for-negative-container-size"),
            4
        );
        assert!(
            issues
                .iter()
                .filter(|issue| issue.rule_key == "java/test-for-negative-container-size")
                .any(|issue| issue.message.contains("a collection"))
                && issues
                    .iter()
                    .filter(|issue| issue.rule_key == "java/test-for-negative-container-size")
                    .any(|issue| issue.message.contains("a map"))
        );
        let reversed = "class C { boolean m(int[] xs) { return 0 > xs.length && xs.length >= 0 && 0 <= xs.length; } }";
        assert_eq!(
            count_rule(
                &github_issues(reversed),
                "java/test-for-negative-container-size"
            ),
            3
        );
        let clean = "class C { boolean m(int[] xs) { return xs.length > 0 && xs.length == 0 && 0 < xs.length; } }";
        assert_eq!(
            count_rule(
                &github_issues(clean),
                "java/test-for-negative-container-size"
            ),
            0
        );
    }

    #[test]
    fn continue_in_false_loop_only_flags_unlabeled_targets() {
        let source = "class C { void m() { do { continue; } while (false); } }";
        assert_eq!(
            count_rule(&github_issues(source), "java/continue-in-false-loop"),
            1
        );
        let labeled = "class C { void m() { outer: do { do { continue outer; } while (false); } while (false); } }";
        assert_eq!(
            count_rule(&github_issues(labeled), "java/continue-in-false-loop"),
            0
        );
        let while_loop = "class C { void m() { while (false) { continue; } } }";
        assert_eq!(
            count_rule(&github_issues(while_loop), "java/continue-in-false-loop"),
            0
        );
    }

    #[test]
    fn boxed_constructor_prefers_valueof_and_respects_import_shadowing() {
        let source = "class C { Object m() { return new Integer(1); } }";
        assert_eq!(
            count_rule(&github_issues(source), "java/inefficient-boxed-constructor"),
            1
        );
        let clean = "class C { Object m() { return Integer.valueOf(1); } }";
        assert_eq!(
            count_rule(&github_issues(clean), "java/inefficient-boxed-constructor"),
            0
        );
        let shadowed = "import p.Integer;\nclass C { Object m() { return new Integer(1); } }";
        assert_eq!(
            count_rule(
                &github_issues(shadowed),
                "java/inefficient-boxed-constructor"
            ),
            0
        );
    }
}
