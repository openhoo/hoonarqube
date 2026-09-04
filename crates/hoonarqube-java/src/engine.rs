//! Bounded intraprocedural control-flow, reaching-definition, and liveness facts.

use std::collections::BTreeSet;

use hoonarqube_ir::{FlowLocation, Issue, Range};
use tree_sitter::Node;

use crate::context::SemanticIndex;
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
    continue_targets: Vec<NodeId>,
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
            "do_statement" => self.do_loop(node, incoming, depth),
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
                    .find(|(name, _)| label.is_none() || name.as_deref() == label)
                {
                    self.edge(jump, *target);
                }
                Vec::new()
            }
            "continue_statement" => {
                let jump = self.add("continue", Some(node));
                self.connect(&incoming, jump);
                if let Some(target) = self.continue_targets.last().copied() {
                    self.edge(jump, target);
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

    fn while_loop(&mut self, node: Node<'_>, incoming: &[NodeId], depth: usize) -> Vec<NodeId> {
        let condition = node.child_by_field_name("condition").unwrap_or(node);
        let cond = self.add("condition", Some(condition));
        self.connect(incoming, cond);
        let after = self.add("loop_join", None);
        self.edge(cond, after);
        self.break_targets.push((None, after));
        self.continue_targets.push(cond);
        if let Some(body) = node.child_by_field_name("body") {
            let ends = self.statement(body, vec![cond], depth + 1);
            self.connect(&ends, cond);
        }
        self.continue_targets.pop();
        self.break_targets.pop();
        vec![after]
    }

    fn do_loop(&mut self, node: Node<'_>, incoming: Vec<NodeId>, depth: usize) -> Vec<NodeId> {
        let after = self.add("loop_join", None);
        self.break_targets.push((None, after));
        let condition = node.child_by_field_name("condition").unwrap_or(node);
        let cond = self.add("condition", Some(condition));
        self.continue_targets.push(cond);
        let ends = node
            .child_by_field_name("body")
            .map_or(incoming.clone(), |body| {
                self.statement(body, incoming, depth + 1)
            });
        self.connect(&ends, cond);
        self.edge(cond, after);
        if let Some(body) = node.child_by_field_name("body") {
            let body_start = self
                .nodes
                .iter()
                .find(|candidate| {
                    candidate.range.start == range_of(body, self.source, self.index).start
                })
                .map(|candidate| candidate.id);
            if let Some(body_start) = body_start {
                self.edge(cond, body_start);
            }
        }
        self.continue_targets.pop();
        self.break_targets.pop();
        vec![after]
    }

    fn for_loop(&mut self, node: Node<'_>, incoming: Vec<NodeId>, depth: usize) -> Vec<NodeId> {
        let mut frontier = incoming;
        if let Some(init) = node.child_by_field_name("init") {
            frontier = self.statement(init, frontier, depth + 1);
        }
        let condition = node.child_by_field_name("condition").unwrap_or(node);
        let cond = self.add("condition", Some(condition));
        self.connect(&frontier, cond);
        let after = self.add("loop_join", None);
        self.edge(cond, after);
        self.break_targets.push((None, after));
        self.continue_targets.push(cond);
        let body_end = node.child_by_field_name("body").map_or(vec![cond], |body| {
            self.statement(body, vec![cond], depth + 1)
        });
        let mut step_end = body_end;
        if let Some(update) = node.child_by_field_name("update") {
            step_end = self.statement(update, step_end, depth + 1);
        }
        self.connect(&step_end, cond);
        self.continue_targets.pop();
        self.break_targets.pop();
        vec![after]
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

#[must_use]
pub fn solve_dataflow(cfg: &ControlFlowGraph) -> DataflowSummary {
    let count = cfg.nodes.len();
    let mut reaching_in = vec![BTreeSet::new(); count];
    let mut reaching_out = vec![BTreeSet::new(); count];
    let mut live_in = vec![BTreeSet::new(); count];
    let mut live_out = vec![BTreeSet::new(); count];
    let mut iterations = 0;
    let limit = count.saturating_mul(8).max(8);
    for iteration in 0..limit {
        iterations = iteration + 1;
        let changed = reaching_pass(cfg, &mut reaching_in, &mut reaching_out)
            | liveness_pass(cfg, &mut live_in, &mut live_out);
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
    reaching_in: &mut [BTreeSet<Definition>],
    reaching_out: &mut [BTreeSet<Definition>],
) -> bool {
    let mut changed = false;
    for node in &cfg.nodes {
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
    live_in: &mut [BTreeSet<String>],
    live_out: &mut [BTreeSet<String>],
) -> bool {
    let mut changed = false;
    for node in cfg.nodes.iter().rev() {
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
            "method_declaration",
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
        "binary_expression" => binary_issues(node, source, index, issues),
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
    for supertype in direct_supertype_nodes(node) {
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
        && expression_is_type(first, semantics, source, "String")
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
        && expression_is_type(first, semantics, source, "char")
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
    expected: &str,
) -> bool {
    if expected == "String" && matches!(expression.kind(), "string_literal" | "text_block") {
        return true;
    }
    if expected == "char" && expression.kind() == "character_literal" {
        return true;
    }
    if expression.kind() != "identifier" {
        return false;
    }
    semantics
        .references
        .iter()
        .find(|reference| {
            reference.range.start.line as usize == expression.start_position().row + 1
                && reference.range.start.column as usize == expression.start_position().column
                && reference.name == node_text(expression, source)
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
            .is_some_and(|name| {
                node_text(name, source)
                    .to_ascii_lowercase()
                    .contains("test")
            })
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
            node,
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
            annotation
                .child_by_field_name("name")
                .is_some_and(|name| crate::support::simple_name(node_text(name, source)) == wanted)
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
            spelling == qualified || (imported && crate::support::simple_name(spelling) == wanted)
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
    member_class
        && !["static", "private", "abstract"]
            .iter()
            .any(|modifier| has_modifier(node, source, modifier))
        && (has_junit_annotation(node, source, index, "Test")
            || crate::support::collect_kinds(node, &["method_declaration"])
                .into_iter()
                .any(|method| has_junit_annotation(method, source, index, "Test")))
}

fn is_shadowed_type(index: &SemanticIndex, name: &str) -> bool {
    index.symbols.iter().any(|symbol| {
        symbol.kind == crate::context::SymbolKind::Type && symbol.canonical_name == name
    }) || index.imports.iter().any(|import| {
        !import.wildcard && import.simple_name == name && import.path != format!("java.lang.{name}")
    })
}

fn is_jdk_type(index: &SemanticIndex, node: Node<'_>, source: &str, expected: &str) -> bool {
    let spelling = node_text(node, source)
        .split_whitespace()
        .collect::<String>();
    spelling == format!("java.lang.{expected}")
        || (spelling == expected && !is_shadowed_type(index, expected))
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
    let l = string_tail(left, source);
    let r = string_tail(right, source);
    if !r.chars().next().is_some_and(|ch| ch.is_ascii_alphabetic()) {
        return false;
    }
    let mut word = l.trim_end();
    if word.len() != l.len() {
        return false;
    }
    while word
        .chars()
        .last()
        .is_some_and(|ch| matches!(ch, '.' | ':' | ',' | ';' | '!' | '?' | '\''))
    {
        word = word.get(..word.len().saturating_sub(1)).unwrap_or("");
    }
    word.chars()
        .last()
        .is_some_and(|ch| ch.is_ascii_alphanumeric())
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
    for (offset, line) in text.lines().enumerate() {
        let Some(at) = line.find("@param") else {
            continue;
        };
        let rest = line[at + 6..].trim();
        let tag_start = start
            + text
                .split_inclusive('\n')
                .take(offset)
                .map(str::len)
                .sum::<usize>()
            + at;
        let tag_range = index.range(source, tag_start, tag_start + 6);
        let valid = if rest.is_empty() {
            false
        } else {
            rest.starts_with('<') && rest.find('>').is_some() || !rest.starts_with('<')
        };
        let name_text = rest.split_whitespace().next().unwrap_or("");
        let params = node
            .child_by_field_name("parameters")
            .map(|p| {
                direct_named_children(p)
                    .into_iter()
                    .filter_map(|p| p.child_by_field_name("name"))
                    .map(|n| node_text(n, source))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let type_params = node
            .child_by_field_name("type_parameters")
            .map(|p| {
                direct_named_children(p)
                    .into_iter()
                    .map(|p| node_text(p, source))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let known = if name_text.starts_with('<') {
            type_params
                .iter()
                .any(|p| p.contains(name_text.trim_matches(['<', '>'])))
        } else {
            params.contains(&name_text)
        };
        if !valid || !known {
            let message = if valid {
                let what = if node.kind() == "constructor_declaration" {
                    "constructor"
                } else {
                    "method"
                };
                format!(
                    "@param tag \"{name_text}\" does not match any actual parameter of {what} \"{}()\".",
                    node_text(name, source)
                )
            } else {
                "This @param tag does not have a value.".to_owned()
            };
            out.push(Issue::new(
                "java/unknown-javadoc-parameter",
                message,
                tag_range,
            ));
        }
    }
    out
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
        let Some(owner) = ancestor(*method, "class_declaration") else {
            continue;
        };
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        if has_annotation(*method, source, "Deprecated") {
            continue;
        }
        for other in methods.iter().skip(i + 1) {
            if ancestor(*other, "class_declaration").is_none_or(|value| value.id() != owner.id())
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
        let count = method
            .child_by_field_name("parameters")
            .map_or(0, |p| p.named_child_count());
        for other in methods.iter().skip(i + 1) {
            let Some(other_name) = other.child_by_field_name("name") else {
                continue;
            };
            if ancestor(*method, "class_declaration").map(|node| node.id())
                != ancestor(*other, "class_declaration").map(|node| node.id())
            {
                continue;
            }
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
            let (primary, related) = if ancestor(*method, "class_declaration").map(|n| n.id())
                == ancestor(*other, "class_declaration").map(|n| n.id())
                || method.start_byte() > other.start_byte()
            {
                (*method, *other)
            } else {
                (*other, *method)
            };
            let owner = ancestor(primary, "class_declaration")
                .and_then(|n| n.child_by_field_name("name"))
                .map_or("", |n| node_text(n, source));
            let method_name = primary
                .child_by_field_name("name")
                .map_or("", |n| node_text(n, source));
            let mut finding = issue(
                "java/confusing-method-signature",
                &format!(
                    "Method {owner}.{method_name}(..) could be confused with overloaded method $@, since dispatch depends on static types."
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
    a == b
        || a == "Object"
        || b == "Object"
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
}
