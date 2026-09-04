//! Owned semantic facts produced by the tolerant Ruby frontend.
//!
//! These types intentionally contain no tree-sitter handles or serialization
//! traits. They are stable, deterministic inputs for rule engines and dataflow
//! passes, including when parsing recovered syntax trees.

use std::collections::{BTreeMap, BTreeSet};

use hoonarqube_ir::{FileMetrics, Range};

/// Lexical scope categories recognized by the Ruby analyzer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScopeKind {
    #[default]
    TopLevel,
    Block,
    Method,
    Class,
    Module,
    Lambda,
}

impl ScopeKind {
    /// Stable lexical spelling used by scope-boundary logic.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TopLevel => "top_level",
            Self::Block => "block",
            Self::Method => "method",
            Self::Class => "class",
            Self::Module => "module",
            Self::Lambda => "lambda",
        }
    }
}

/// Kinds of local bindings Ruby can introduce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BindingKind {
    #[default]
    Local,
    Parameter,
    BlockParameter,
    ForVariable,
    RescueVariable,
}

/// Whether a local fact reads or writes its binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LocalFactKind {
    #[default]
    Read,
    Write,
}

/// One lexical local-variable use or definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFact {
    pub name: String,
    pub kind: LocalFactKind,
    pub binding_kind: BindingKind,
    pub range: Range,
    pub byte_start: usize,
    pub byte_end: usize,
    pub lexical_scope: usize,
    pub binding_scope: Option<usize>,
    pub definition: Option<usize>,
}

impl Default for LocalFact {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: LocalFactKind::Read,
            binding_kind: BindingKind::Local,
            range: Range::file_level(),
            byte_start: 0,
            byte_end: 0,
            lexical_scope: 0,
            binding_scope: None,
            definition: None,
        }
    }
}

/// Symbol information accumulated for one local binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub name: String,
    pub kind: BindingKind,
    pub scope_id: usize,
    pub declaration: Range,
    pub writes: Vec<usize>,
    pub reads: Vec<usize>,
    pub captured: bool,
}

impl Default for Binding {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: BindingKind::Local,
            scope_id: 0,
            declaration: Range::file_level(),
            writes: Vec::new(),
            reads: Vec::new(),
            captured: false,
        }
    }
}

/// One lexical scope and the bindings declared directly within it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub id: usize,
    pub kind: ScopeKind,
    pub parent: Option<usize>,
    pub start: usize,
    pub end: usize,
    pub name: Option<String>,
    pub bindings: BTreeMap<String, Binding>,
}

impl Default for Scope {
    fn default() -> Self {
        Self {
            id: 0,
            kind: ScopeKind::TopLevel,
            parent: None,
            start: 0,
            end: 0,
            name: None,
            bindings: BTreeMap::new(),
        }
    }
}

/// A method invocation, including safe-navigation and attached block facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodCall {
    pub receiver: Option<String>,
    pub method: String,
    pub safe_navigation: bool,
    pub range: Range,
    pub byte_start: usize,
    pub byte_end: usize,
    pub arguments: usize,
    pub block: Option<BlockInfo>,
}

impl Default for MethodCall {
    fn default() -> Self {
        Self {
            receiver: None,
            method: String::new(),
            safe_navigation: false,
            range: Range::file_level(),
            byte_start: 0,
            byte_end: 0,
            arguments: 0,
            block: None,
        }
    }
}

/// Lexical block attached to a method call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    pub range: Range,
    pub byte_start: usize,
    pub byte_end: usize,
    pub parameters: Vec<String>,
    pub scope_id: usize,
}

impl Default for BlockInfo {
    fn default() -> Self {
        Self {
            range: Range::file_level(),
            byte_start: 0,
            byte_end: 0,
            parameters: Vec::new(),
            scope_id: 0,
        }
    }
}

/// Conservative nil-state fact used by guard-sensitive checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NilState {
    Nil,
    NotNil,
    #[default]
    Unknown,
}

/// A branch guard that establishes a nil-state for one variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NilGuard {
    pub variable: String,
    pub state: NilState,
    pub range: Range,
    pub truthy_branch: bool,
}

impl Default for NilGuard {
    fn default() -> Self {
        Self {
            variable: String::new(),
            state: NilState::Unknown,
            range: Range::file_level(),
            truthy_branch: false,
        }
    }
}

/// Node categories in the Ruby control-flow graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CfgNodeKind {
    #[default]
    Entry,
    Statement,
    Condition,
    BlockEnter,
    BlockExit,
    Rescue,
    Ensure,
    Retry,
    Exit,
}

/// One CFG local fact keyed by its resolved lexical binding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScopedLocal {
    pub scope_id: usize,
    pub name: String,
}

/// One control-flow graph node and its explicit predecessor/successor edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgNode {
    pub id: usize,
    pub kind: CfgNodeKind,
    pub range: Range,
    pub byte_start: usize,
    pub byte_end: usize,
    pub reads: Vec<String>,
    pub writes: Vec<String>,
    pub scoped_reads: Vec<ScopedLocal>,
    pub scoped_writes: Vec<ScopedLocal>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
}

impl Default for CfgNode {
    fn default() -> Self {
        Self {
            id: 0,
            kind: CfgNodeKind::Entry,
            range: Range::file_level(),
            byte_start: 0,
            byte_end: 0,
            reads: Vec::new(),
            writes: Vec::new(),
            scoped_reads: Vec::new(),
            scoped_writes: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }
}
impl CfgNode {
    /// Creates an empty CFG node with the supplied identity and source range.
    #[must_use]
    pub fn new(id: usize, kind: CfgNodeKind, range: Range) -> Self {
        Self {
            id,
            kind,
            range,
            ..Self::default()
        }
    }
}

/// Complete control-flow graph for one analyzed body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ControlFlowGraph {
    pub nodes: Vec<CfgNode>,
    pub entry: usize,
    pub exit: usize,
}
impl ControlFlowGraph {
    /// Appends a node and returns its graph-local identity.
    pub fn add(&mut self, mut node: CfgNode) -> usize {
        let id = self.nodes.len();
        node.id = id;
        self.nodes.push(node);
        id
    }

    pub fn link(&mut self, from: usize, to: usize) {
        if from >= self.nodes.len() || to >= self.nodes.len() {
            return;
        }
        if self.nodes[from].successors.contains(&to) {
            return;
        }
        self.nodes[from].successors.push(to);
        if !self.nodes[to].predecessors.contains(&from) {
            self.nodes[to].predecessors.push(from);
        }
    }

    /// Rebuilds predecessor lists from the current successor lists.
    pub fn rebuild_predecessors(&mut self) {
        for node in &mut self.nodes {
            node.predecessors.clear();
        }
        let edges: Vec<(usize, Vec<usize>)> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(from, node)| (from, node.successors.clone()))
            .collect();
        for (from, successors) in edges {
            for to in successors {
                if let Some(node) = self.nodes.get_mut(to)
                    && !node.predecessors.contains(&from)
                {
                    node.predecessors.push(from);
                }
            }
        }
        for node in &mut self.nodes {
            node.predecessors.sort_unstable();
        }
    }
}

/// One named definition associated with a CFG node and binding scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    pub id: usize,
    pub name: String,
    pub scope_id: usize,
    pub node: usize,
    pub range: Range,
}

impl Default for Definition {
    fn default() -> Self {
        Self {
            id: 0,
            name: String::new(),
            scope_id: 0,
            node: 0,
            range: Range::file_level(),
        }
    }
}

/// Fixed-point dataflow sets for reaching definitions, definite initialization,
/// and live locals.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DataflowResults {
    pub reaching_in: Vec<BTreeSet<usize>>,
    pub reaching_out: Vec<BTreeSet<usize>>,
    pub initialized_in: Vec<BTreeSet<ScopedLocal>>,
    pub initialized_out: Vec<BTreeSet<ScopedLocal>>,
    pub live_in: Vec<BTreeSet<ScopedLocal>>,
    pub live_out: Vec<BTreeSet<ScopedLocal>>,
}

/// Ruby-specific size, structure, and complexity metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RubyMetrics {
    pub file: FileMetrics,
    pub methods: usize,
    pub classes: usize,
    pub blocks: usize,
    pub conditionals: usize,
    pub loops: usize,
    pub rescue_clauses: usize,
    pub max_nesting: usize,
    pub cognitive_complexity: usize,
}

impl Default for RubyMetrics {
    fn default() -> Self {
        Self {
            file: FileMetrics {
                lines: 0,
                code_lines: 0,
                comment_lines: 0,
            },
            methods: 0,
            classes: 0,
            blocks: 0,
            conditionals: 0,
            loops: 0,
            rescue_clauses: 0,
            max_nesting: 0,
            cognitive_complexity: 0,
        }
    }
}

/// Complete owned result of tolerant Ruby parsing and semantic indexing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RubyFacts {
    pub source_len: usize,
    pub malformed: bool,
    pub syntax_error_count: usize,
    pub analysis_complete: bool,
    pub scopes: Vec<Scope>,
    pub locals: Vec<LocalFact>,
    pub calls: Vec<MethodCall>,
    pub nil_guards: Vec<NilGuard>,
    pub cfg: ControlFlowGraph,
    pub definitions: Vec<Definition>,
    pub dataflow: DataflowResults,
    pub metrics: RubyMetrics,
}
