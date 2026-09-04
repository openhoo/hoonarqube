//! AST lowering and conservative semantic facts for Ruby.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use tree_sitter::{Node, Parser, Tree};

use crate::context::{
    Binding, BindingKind, BlockInfo, CfgNode, CfgNodeKind, ControlFlowGraph, DataflowResults,
    Definition, LocalFact, LocalFactKind, MethodCall, NilGuard, NilState, RubyFacts, RubyMetrics,
    Scope, ScopeKind, ScopedLocal,
};
use crate::support::{SourceMap, lexical_metrics, node_text, walk};

/// Parse and lower Ruby into owned syntax and semantic facts.
#[must_use]
pub fn analyze_facts(source: &str) -> RubyFacts {
    let map = SourceMap::new(source);
    let Some(tree) = parse(source) else {
        return empty_facts(source, &map, true, 1);
    };
    let root = tree.root_node();
    let malformed = root.has_error();
    let syntax_error_count = count_errors(root);
    let mut facts = empty_facts(source, &map, malformed, syntax_error_count);
    let mut scopes_by_start = BTreeMap::new();
    collect_scopes(root, 0, &map, &mut facts.scopes, &mut scopes_by_start);
    collect_locals(root, 0, &map, &scopes_by_start, &mut facts);
    collect_calls_and_guards(root, 0, &map, &scopes_by_start, &mut facts);
    let (cfg, cfg_complete) = build_cfg(root, &map, &facts);
    facts.cfg = cfg;
    facts.definitions = definitions(&facts);
    attach_definition_ids(&mut facts);
    let (dataflow, dataflow_complete) = solve_dataflow(&facts.cfg, &facts.definitions);
    facts.dataflow = dataflow;
    facts.analysis_complete = cfg_complete && dataflow_complete;
    facts.metrics = collect_ruby_metrics(source, root, &facts.metrics.file);
    facts
}

fn parse(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_ruby::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

fn empty_facts(source: &str, map: &SourceMap, malformed: bool, errors: usize) -> RubyFacts {
    let file = lexical_metrics(source);
    let mut cfg = ControlFlowGraph::default();
    let entry = cfg.add(CfgNode::new(0, CfgNodeKind::Entry, map.range(0, 0)));
    let exit = cfg.add(CfgNode::new(
        1,
        CfgNodeKind::Exit,
        map.range(source.len(), source.len()),
    ));
    cfg.entry = entry;
    cfg.exit = exit;
    RubyFacts {
        source_len: source.len(),
        malformed,
        syntax_error_count: errors,
        analysis_complete: false,
        scopes: vec![Scope {
            id: 0,
            kind: ScopeKind::TopLevel,
            parent: None,
            start: 0,
            end: source.len(),
            name: None,
            bindings: BTreeMap::new(),
        }],
        locals: Vec::new(),
        calls: Vec::new(),
        nil_guards: Vec::new(),
        cfg,
        definitions: Vec::new(),
        dataflow: DataflowResults::default(),
        metrics: RubyMetrics {
            file,
            ..RubyMetrics::default()
        },
    }
}

fn count_errors(root: Node<'_>) -> usize {
    let mut count = 0;
    walk(root, &mut |node: Node<'_>| {
        if node.is_error() || node.is_missing() {
            count += 1;
        }
    });
    count
}

fn scope_kind(node: Node<'_>) -> Option<ScopeKind> {
    if matches!(node.kind(), "block" | "do_block")
        && node
            .parent()
            .is_some_and(|parent| parent.kind() == "lambda")
    {
        return None;
    }
    match node.kind() {
        "block" | "do_block" => Some(ScopeKind::Block),
        "lambda" => Some(ScopeKind::Lambda),
        "method" | "singleton_method" => Some(ScopeKind::Method),
        "class" => Some(ScopeKind::Class),
        "module" => Some(ScopeKind::Module),
        _ => None,
    }
}

fn collect_scopes(
    node: Node<'_>,
    current: usize,
    map: &SourceMap,
    scopes: &mut Vec<Scope>,
    by_start: &mut BTreeMap<usize, usize>,
) {
    let mut pending = vec![(node, current)];
    while let Some((node, current)) = pending.pop() {
        let mut owner = current;
        if (node.start_byte() != 0 || node.kind() != "program")
            && let Some(kind) = scope_kind(node)
        {
            let name = node
                .child_by_field_name("name")
                .map(|n| node_text(n, map.source()).to_string());
            owner = scopes.len();
            scopes.push(Scope {
                id: owner,
                kind,
                parent: Some(current),
                start: node.start_byte(),
                end: node.end_byte(),
                name,
                bindings: BTreeMap::new(),
            });
            by_start.insert(node.start_byte(), owner);
        }

        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            pending.push((child, owner));
        }
    }
}

fn owner_for(node: Node<'_>, current: usize, by_start: &BTreeMap<usize, usize>) -> usize {
    by_start.get(&node.start_byte()).copied().unwrap_or(current)
}

fn is_scope_boundary(kind: &str) -> bool {
    matches!(kind, "method" | "class" | "module")
}

fn collect_locals(
    root: Node<'_>,
    current: usize,
    map: &SourceMap,
    by_start: &BTreeMap<usize, usize>,
    facts: &mut RubyFacts,
) {
    visit_locals(root, current, map, by_start, facts);
    resolve_bindings(facts);
}

fn visit_locals(
    node: Node<'_>,
    current: usize,
    map: &SourceMap,
    by_start: &BTreeMap<usize, usize>,
    facts: &mut RubyFacts,
) {
    let mut pending = vec![(node, current)];
    while let Some((node, current)) = pending.pop() {
        let scope = owner_for(node, current, by_start);
        if handle_local_node(node, scope, map, by_start, facts, &mut pending) {
            continue;
        }
        schedule_local_children(node, scope, &mut pending);
    }
}

fn handle_local_node<'tree>(
    node: Node<'tree>,
    scope: usize,
    map: &SourceMap,
    by_start: &BTreeMap<usize, usize>,
    facts: &mut RubyFacts,
    pending: &mut Vec<(Node<'tree>, usize)>,
) -> bool {
    match node.kind() {
        "method" | "singleton_method" | "lambda" => {
            collect_node_parameters(node, scope, BindingKind::Parameter, map, by_start, facts);
            schedule_node_body(node, scope, pending);
            true
        }
        "block" | "do_block" => {
            collect_node_parameters(
                node,
                scope,
                BindingKind::BlockParameter,
                map,
                by_start,
                facts,
            );
            false
        }
        "class" | "module" => {
            schedule_node_body(node, scope, pending);
            true
        }
        "assignment" => {
            schedule_assignment(node, scope, map, facts, pending);
            true
        }
        "operator_assignment" => {
            schedule_operator_assignment(node, scope, map, facts, pending);
            true
        }
        "for" => {
            if let Some(pattern) = node.child_by_field_name("pattern") {
                collect_lhs(pattern, scope, map, facts, BindingKind::ForVariable);
            }
            false
        }
        "match_pattern" | "test_pattern" => {
            if let Some(value) = node.child_by_field_name("value") {
                collect_expression_reads(value, scope, map, facts);
            }
            if let Some(pattern) = node.child_by_field_name("pattern") {
                collect_pattern_lhs(pattern, scope, map, facts);
            }
            true
        }
        "in_clause" => {
            if let Some(pattern) = node.child_by_field_name("pattern") {
                collect_pattern_lhs(pattern, scope, map, facts);
            }
            if let Some(guard) = node.child_by_field_name("guard") {
                collect_expression_reads(guard, scope, map, facts);
            }
            if let Some(body) = node.child_by_field_name("body") {
                pending.push((body, scope));
            }
            true
        }
        "rescue" => {
            if let Some(variable) = node.child_by_field_name("variable") {
                collect_lhs(variable, scope, map, facts, BindingKind::RescueVariable);
            }
            false
        }
        "identifier" => {
            add_local(facts, map, node, LocalFactKind::Read, scope);
            true
        }
        _ => false,
    }
}

fn collect_pattern_lhs(node: Node<'_>, scope: usize, map: &SourceMap, facts: &mut RubyFacts) {
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        match node.kind() {
            "identifier" => collect_pattern_identifier(node, scope, map, facts),
            "splat_parameter" | "hash_splat_parameter" => {
                collect_pattern_splat(node, scope, map, facts, &mut pending);
            }
            "variable_reference_pattern" => {
                collect_pattern_reference(node, "name", scope, map, facts);
            }
            "expression_reference_pattern" => {
                collect_pattern_reference(node, "value", scope, map, facts);
            }
            "as_pattern" => schedule_as_pattern(node, scope, map, facts, &mut pending),
            "keyword_pattern" => schedule_keyword_pattern(node, scope, map, facts, &mut pending),
            "constant" | "scope_resolution" | "hash_key_symbol" => {}
            _ => schedule_pattern_children(node, &mut pending),
        }
    }
}

fn collect_pattern_identifier(
    node: Node<'_>,
    scope: usize,
    map: &SourceMap,
    facts: &mut RubyFacts,
) {
    add_local_with_kind(
        facts,
        map,
        node,
        LocalFactKind::Write,
        scope,
        BindingKind::Local,
    );
}

fn collect_pattern_splat<'tree>(
    node: Node<'tree>,
    scope: usize,
    map: &SourceMap,
    facts: &mut RubyFacts,
    pending: &mut Vec<Node<'tree>>,
) {
    if let Some(name) = node.child_by_field_name("name") {
        collect_pattern_identifier(name, scope, map, facts);
    } else {
        schedule_pattern_children(node, pending);
    }
}

fn collect_pattern_reference(
    node: Node<'_>,
    field: &str,
    scope: usize,
    map: &SourceMap,
    facts: &mut RubyFacts,
) {
    if let Some(value) = node.child_by_field_name(field) {
        collect_expression_reads(value, scope, map, facts);
    }
}

fn schedule_as_pattern<'tree>(
    node: Node<'tree>,
    scope: usize,
    map: &SourceMap,
    facts: &mut RubyFacts,
    pending: &mut Vec<Node<'tree>>,
) {
    if let Some(value) = node.child_by_field_name("value") {
        pending.push(value);
    }
    if let Some(name) = node.child_by_field_name("name") {
        collect_pattern_identifier(name, scope, map, facts);
    }
}

fn schedule_keyword_pattern<'tree>(
    node: Node<'tree>,
    scope: usize,
    map: &SourceMap,
    facts: &mut RubyFacts,
    pending: &mut Vec<Node<'tree>>,
) {
    if let Some(value) = node.child_by_field_name("value") {
        pending.push(value);
    } else if let Some(key) = node.child_by_field_name("key") {
        let name = node_text(key, map.source()).trim();
        let is_local_name = name
            .as_bytes()
            .first()
            .is_some_and(|byte| *byte == b'_' || byte.is_ascii_lowercase());
        if is_local_name && is_identifier(name) {
            collect_pattern_identifier(key, scope, map, facts);
        }
    }
}

fn schedule_pattern_children<'tree>(node: Node<'tree>, pending: &mut Vec<Node<'tree>>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    pending.extend(children.into_iter().rev());
}

fn collect_node_parameters(
    node: Node<'_>,
    scope: usize,
    kind: BindingKind,
    map: &SourceMap,
    by_start: &BTreeMap<usize, usize>,
    facts: &mut RubyFacts,
) {
    if let Some(parameters) = node.child_by_field_name("parameters") {
        collect_parameter_writes(parameters, scope, kind, map, by_start, facts);
    }
}

fn schedule_node_body<'tree>(
    node: Node<'tree>,
    scope: usize,
    pending: &mut Vec<(Node<'tree>, usize)>,
) {
    if let Some(body) = node.child_by_field_name("body") {
        pending.push((body, scope));
    }
}

fn schedule_assignment<'tree>(
    node: Node<'tree>,
    scope: usize,
    map: &SourceMap,
    facts: &mut RubyFacts,
    pending: &mut Vec<(Node<'tree>, usize)>,
) {
    if let Some(right) = node.child_by_field_name("right") {
        pending.push((right, scope));
    }
    if let Some(left) = node.child_by_field_name("left") {
        collect_lhs(left, scope, map, facts, BindingKind::Local);
    }
}

fn schedule_operator_assignment<'tree>(
    node: Node<'tree>,
    scope: usize,
    map: &SourceMap,
    facts: &mut RubyFacts,
    pending: &mut Vec<(Node<'tree>, usize)>,
) {
    if let Some(right) = node.child_by_field_name("right") {
        pending.push((right, scope));
    }
    if let Some(left) = node.child_by_field_name("left") {
        collect_lhs(left, scope, map, facts, BindingKind::Local);
        pending.push((left, scope));
    }
}

fn schedule_local_children<'tree>(
    node: Node<'tree>,
    scope: usize,
    pending: &mut Vec<(Node<'tree>, usize)>,
) {
    let parameters = node.child_by_field_name("parameters");
    let excluded_binding = if node.kind() == "for" {
        node.child_by_field_name("pattern")
    } else {
        node.child_by_field_name("variable")
    };
    let method = if node.kind() == "call" {
        node.child_by_field_name("method")
    } else {
        None
    };
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    for child in children.into_iter().rev() {
        if local_child_is_excluded(child, parameters, excluded_binding, method) {
            continue;
        }
        pending.push((child, scope));
    }
}

fn local_child_is_excluded<'tree>(
    child: Node<'tree>,
    parameters: Option<Node<'tree>>,
    excluded_binding: Option<Node<'tree>>,
    method: Option<Node<'tree>>,
) -> bool {
    parameters.is_some_and(|value| value.id() == child.id())
        || excluded_binding.is_some_and(|value| value.id() == child.id())
        || method.is_some_and(|value| value.id() == child.id())
}

fn collect_parameter_writes(
    parameters: Node<'_>,
    scope: usize,
    kind: BindingKind,
    map: &SourceMap,
    by_start: &BTreeMap<usize, usize>,
    facts: &mut RubyFacts,
) {
    let (binding_nodes, default_values) = parameter_binding_nodes(parameters);
    let mut seen = BTreeSet::new();
    for node in binding_nodes {
        if seen.insert((node.start_byte(), node.end_byte())) {
            add_local_with_kind(facts, map, node, LocalFactKind::Write, scope, kind);
        }
    }
    for value in default_values {
        visit_locals(value, scope, map, by_start, facts);
    }
}

fn parameter_binding_nodes(parameters: Node<'_>) -> (Vec<Node<'_>>, Vec<Node<'_>>) {
    let mut bindings = Vec::new();
    let mut defaults = Vec::new();
    let mut pending = vec![parameters];
    while let Some(node) = pending.pop() {
        match node.kind() {
            "optional_parameter" | "keyword_parameter" => {
                if let Some(name) = node.child_by_field_name("name") {
                    bindings.push(name);
                }
                if let Some(value) = node.child_by_field_name("value") {
                    defaults.push(value);
                }
                continue;
            }
            "splat_parameter" | "hash_splat_parameter" | "block_parameter" => {
                if let Some(name) = node.child_by_field_name("name") {
                    bindings.push(name);
                }
                continue;
            }
            "identifier" => {
                bindings.push(node);
                continue;
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            pending.push(child);
        }
    }
    (bindings, defaults)
}

fn collect_lhs(
    node: Node<'_>,
    scope: usize,
    map: &SourceMap,
    facts: &mut RubyFacts,
    kind: BindingKind,
) {
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        if node.kind() == "call" {
            if let Some(receiver) = node.child_by_field_name("receiver") {
                collect_expression_reads(receiver, scope, map, facts);
            }
            if let Some(arguments) = node.child_by_field_name("arguments") {
                collect_expression_reads(arguments, scope, map, facts);
            }
            continue;
        }
        if node.kind() == "identifier" {
            add_local_with_kind(facts, map, node, LocalFactKind::Write, scope, kind);
            continue;
        }
        if matches!(
            node.kind(),
            "instance_variable" | "class_variable" | "global_variable"
        ) {
            continue;
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            pending.push(child);
        }
    }
}

fn collect_expression_reads(node: Node<'_>, scope: usize, map: &SourceMap, facts: &mut RubyFacts) {
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        if node.kind() == "identifier" {
            add_local(facts, map, node, LocalFactKind::Read, scope);
            continue;
        }
        let method = if node.kind() == "call" {
            node.child_by_field_name("method")
        } else {
            None
        };
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            if method.is_some_and(|value| value.id() == child.id()) {
                continue;
            }
            pending.push(child);
        }
    }
}

fn add_local(
    facts: &mut RubyFacts,
    map: &SourceMap,
    node: Node<'_>,
    kind: LocalFactKind,
    scope: usize,
) {
    add_local_with_kind(facts, map, node, kind, scope, BindingKind::Local);
}

fn add_local_with_kind(
    facts: &mut RubyFacts,
    map: &SourceMap,
    node: Node<'_>,
    kind: LocalFactKind,
    scope: usize,
    binding_kind: BindingKind,
) {
    let name = node_text(node, map.source()).to_string();
    if name.is_empty() || name == "_" {
        return;
    }
    let range = map.range(node.start_byte(), node.end_byte());
    facts.locals.push(LocalFact {
        name,
        kind,
        binding_kind,
        range,
        byte_start: node.start_byte(),
        byte_end: node.end_byte(),
        lexical_scope: scope,
        binding_scope: None,
        definition: None,
    });
}

fn resolve_bindings(facts: &mut RubyFacts) {
    let declarations = collect_declarations(facts);
    let targets = resolve_write_targets(facts, &declarations);
    let binding_names = collect_binding_names(facts, &targets);
    for (index, local) in facts.locals.clone().into_iter().enumerate() {
        let binding_scope =
            binding_scope_for_local(&local, targets[index], &binding_names, &facts.scopes);
        record_binding(facts, index, &local, binding_scope);
    }
    sort_bindings(facts);
}

fn collect_declarations(facts: &RubyFacts) -> Vec<BTreeMap<String, BindingKind>> {
    let mut declarations = vec![BTreeMap::<String, BindingKind>::new(); facts.scopes.len()];
    for local in facts
        .locals
        .iter()
        .filter(|local| local.kind == LocalFactKind::Write)
    {
        declarations[local.lexical_scope]
            .entry(local.name.clone())
            .or_insert(local.binding_kind);
    }
    declarations
}

fn resolve_write_targets(
    facts: &RubyFacts,
    declarations: &[BTreeMap<String, BindingKind>],
) -> Vec<Option<usize>> {
    let mut targets = vec![None; facts.locals.len()];
    for (index, local) in facts.locals.iter().enumerate() {
        if local.kind == LocalFactKind::Write {
            targets[index] = Some(write_target_for(local, facts, declarations));
        }
    }
    targets
}

fn write_target_for(
    local: &LocalFact,
    facts: &RubyFacts,
    declarations: &[BTreeMap<String, BindingKind>],
) -> usize {
    let target = local.lexical_scope;
    if local.binding_kind == BindingKind::BlockParameter
        || !matches!(
            facts.scopes[target].kind,
            ScopeKind::Block | ScopeKind::Lambda
        )
    {
        return target;
    }
    let mut parent = facts.scopes[target].parent;
    while let Some(parent_id) = parent {
        if declarations[parent_id].contains_key(&local.name) {
            return parent_id;
        }
        if is_scope_boundary(facts.scopes[parent_id].kind.as_str()) {
            break;
        }
        parent = facts.scopes[parent_id].parent;
    }
    target
}

fn collect_binding_names(facts: &RubyFacts, targets: &[Option<usize>]) -> Vec<BTreeSet<String>> {
    let mut binding_names = vec![BTreeSet::new(); facts.scopes.len()];
    for (index, target) in targets.iter().enumerate() {
        if let Some(scope_id) = target {
            binding_names[*scope_id].insert(facts.locals[index].name.clone());
        }
    }
    binding_names
}

fn binding_scope_for_local(
    local: &LocalFact,
    target: Option<usize>,
    binding_names: &[BTreeSet<String>],
    scopes: &[Scope],
) -> Option<usize> {
    target.or_else(|| inherited_binding_scope(local, binding_names, scopes))
}

fn inherited_binding_scope(
    local: &LocalFact,
    binding_names: &[BTreeSet<String>],
    scopes: &[Scope],
) -> Option<usize> {
    let mut scope = local.lexical_scope;
    loop {
        if binding_names[scope].contains(&local.name) {
            return Some(scope);
        }
        let parent = scopes[scope].parent;
        if parent.is_none() || is_scope_boundary(scopes[scope].kind.as_str()) {
            return None;
        }
        scope = parent.expect("checked above");
    }
}

fn record_binding(
    facts: &mut RubyFacts,
    index: usize,
    local: &LocalFact,
    binding_scope: Option<usize>,
) {
    facts.locals[index].binding_scope = binding_scope;
    let Some(scope_id) = binding_scope else {
        return;
    };
    let binding_kind = if local.kind == LocalFactKind::Write {
        local.binding_kind
    } else {
        BindingKind::Local
    };
    let binding = facts.scopes[scope_id]
        .bindings
        .entry(local.name.clone())
        .or_insert_with(|| Binding {
            name: local.name.clone(),
            kind: binding_kind,
            scope_id,
            declaration: local.range.clone(),
            writes: Vec::new(),
            reads: Vec::new(),
            captured: false,
        });
    if local.kind == LocalFactKind::Write {
        binding.writes.push(index);
        if binding.kind == BindingKind::Local && binding_kind != BindingKind::Local {
            binding.kind = binding_kind;
        }
        if binding.writes.len() == 1 {
            binding.declaration = local.range.clone();
        }
    } else {
        binding.reads.push(index);
    }
    if scope_id != local.lexical_scope {
        binding.captured = true;
    }
}

fn sort_bindings(facts: &mut RubyFacts) {
    for scope in &mut facts.scopes {
        for binding in scope.bindings.values_mut() {
            binding.writes.sort_unstable();
            binding.reads.sort_unstable();
        }
    }
}

fn collect_calls_and_guards(
    root: Node<'_>,
    current: usize,
    map: &SourceMap,
    by_start: &BTreeMap<usize, usize>,
    facts: &mut RubyFacts,
) {
    walk(root, &mut |node: Node<'_>| {
        let scope = owner_for(node, current, by_start);
        if node.kind() == "call" {
            let method = node.child_by_field_name("method").map_or_else(
                || method_from_text(node_text(node, map.source())),
                |n| node_text(n, map.source()).to_string(),
            );

            if !method.is_empty() {
                let receiver = node
                    .child_by_field_name("receiver")
                    .map(|n| node_text(n, map.source()).trim().to_string());
                let operator = node
                    .child_by_field_name("operator")
                    .map(|n| node_text(n, map.source()));
                let block = node
                    .child_by_field_name("block")
                    .map(|block_node| BlockInfo {
                        range: map.range(block_node.start_byte(), block_node.end_byte()),
                        byte_start: block_node.start_byte(),
                        byte_end: block_node.end_byte(),
                        parameters: block_node
                            .child_by_field_name("parameters")
                            .map(|p| parameter_names(p, map.source()))
                            .unwrap_or_default(),
                        scope_id: owner_for(block_node, scope, by_start),
                    });
                facts.calls.push(MethodCall {
                    receiver,
                    method,
                    safe_navigation: operator == Some("&."),

                    range: map.range(node.start_byte(), node.end_byte()),
                    byte_start: node.start_byte(),
                    byte_end: node.end_byte(),
                    arguments: node
                        .child_by_field_name("arguments")
                        .map_or(0, |a| a.named_child_count()),
                    block,
                });
            }
        }
        if matches!(
            node.kind(),
            "if" | "unless"
                | "while"
                | "until"
                | "if_modifier"
                | "unless_modifier"
                | "while_modifier"
                | "until_modifier"
        ) && let Some(condition) = node.child_by_field_name("condition")
        {
            facts.nil_guards.extend(nil_guards(condition, map));
        }
    });
    facts
        .calls
        .sort_by_key(|call| (call.byte_start, call.byte_end, call.method.clone()));
    facts.nil_guards.sort_by_key(|guard| {
        (
            guard.range.start.line,
            guard.range.start.column,
            guard.variable.clone(),
        )
    });
}

fn parameter_names(node: Node<'_>, source: &str) -> Vec<String> {
    let (bindings, _) = parameter_binding_nodes(node);
    let mut names = BTreeSet::new();
    for binding in bindings {
        names.insert(node_text(binding, source).to_string());
    }
    names.into_iter().collect()
}

fn method_from_text(text: &str) -> String {
    text.split(|c: char| c.is_whitespace() || c == '(' || c == '.' || c == '&')
        .next_back()
        .unwrap_or_default()
        .trim_end_matches('!')
        .to_string()
}

fn nil_guards(condition: Node<'_>, map: &SourceMap) -> Vec<NilGuard> {
    let text = node_text(condition, map.source()).trim();
    let range = map.range(condition.start_byte(), condition.end_byte());
    let (truthy_branch, expression) = parse_guard_branch(text);
    match nil_guard_candidate(expression, truthy_branch) {
        Some((variable, state)) => vec![NilGuard {
            variable: variable.to_string(),
            state,
            range,
            truthy_branch,
        }],
        None => Vec::new(),
    }
}

fn parse_guard_branch(text: &str) -> (bool, &str) {
    match text.strip_prefix('!') {
        Some(rest) => (false, rest.trim()),
        None => (true, text),
    }
}

fn nil_guard_candidate(expression: &str, truthy_branch: bool) -> Option<(&str, NilState)> {
    if let Some(variable) = expression.strip_suffix(".nil?") {
        let variable = variable.trim();
        let state = if truthy_branch {
            NilState::Nil
        } else {
            NilState::NotNil
        };
        return is_identifier(variable).then_some((variable, state));
    }
    if let Some((left, right, equal)) = comparison(expression) {
        let variable = if right == "nil" { left } else { right };
        let state = if equal == "==" {
            NilState::Nil
        } else {
            NilState::NotNil
        };
        return is_identifier(variable).then_some((variable, state));
    }
    is_identifier(expression).then_some((expression, NilState::NotNil))
}

fn comparison(text: &str) -> Option<(&str, &str, &str)> {
    for operator in ["!=", "=="] {
        if let Some((left, right)) = text.split_once(operator)
            && (left.trim() == "nil" || right.trim() == "nil")
        {
            return Some((left.trim(), right.trim(), operator));
        }
    }
    None
}

fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphanumeric() && (i > 0 || !b.is_ascii_digit()))
}

#[derive(Default)]
struct Flow {
    entry: Option<usize>,
    exits: Vec<usize>,
    breaks: Vec<usize>,
    continues: Vec<usize>,
    retries: Vec<usize>,
}

const MAX_CFG_WORK_ITEMS: usize = 1_000_000;

fn build_cfg(root: Node<'_>, map: &SourceMap, facts: &RubyFacts) -> (ControlFlowGraph, bool) {
    let mut cfg = ControlFlowGraph::default();
    let entry = cfg.add(CfgNode::new(0, CfgNodeKind::Entry, map.range(0, 0)));
    cfg.entry = entry;
    let (flow, complete) = build_sequence(
        sequence_children(root),
        map,
        facts,
        &mut cfg,
        None,
        Vec::new(),
    );
    if !complete {
        let mut fallback = ControlFlowGraph::default();
        let entry = fallback.add(CfgNode::new(0, CfgNodeKind::Entry, map.range(0, 0)));
        let exit = fallback.add(CfgNode::new(
            1,
            CfgNodeKind::Exit,
            map.range(map.source().len(), map.source().len()),
        ));
        fallback.entry = entry;
        fallback.exit = exit;
        fallback.link(entry, exit);
        fallback.rebuild_predecessors();
        return (fallback, false);
    }
    let exit = cfg.add(CfgNode::new(
        cfg.nodes.len(),
        CfgNodeKind::Exit,
        map.range(map.source().len(), map.source().len()),
    ));
    cfg.exit = exit;
    if let Some(start) = flow.entry {
        cfg.link(entry, start);
    } else {
        cfg.link(entry, exit);
    }
    for node in flow.exits {
        cfg.link(node, exit);
    }
    cfg.rebuild_predecessors();
    (cfg, true)
}

fn sequence_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

struct BeginAfterHandlerTask<'tree> {
    handlers: Vec<Node<'tree>>,
    ensures: Vec<Node<'tree>>,
    handler_index: usize,
    protected_start: usize,
    protected_end: usize,
    protected_entry: Option<usize>,
    main: Flow,
    path: Vec<usize>,
}

enum CfgBuildTask<'tree> {
    Sequence {
        nodes: Vec<Node<'tree>>,
        next: usize,
        flow: Flow,
        loop_header: Option<usize>,
        path: Vec<usize>,
    },
    Statement {
        node: Node<'tree>,
        loop_header: Option<usize>,
        path: Vec<usize>,
    },
    BranchAfterThen {
        condition: usize,
        alternative: Vec<Node<'tree>>,
        loop_header: Option<usize>,
        path: Vec<usize>,
    },
    BranchAfterElse {
        condition: usize,
        then_flow: Flow,
    },
    LoopAfterBody {
        condition: usize,
    },
    BlockAfterBody {
        node: Node<'tree>,
        enter: usize,
    },
    BeginAfterMain {
        handlers: Vec<Node<'tree>>,
        ensures: Vec<Node<'tree>>,
        protected_start: usize,
        path: Vec<usize>,
    },
    BeginAfterHandler {
        data: BeginAfterHandlerTask<'tree>,
    },
    BeginAfterEnsure {
        ensures: Vec<Node<'tree>>,
        ensure_index: usize,
        main: Flow,
        path: Vec<usize>,
    },
    CallAfterBlock {
        call: Flow,
    },
    SpecialAfterBody {
        special: Flow,
    },
}

struct CfgProcessor<'tree, 'ctx> {
    map: &'ctx SourceMap,
    facts: &'ctx RubyFacts,
    cfg: &'ctx mut ControlFlowGraph,
    tasks: &'ctx mut Vec<CfgBuildTask<'tree>>,
    result: &'ctx mut Option<Flow>,
}

impl<'tree, 'ctx> CfgProcessor<'tree, 'ctx> {
    fn new(
        map: &'ctx SourceMap,
        facts: &'ctx RubyFacts,
        cfg: &'ctx mut ControlFlowGraph,
        tasks: &'ctx mut Vec<CfgBuildTask<'tree>>,
        result: &'ctx mut Option<Flow>,
    ) -> Self {
        Self {
            map,
            facts,
            cfg,
            tasks,
            result,
        }
    }

    fn add_node(&mut self, node: Node<'tree>, kind: CfgNodeKind) -> usize {
        let index = self.cfg.nodes.len();
        self.cfg
            .add(node_from_facts(node, kind, self.map, self.facts, index))
    }

    fn make_simple_flow(&mut self, node: Node<'tree>, kind: CfgNodeKind) -> Flow {
        let id = self.add_node(node, kind);
        Flow {
            entry: Some(id),
            exits: vec![id],
            ..Flow::default()
        }
    }
}

fn append_sequence_flow(cfg: &mut ControlFlowGraph, result: &mut Flow, current: Flow) {
    let current_entry = current.entry;
    for previous in result.exits.drain(..) {
        if let Some(next) = current_entry {
            cfg.link(previous, next);
        }
    }
    if result.entry.is_none() {
        result.entry = current_entry;
    }
    result.exits = current.exits;
    result.breaks.extend(current.breaks);
    result.continues.extend(current.continues);
    result.retries.extend(current.retries);
}

fn build_sequence(
    nodes: Vec<Node<'_>>,
    map: &SourceMap,
    facts: &RubyFacts,
    cfg: &mut ControlFlowGraph,
    loop_header: Option<usize>,
    path: Vec<usize>,
) -> (Flow, bool) {
    let mut tasks = vec![CfgBuildTask::Sequence {
        nodes,
        next: 0,
        flow: Flow::default(),
        loop_header,
        path,
    }];
    let mut result = None;
    let mut work_items = 0;

    while let Some(task) = tasks.pop() {
        work_items += 1;
        if work_items > MAX_CFG_WORK_ITEMS {
            return (Flow::default(), false);
        }
        let mut processor = CfgProcessor::new(map, facts, cfg, &mut tasks, &mut result);
        process_cfg_task(task, &mut processor);
    }
    (result.unwrap_or_default(), true)
}

fn process_cfg_task<'tree>(task: CfgBuildTask<'tree>, processor: &mut CfgProcessor<'tree, '_>) {
    match task {
        CfgBuildTask::Sequence {
            nodes,
            next,
            flow,
            loop_header,
            path,
        } => process_cfg_sequence(nodes, next, flow, loop_header, path, processor),
        CfgBuildTask::Statement {
            node,
            loop_header,
            path,
        } => process_cfg_statement(node, loop_header, path, processor),
        CfgBuildTask::BranchAfterThen {
            condition,
            alternative,
            loop_header,
            path,
        } => {
            process_cfg_branch_after_then(condition, alternative, loop_header, path, processor);
        }
        CfgBuildTask::BranchAfterElse {
            condition,
            then_flow,
        } => process_cfg_branch_after_else(condition, then_flow, processor),
        CfgBuildTask::LoopAfterBody { condition } => {
            process_cfg_loop_after_body(condition, processor);
        }
        CfgBuildTask::BlockAfterBody { node, enter } => {
            process_cfg_block_after_body(node, enter, processor);
        }
        CfgBuildTask::BeginAfterMain {
            handlers,
            ensures,
            protected_start,
            path,
        } => process_cfg_begin_after_main(handlers, ensures, protected_start, path, processor),
        CfgBuildTask::BeginAfterHandler { data } => {
            process_cfg_begin_after_handler(data, processor);
        }
        CfgBuildTask::BeginAfterEnsure {
            ensures,
            ensure_index,
            main,
            path,
        } => process_cfg_begin_after_ensure(ensures, ensure_index, main, path, processor),
        CfgBuildTask::CallAfterBlock { call } => {
            process_cfg_call_after_block(call, processor);
        }
        CfgBuildTask::SpecialAfterBody { special } => {
            process_cfg_special_after_body(special, processor);
        }
    }
}

fn process_cfg_statement<'tree>(
    node: Node<'tree>,
    loop_header: Option<usize>,
    path: Vec<usize>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    if path.contains(&node.id()) {
        *processor.result = Some(Flow::default());
        return;
    }
    let mut child_path = path;
    child_path.push(node.id());
    match node.kind() {
        "if" | "unless" | "conditional" | "if_modifier" | "unless_modifier" => {
            process_cfg_branch_statement(node, loop_header, child_path, processor);
        }
        "while" | "until" | "for" | "while_modifier" | "until_modifier" => {
            process_cfg_loop_statement(node, child_path, processor);
        }
        "begin" => process_cfg_begin_statement(node, loop_header, child_path, processor),
        "block" | "do_block" => {
            process_cfg_block_statement(node, loop_header, child_path, processor);
        }
        "method" | "singleton_method" | "class" | "module" => {
            process_cfg_container_statement(node, loop_header, child_path, processor);
        }
        "call" => process_cfg_call_statement(node, loop_header, child_path, processor),
        "rescue" => process_cfg_special_statement(
            node,
            CfgNodeKind::Rescue,
            loop_header,
            child_path,
            processor,
        ),
        "ensure" => process_cfg_special_statement(
            node,
            CfgNodeKind::Ensure,
            loop_header,
            child_path,
            processor,
        ),
        "retry" | "break" | "next" | "return" | "raise" => {
            process_cfg_terminal_statement(node, processor);
        }
        _ => process_cfg_fallback_statement(node, loop_header, child_path, processor),
    }
}

fn process_cfg_branch_statement<'tree>(
    node: Node<'tree>,
    loop_header: Option<usize>,
    path: Vec<usize>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    let condition = processor.add_node(node, CfgNodeKind::Condition);
    let consequence = node
        .child_by_field_name("consequence")
        .map(sequence_children)
        .unwrap_or_default();
    let alternative = node
        .child_by_field_name("alternative")
        .map(sequence_children)
        .unwrap_or_default();
    processor.tasks.push(CfgBuildTask::BranchAfterThen {
        condition,
        alternative,
        loop_header,
        path: path.clone(),
    });
    processor.tasks.push(CfgBuildTask::Sequence {
        nodes: consequence,
        next: 0,
        flow: Flow::default(),
        loop_header,
        path,
    });
}

fn process_cfg_loop_statement<'tree>(
    node: Node<'tree>,
    path: Vec<usize>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    let condition = processor.add_node(node, CfgNodeKind::Condition);
    let body = node
        .child_by_field_name("body")
        .map(sequence_children)
        .unwrap_or_default();
    processor
        .tasks
        .push(CfgBuildTask::LoopAfterBody { condition });
    processor.tasks.push(CfgBuildTask::Sequence {
        nodes: body,
        next: 0,
        flow: Flow::default(),
        loop_header: Some(condition),
        path,
    });
}

fn process_cfg_begin_statement<'tree>(
    node: Node<'tree>,
    loop_header: Option<usize>,
    path: Vec<usize>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    let mut body = Vec::new();
    let mut handlers = Vec::new();
    let mut ensures = Vec::new();
    for child in sequence_children(node) {
        match child.kind() {
            "rescue" => handlers.push(child),
            "ensure" => ensures.push(child),
            _ => body.push(child),
        }
    }
    let protected_start = processor.cfg.nodes.len();
    processor.tasks.push(CfgBuildTask::BeginAfterMain {
        handlers,
        ensures,
        protected_start,
        path: path.clone(),
    });
    processor.tasks.push(CfgBuildTask::Sequence {
        nodes: body,
        next: 0,
        flow: Flow::default(),
        loop_header,
        path,
    });
}

fn process_cfg_block_statement<'tree>(
    node: Node<'tree>,
    loop_header: Option<usize>,
    path: Vec<usize>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    let enter = processor.add_node(node, CfgNodeKind::BlockEnter);
    let body = node
        .child_by_field_name("body")
        .map(sequence_children)
        .unwrap_or_default();
    processor
        .tasks
        .push(CfgBuildTask::BlockAfterBody { node, enter });
    processor.tasks.push(CfgBuildTask::Sequence {
        nodes: body,
        next: 0,
        flow: Flow::default(),
        loop_header,
        path,
    });
}

fn process_cfg_container_statement<'tree>(
    node: Node<'tree>,
    loop_header: Option<usize>,
    path: Vec<usize>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    if let Some(body) = node.child_by_field_name("body") {
        processor.tasks.push(CfgBuildTask::Sequence {
            nodes: sequence_children(body),
            next: 0,
            flow: Flow::default(),
            loop_header,
            path,
        });
    } else {
        let flow = processor.make_simple_flow(node, CfgNodeKind::Statement);
        *processor.result = Some(flow);
    }
}

fn process_cfg_call_statement<'tree>(
    node: Node<'tree>,
    loop_header: Option<usize>,
    path: Vec<usize>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    if node.child_by_field_name("block").is_some() {
        let call = processor.make_simple_flow(node, CfgNodeKind::Statement);
        let block = node.child_by_field_name("block").expect("checked above");
        processor.tasks.push(CfgBuildTask::CallAfterBlock { call });
        processor.tasks.push(CfgBuildTask::Statement {
            node: block,
            loop_header,
            path,
        });
    } else {
        let flow = processor.make_simple_flow(node, CfgNodeKind::Statement);
        *processor.result = Some(flow);
    }
}

fn process_cfg_special_statement<'tree>(
    node: Node<'tree>,
    kind: CfgNodeKind,
    loop_header: Option<usize>,
    path: Vec<usize>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    let special = processor.make_simple_flow(node, kind);
    let mut body = node
        .child_by_field_name("body")
        .map(sequence_children)
        .unwrap_or_default();
    if body.is_empty() {
        body = sequence_children(node);
    }
    let body: Vec<Node<'tree>> = body
        .into_iter()
        .filter(|child| !matches!(child.kind(), "exception_list" | "variable"))
        .collect();
    if body.is_empty() {
        *processor.result = Some(special);
    } else {
        processor
            .tasks
            .push(CfgBuildTask::SpecialAfterBody { special });
        processor.tasks.push(CfgBuildTask::Sequence {
            nodes: body,
            next: 0,
            flow: Flow::default(),
            loop_header,
            path,
        });
    }
}

fn process_cfg_terminal_statement<'tree>(
    node: Node<'tree>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    let kind = if node.kind() == "retry" {
        CfgNodeKind::Retry
    } else {
        CfgNodeKind::Statement
    };
    let flow = processor.make_simple_flow(node, kind);
    let terminal = match node.kind() {
        "retry" => Flow {
            entry: flow.entry,
            retries: flow.exits,
            ..Flow::default()
        },
        "break" => Flow {
            entry: flow.entry,
            breaks: flow.exits,
            ..Flow::default()
        },
        "next" => Flow {
            entry: flow.entry,
            continues: flow.exits,
            ..Flow::default()
        },
        "return" | "raise" => Flow {
            entry: flow.entry,
            ..Flow::default()
        },
        _ => unreachable!("terminal statement kind is validated by caller"),
    };
    *processor.result = Some(terminal);
}

fn process_cfg_fallback_statement<'tree>(
    node: Node<'tree>,
    loop_header: Option<usize>,
    path: Vec<usize>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    if node.named_child_count() == 0 || is_statement_node(node) {
        let flow = processor.make_simple_flow(node, CfgNodeKind::Statement);
        *processor.result = Some(flow);
    } else {
        processor.tasks.push(CfgBuildTask::Sequence {
            nodes: sequence_children(node),
            next: 0,
            flow: Flow::default(),
            loop_header,
            path,
        });
    }
}

fn process_cfg_branch_after_then<'tree>(
    condition: usize,
    alternative: Vec<Node<'tree>>,
    loop_header: Option<usize>,
    path: Vec<usize>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    let then_flow = processor.result.take().unwrap_or_default();
    processor.tasks.push(CfgBuildTask::BranchAfterElse {
        condition,
        then_flow,
    });
    processor.tasks.push(CfgBuildTask::Sequence {
        nodes: alternative,
        next: 0,
        flow: Flow::default(),
        loop_header,
        path,
    });
}

fn process_cfg_branch_after_else(
    condition: usize,
    then_flow: Flow,
    processor: &mut CfgProcessor<'_, '_>,
) {
    let else_flow = processor.result.take().unwrap_or_default();
    let mut exits = Vec::new();
    if let Some(entry) = then_flow.entry {
        processor.cfg.link(condition, entry);
        exits.extend(then_flow.exits);
    } else {
        exits.push(condition);
    }
    if let Some(entry) = else_flow.entry {
        processor.cfg.link(condition, entry);
        exits.extend(else_flow.exits);
    } else {
        exits.push(condition);
    }
    let mut flow = Flow {
        entry: Some(condition),
        exits,
        ..Flow::default()
    };
    flow.breaks.extend(then_flow.breaks);
    flow.breaks.extend(else_flow.breaks);
    flow.continues.extend(then_flow.continues);
    flow.continues.extend(else_flow.continues);
    flow.retries.extend(then_flow.retries);
    flow.retries.extend(else_flow.retries);
    *processor.result = Some(flow);
}

fn process_cfg_loop_after_body(condition: usize, processor: &mut CfgProcessor<'_, '_>) {
    let body_flow = processor.result.take().unwrap_or_default();
    if let Some(entry) = body_flow.entry {
        processor.cfg.link(condition, entry);
    }
    for exit in body_flow.exits {
        processor.cfg.link(exit, condition);
    }
    for next in body_flow.continues {
        processor.cfg.link(next, condition);
    }
    let mut exits = vec![condition];
    exits.extend(body_flow.breaks);
    *processor.result = Some(Flow {
        entry: Some(condition),
        exits,
        retries: body_flow.retries,
        ..Flow::default()
    });
}

fn process_cfg_block_after_body<'tree>(
    node: Node<'tree>,
    enter: usize,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    let body_flow = processor.result.take().unwrap_or_default();
    let exit = processor.add_node(node, CfgNodeKind::BlockExit);
    if let Some(entry) = body_flow.entry {
        processor.cfg.link(enter, entry);
    } else {
        processor.cfg.link(enter, exit);
    }
    for item in body_flow.exits {
        processor.cfg.link(item, exit);
    }
    *processor.result = Some(Flow {
        entry: Some(enter),
        exits: vec![exit],
        breaks: body_flow.breaks,
        continues: body_flow.continues,
        retries: body_flow.retries,
    });
}

fn process_cfg_begin_after_main<'tree>(
    handlers: Vec<Node<'tree>>,
    ensures: Vec<Node<'tree>>,
    protected_start: usize,
    path: Vec<usize>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    let main = processor.result.take().unwrap_or_default();
    let protected_end = processor.cfg.nodes.len();
    let protected_entry = main.entry;
    if let Some(handler) = handlers.first().copied() {
        processor.tasks.push(CfgBuildTask::BeginAfterHandler {
            data: BeginAfterHandlerTask {
                handlers,
                ensures,
                handler_index: 1,
                protected_start,
                protected_end,
                protected_entry,
                main,
                path: path.clone(),
            },
        });
        processor.tasks.push(CfgBuildTask::Statement {
            node: handler,
            loop_header: None,
            path,
        });
    } else {
        process_cfg_finish_begin(ensures, main, protected_entry, path, processor);
    }
}

fn process_cfg_finish_begin<'tree>(
    ensures: Vec<Node<'tree>>,
    mut main: Flow,
    protected_entry: Option<usize>,
    path: Vec<usize>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    for retry in main.retries.drain(..) {
        if let Some(entry) = protected_entry {
            processor.cfg.link(retry, entry);
        }
    }
    if let Some(ensure) = ensures.first().copied() {
        processor.tasks.push(CfgBuildTask::BeginAfterEnsure {
            ensures,
            ensure_index: 1,
            main,
            path: path.clone(),
        });
        processor.tasks.push(CfgBuildTask::Statement {
            node: ensure,
            loop_header: None,
            path,
        });
    } else {
        *processor.result = Some(main);
    }
}

fn process_cfg_begin_after_handler<'tree>(
    data: BeginAfterHandlerTask<'tree>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    let BeginAfterHandlerTask {
        handlers,
        ensures,
        handler_index,
        protected_start,
        protected_end,
        protected_entry,
        mut main,
        path,
    } = data;
    let rescue = processor.result.take().unwrap_or_default();
    if let Some(entry) = rescue.entry {
        for protected in protected_start..protected_end {
            processor.cfg.link(protected, entry);
        }
        main.exits.extend(rescue.exits);
        main.breaks.extend(rescue.breaks);
        main.continues.extend(rescue.continues);
        main.retries.extend(rescue.retries);
    }
    if let Some(handler) = handlers.get(handler_index).copied() {
        processor.tasks.push(CfgBuildTask::BeginAfterHandler {
            data: BeginAfterHandlerTask {
                handlers,
                ensures,
                handler_index: handler_index + 1,
                protected_start,
                protected_end,
                protected_entry,
                main,
                path: path.clone(),
            },
        });
        processor.tasks.push(CfgBuildTask::Statement {
            node: handler,
            loop_header: None,
            path,
        });
    } else {
        process_cfg_finish_begin(ensures, main, protected_entry, path, processor);
    }
}

fn process_cfg_begin_after_ensure<'tree>(
    ensures: Vec<Node<'tree>>,
    ensure_index: usize,
    mut main: Flow,
    path: Vec<usize>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    let final_flow = processor.result.take().unwrap_or_default();
    for exit in main.exits.drain(..) {
        if let Some(entry) = final_flow.entry {
            processor.cfg.link(exit, entry);
        }
    }
    main.exits = final_flow.exits;
    main.retries.extend(final_flow.retries);
    if let Some(ensure) = ensures.get(ensure_index).copied() {
        processor.tasks.push(CfgBuildTask::BeginAfterEnsure {
            ensures,
            ensure_index: ensure_index + 1,
            main,
            path: path.clone(),
        });
        processor.tasks.push(CfgBuildTask::Statement {
            node: ensure,
            loop_header: None,
            path,
        });
    } else {
        *processor.result = Some(main);
    }
}

fn process_cfg_call_after_block(call: Flow, processor: &mut CfgProcessor<'_, '_>) {
    let block_flow = processor.result.take().unwrap_or_default();
    if let (Some(call_entry), Some(block_entry)) = (call.entry, block_flow.entry) {
        processor.cfg.link(call_entry, block_entry);
    }
    let mut breaks = call.breaks;
    breaks.extend(block_flow.breaks);
    let mut continues = call.continues;
    continues.extend(block_flow.continues);
    let mut retries = call.retries;
    retries.extend(block_flow.retries);
    *processor.result = Some(Flow {
        entry: call.entry,
        exits: block_flow.exits,
        breaks,
        continues,
        retries,
    });
}

fn process_cfg_special_after_body(special: Flow, processor: &mut CfgProcessor<'_, '_>) {
    let child = processor.result.take().unwrap_or_default();
    if let (Some(exit), Some(entry)) = (special.entry, child.entry) {
        processor.cfg.link(exit, entry);
    }
    *processor.result = Some(Flow {
        entry: special.entry,
        exits: if child.entry.is_some() {
            child.exits
        } else {
            special.exits
        },
        breaks: child.breaks,
        continues: child.continues,
        retries: child.retries,
    });
}
fn process_cfg_sequence<'tree>(
    nodes: Vec<Node<'tree>>,
    mut next: usize,
    mut flow: Flow,
    loop_header: Option<usize>,
    path: Vec<usize>,
    processor: &mut CfgProcessor<'tree, '_>,
) {
    if let Some(current) = processor.result.take() {
        append_sequence_flow(processor.cfg, &mut flow, current);
    }
    if next == nodes.len() {
        *processor.result = Some(flow);
        return;
    }
    let node = nodes[next];
    next += 1;
    processor.tasks.push(CfgBuildTask::Sequence {
        nodes,
        next,
        flow,
        loop_header,
        path: path.clone(),
    });
    processor.tasks.push(CfgBuildTask::Statement {
        node,
        loop_header,
        path,
    });
}

fn is_statement_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "assignment"
            | "operator_assignment"
            | "call"
            | "return"
            | "yield"
            | "raise"
            | "break"
            | "next"
            | "method"
            | "singleton_method"
            | "class"
            | "module"
            | "expression_statement"
            | "binary"
            | "unary"
    )
}

fn node_from_facts(
    node: Node<'_>,
    kind: CfgNodeKind,
    map: &SourceMap,
    facts: &RubyFacts,
    id: usize,
) -> CfgNode {
    let range = map.range(node.start_byte(), node.end_byte());
    let nested_ranges: Vec<(usize, usize)> = [
        "body",
        "block",
        "consequence",
        "alternative",
        "then",
        "else",
        "rescue",
        "ensure",
    ]
    .iter()
    .filter_map(|field| node.child_by_field_name(field))
    .map(|child| (child.start_byte(), child.end_byte()))
    .collect();
    let mut reads = BTreeSet::new();
    let mut writes = BTreeSet::new();
    let mut scoped_reads = BTreeSet::new();
    let mut scoped_writes = BTreeSet::new();
    for local in &facts.locals {
        if local.byte_start < node.start_byte()
            || local.byte_end > node.end_byte()
            || nested_ranges
                .iter()
                .any(|(start, end)| local.byte_start >= *start && local.byte_end <= *end)
        {
            continue;
        }
        let scoped = ScopedLocal {
            scope_id: local.binding_scope.unwrap_or(local.lexical_scope),
            name: local.name.clone(),
        };
        match local.kind {
            LocalFactKind::Read => {
                reads.insert(local.name.clone());
                scoped_reads.insert(scoped);
            }
            LocalFactKind::Write => {
                writes.insert(local.name.clone());
                scoped_writes.insert(scoped);
            }
        }
    }
    CfgNode {
        id,
        kind,
        range,
        byte_start: node.start_byte(),
        byte_end: node.end_byte(),
        reads: reads.into_iter().collect(),
        writes: writes.into_iter().collect(),
        scoped_reads: scoped_reads.into_iter().collect(),
        scoped_writes: scoped_writes.into_iter().collect(),
        successors: Vec::new(),
        predecessors: Vec::new(),
    }
}

fn definitions(facts: &RubyFacts) -> Vec<Definition> {
    let mut defs = Vec::new();
    for (node, cfg_node) in facts.cfg.nodes.iter().enumerate() {
        for binding in &cfg_node.scoped_writes {
            defs.push(Definition {
                id: defs.len(),
                name: binding.name.clone(),
                scope_id: binding.scope_id,
                node,
                range: cfg_node.range.clone(),
            });
        }
    }
    defs
}

fn attach_definition_ids(facts: &mut RubyFacts) {
    let definition_ids: Vec<Option<usize>> = facts
        .locals
        .iter()
        .map(|local| {
            if local.kind != LocalFactKind::Write {
                return None;
            }
            let scope_id = local.binding_scope.unwrap_or(local.lexical_scope);
            let node_id = facts
                .cfg
                .nodes
                .iter()
                .filter(|node| {
                    local.byte_start >= node.byte_start && local.byte_end <= node.byte_end
                })
                .min_by_key(|node| node.byte_end.saturating_sub(node.byte_start))
                .map(|node| node.id);
            node_id.and_then(|node| {
                facts
                    .definitions
                    .iter()
                    .find(|definition| {
                        definition.node == node
                            && definition.name == local.name
                            && definition.scope_id == scope_id
                    })
                    .map(|definition| definition.id)
            })
        })
        .collect();
    for (local, definition) in facts.locals.iter_mut().zip(definition_ids) {
        local.definition = definition;
    }
}

const MAX_DATAFLOW_WORK_ITEMS: usize = 1_000_000;

struct DataflowState {
    reaching_in: Vec<BTreeSet<usize>>,
    reaching_out: Vec<BTreeSet<usize>>,
    initialized_in: Vec<BTreeSet<ScopedLocal>>,
    initialized_out: Vec<BTreeSet<ScopedLocal>>,
    live_in: Vec<BTreeSet<ScopedLocal>>,
    live_out: Vec<BTreeSet<ScopedLocal>>,
}

impl DataflowState {
    fn new(node_count: usize) -> Self {
        Self {
            reaching_in: vec![BTreeSet::new(); node_count],
            reaching_out: vec![BTreeSet::new(); node_count],
            initialized_in: vec![BTreeSet::new(); node_count],
            initialized_out: vec![BTreeSet::new(); node_count],
            live_in: vec![BTreeSet::new(); node_count],
            live_out: vec![BTreeSet::new(); node_count],
        }
    }

    fn into_results(self) -> DataflowResults {
        DataflowResults {
            reaching_in: self.reaching_in,
            reaching_out: self.reaching_out,
            initialized_in: self.initialized_in,
            initialized_out: self.initialized_out,
            live_in: self.live_in,
            live_out: self.live_out,
        }
    }
}

fn solve_dataflow(cfg: &ControlFlowGraph, defs: &[Definition]) -> (DataflowResults, bool) {
    solve_dataflow_with_budget(cfg, defs, MAX_DATAFLOW_WORK_ITEMS)
}

fn solve_dataflow_with_budget(
    cfg: &ControlFlowGraph,
    defs: &[Definition],
    budget: usize,
) -> (DataflowResults, bool) {
    let mut state = DataflowState::new(cfg.nodes.len());
    let mut work_items = 0;
    let mut tick = || {
        work_items += 1;
        work_items <= budget
    };
    let complete = solve_reaching_definitions(cfg, defs, &mut state, &mut tick)
        && solve_initialized_locals(cfg, &mut state, &mut tick)
        && solve_live_locals(cfg, &mut state, &mut tick);
    (state.into_results(), complete)
}

fn solve_reaching_definitions(
    cfg: &ControlFlowGraph,
    defs: &[Definition],
    state: &mut DataflowState,
    tick: &mut impl FnMut() -> bool,
) -> bool {
    let mut changed = true;
    while changed {
        changed = false;
        for node in &cfg.nodes {
            if !tick() {
                return false;
            }
            let incoming: BTreeSet<usize> = node
                .predecessors
                .iter()
                .flat_map(|pred| state.reaching_out[*pred].iter().copied())
                .collect();
            let mut outgoing = incoming.clone();
            for def in defs.iter().filter(|def| def.node == node.id) {
                outgoing
                    .retain(|id| defs[*id].scope_id != def.scope_id || defs[*id].name != def.name);
                outgoing.insert(def.id);
            }
            if state.reaching_in[node.id] != incoming {
                state.reaching_in[node.id] = incoming;
                changed = true;
            }
            if state.reaching_out[node.id] != outgoing {
                state.reaching_out[node.id] = outgoing;
                changed = true;
            }
        }
    }
    true
}

fn solve_initialized_locals(
    cfg: &ControlFlowGraph,
    state: &mut DataflowState,
    tick: &mut impl FnMut() -> bool,
) -> bool {
    let mut changed = true;
    while changed {
        changed = false;
        for node in &cfg.nodes {
            if !tick() {
                return false;
            }
            if update_initialized_node(node, state) {
                changed = true;
            }
        }
    }
    true
}

fn initialized_incoming(node: &CfgNode, state: &DataflowState) -> BTreeSet<ScopedLocal> {
    let mut incoming: Option<BTreeSet<ScopedLocal>> = None;
    for predecessor in &node.predecessors {
        incoming = Some(match incoming {
            Some(current) => current
                .intersection(&state.initialized_out[*predecessor])
                .cloned()
                .collect(),
            None => state.initialized_out[*predecessor].clone(),
        });
    }
    incoming.unwrap_or_default()
}

fn update_initialized_node(node: &CfgNode, state: &mut DataflowState) -> bool {
    let incoming = initialized_incoming(node, state);
    let mut outgoing = incoming.clone();
    outgoing.extend(node.scoped_writes.iter().cloned());
    let incoming_changed = state.initialized_in[node.id] != incoming;
    let outgoing_changed = state.initialized_out[node.id] != outgoing;
    if incoming_changed {
        state.initialized_in[node.id] = incoming;
    }
    if outgoing_changed {
        state.initialized_out[node.id] = outgoing;
    }
    incoming_changed || outgoing_changed
}

fn solve_live_locals(
    cfg: &ControlFlowGraph,
    state: &mut DataflowState,
    tick: &mut impl FnMut() -> bool,
) -> bool {
    let mut changed = true;
    while changed {
        changed = false;
        for node in cfg.nodes.iter().rev() {
            if !tick() {
                return false;
            }
            let outgoing = node
                .successors
                .iter()
                .flat_map(|succ| state.live_in[*succ].iter().cloned())
                .collect::<BTreeSet<_>>();
            let mut incoming = outgoing.clone();
            for write in &node.scoped_writes {
                incoming.remove(write);
            }
            incoming.extend(node.scoped_reads.iter().cloned());
            if state.live_out[node.id] != outgoing {
                state.live_out[node.id] = outgoing;
                changed = true;
            }
            if state.live_in[node.id] != incoming {
                state.live_in[node.id] = incoming;
                changed = true;
            }
        }
    }
    true
}

fn collect_ruby_metrics(
    source: &str,
    root: Node<'_>,
    file: &hoonarqube_ir::FileMetrics,
) -> RubyMetrics {
    let mut metrics = RubyMetrics {
        file: file.clone(),
        ..RubyMetrics::default()
    };
    let mut pending = vec![(root, 0usize)];
    while let Some((node, nesting)) = pending.pop() {
        let is_nesting = matches!(
            node.kind(),
            "if" | "unless" | "conditional" | "case" | "while" | "until" | "for"
        );
        match node.kind() {
            "method" | "singleton_method" => metrics.methods += 1,
            "class" | "module" => metrics.classes += 1,
            "block" | "do_block" => metrics.blocks += 1,
            "if" | "unless" | "conditional" | "case" => {
                metrics.conditionals += 1;
                metrics.max_nesting = metrics.max_nesting.max(nesting + 1);
                metrics.cognitive_complexity += nesting + 1;
            }
            "while" | "until" | "for" => {
                metrics.loops += 1;
                metrics.max_nesting = metrics.max_nesting.max(nesting + 1);
                metrics.cognitive_complexity += nesting + 2;
            }
            "rescue" => metrics.rescue_clauses += 1,
            _ => {}
        }
        let child_nesting = if is_nesting { nesting + 1 } else { nesting };
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            pending.push((child, child_nesting));
        }
    }
    let _ = source;
    metrics
}
/// Run the registered GitHub-quality Ruby queries.
///
/// The queries are intentionally conservative. They operate only on a
/// syntactically valid tree and never turn an ambiguous recovered fragment
/// into a finding.
#[must_use]
pub fn github_quality(source: &str) -> Vec<hoonarqube_ir::Issue> {
    let facts = analyze_facts(source);
    if facts.malformed || !facts.analysis_complete {
        return Vec::new();
    }
    let mut issues = Vec::new();
    report_uninitialized(&facts, source, &mut issues);
    report_useless_assignments(&facts, source, &mut issues);
    report_database_queries(source, &mut issues);
    hoonarqube_ir::sort_issues(&mut issues);
    issues.dedup();
    debug_assert!(
        issues
            .iter()
            .all(|issue| crate::GITHUB_QUALITY_RULE_IDS.contains(&issue.rule_key.as_str()))
    );
    issues
}

fn report_uninitialized(facts: &RubyFacts, source: &str, issues: &mut Vec<hoonarqube_ir::Issue>) {
    let Some(tree) = parse(source) else { return };
    let root = tree.root_node();
    for local in facts
        .locals
        .iter()
        .filter(|local| local.kind == LocalFactKind::Read && !local.name.starts_with('_'))
    {
        if let Some(binding_scope) = local.binding_scope
            && facts.scopes[binding_scope]
                .bindings
                .get(&local.name)
                .is_some_and(|binding| {
                    matches!(
                        binding.kind,
                        BindingKind::Parameter | BindingKind::BlockParameter
                    )
                })
        {
            continue;
        }
        let Some(call) = facts.calls.iter().find(|call| {
            call.receiver.as_deref() == Some(local.name.as_str())
                && call.byte_start <= local.byte_start
                && call.byte_end >= local.byte_end
        }) else {
            continue;
        };
        if call.safe_navigation
            || matches!(
                call.method.as_str(),
                "inspect"
                    | "instance_of?"
                    | "is_a?"
                    | "kind_of?"
                    | "method"
                    | "nil?"
                    | "rationalize"
                    | "to_a"
                    | "to_c"
                    | "to_f"
                    | "to_h"
                    | "to_i"
                    | "to_r"
                    | "to_s"
            )
        {
            continue;
        }
        let Some(node) = find_node(root, local.byte_start, local.byte_end) else {
            continue;
        };
        if is_in_boolean_context(node) || is_guarded_read(node, source) {
            continue;
        }
        let cfg_node = facts
            .cfg
            .nodes
            .iter()
            .filter(|node| local.byte_start >= node.byte_start && local.byte_end <= node.byte_end)
            .min_by_key(|node| node.byte_end.saturating_sub(node.byte_start));
        let initialized = cfg_node.is_some_and(|node| {
            let key = ScopedLocal {
                scope_id: local.binding_scope.unwrap_or(local.lexical_scope),
                name: local.name.clone(),
            };
            facts
                .dataflow
                .initialized_in
                .get(node.id)
                .is_some_and(|values| values.contains(&key))
        });
        let lexical_fallback = facts.locals.iter().any(|other| {
            other.kind == LocalFactKind::Write
                && other.name == local.name
                && other.binding_scope == local.binding_scope
                && other.byte_end <= local.byte_start
        });
        if !(initialized || (cfg_node.is_none() && lexical_fallback)) {
            let related_range =
                local_binding_range(facts, local).unwrap_or_else(|| local.range.clone());
            issues.push(
                hoonarqube_ir::Issue::new(
                    "rb/uninitialized-local-variable",
                    "Local variable $@ may be used before it is initialized.",
                    local.range.clone(),
                )
                .with_flow(vec![hoonarqube_ir::FlowLocation::in_primary_file(
                    local.name.clone(),
                    related_range,
                )]),
            );
        }
    }
}

fn find_node<'tree>(root: Node<'tree>, start: usize, end: usize) -> Option<Node<'tree>> {
    let mut found = None;
    walk(root, &mut |node: Node<'tree>| {
        if node.start_byte() == start && node.end_byte() == end {
            found = Some(node);
        }
    });
    found
}

fn is_in_boolean_context(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "and"
                | "or"
                | "not"
                | "if_modifier"
                | "unless_modifier"
                | "while_modifier"
                | "until_modifier"
        ) {
            return true;
        }
        if matches!(parent.kind(), "if" | "unless" | "while" | "until")
            && let Some(condition) = parent.child_by_field_name("condition")
            && node.start_byte() >= condition.start_byte()
            && node.end_byte() <= condition.end_byte()
        {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn is_guarded_read(node: Node<'_>, source: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(parent.kind(), "if" | "unless" | "while" | "until") {
            let Some(condition) = parent.child_by_field_name("condition") else {
                current = parent.parent();
                continue;
            };
            let in_consequence = parent
                .child_by_field_name("consequence")
                .is_some_and(|branch| {
                    node.start_byte() >= branch.start_byte() && node.end_byte() <= branch.end_byte()
                });
            let in_alternative = parent
                .child_by_field_name("alternative")
                .is_some_and(|branch| {
                    node.start_byte() >= branch.start_byte() && node.end_byte() <= branch.end_byte()
                });
            if in_consequence || in_alternative {
                let condition_truthy = if parent.kind() == "unless" {
                    in_alternative
                } else {
                    in_consequence
                };
                if guard_proves_not_nil(node_text(condition, source), condition_truthy) {
                    return true;
                }
            }
        }
        current = parent.parent();
    }
    false
}

fn guard_proves_not_nil(condition: &str, truthy_branch: bool) -> bool {
    let condition = condition.trim();
    let (negated, expression) = condition
        .strip_prefix('!')
        .map_or((false, condition), |rest| (true, rest.trim()));
    let expression = expression
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .map_or(expression, str::trim);
    if is_identifier(expression) {
        return truthy_branch != negated;
    }
    if let Some(variable) = expression.strip_suffix(".nil?")
        && is_identifier(variable.trim())
    {
        return truthy_branch == negated;
    }
    false
}

fn report_useless_assignments(
    facts: &RubyFacts,
    source: &str,
    issues: &mut Vec<hoonarqube_ir::Issue>,
) {
    for local in facts
        .locals
        .iter()
        .filter(|local: &&LocalFact| local.kind == LocalFactKind::Write)
    {
        if local.name.starts_with('_') || useless_assignment_excluded(facts, local) {
            continue;
        }
        let has_read_before_next_write = facts.locals.iter().any(|other: &LocalFact| {
            other.kind == LocalFactKind::Read
                && other.name == local.name
                && other.binding_scope == local.binding_scope
                && other.byte_start >= local.byte_start
                && other.byte_end >= local.byte_end
                && !facts.locals.iter().any(|candidate: &LocalFact| {
                    candidate.kind == LocalFactKind::Write
                        && candidate.name == local.name
                        && candidate.binding_scope == local.binding_scope
                        && candidate.byte_start > local.byte_start
                        && candidate.byte_start < other.byte_start
                })
        });
        if !has_read_before_next_write {
            let related_range =
                local_binding_range(facts, local).unwrap_or_else(|| local.range.clone());
            issues.push(
                hoonarqube_ir::Issue::new(
                    "rb/useless-assignment-to-local",
                    "This assignment to $@ is useless, since its value is never read.",
                    local.range.clone(),
                )
                .with_flow(vec![hoonarqube_ir::FlowLocation::in_primary_file(
                    local.name.clone(),
                    related_range,
                )]),
            );
        }
    }
    let _ = source;
}

fn local_binding_range(facts: &RubyFacts, local: &LocalFact) -> Option<hoonarqube_ir::Range> {
    let scope = local.binding_scope?;
    facts
        .scopes
        .get(scope)?
        .bindings
        .get(&local.name)
        .map(|binding| binding.declaration.clone())
}

fn useless_assignment_excluded(facts: &RubyFacts, local: &LocalFact) -> bool {
    let Some(scope_id) = local.binding_scope else {
        return false;
    };
    let Some(binding) = facts.scopes[scope_id].bindings.get(&local.name) else {
        return false;
    };
    if matches!(
        binding.kind,
        BindingKind::Parameter | BindingKind::BlockParameter
    ) {
        return true;
    }
    let scope = &facts.scopes[scope_id];
    facts.cfg.nodes.iter().any(|node: &CfgNode| {
        node.kind == CfgNodeKind::Retry
            && node.byte_start >= scope.start
            && node.byte_end <= scope.end
    }) || facts.calls.iter().any(|call: &MethodCall| {
        call.byte_start >= scope.start
            && call.byte_end <= scope.end
            && ((call.receiver.as_deref() == Some("self") && call.method == "binding")
                || (call.receiver.as_deref() == Some("ERB") && call.method == "result"))
    })
}

fn report_database_queries(source: &str, issues: &mut Vec<hoonarqube_ir::Issue>) {
    let Some(tree) = parse(source) else { return };
    let root = tree.root_node();
    let Some(models) = resolved_framework_models(root, source) else {
        return;
    };
    let map = SourceMap::new(source);
    let mut query_ranges = HashSet::new();
    walk(root, &mut |query: Node<'_>| {
        if query.kind() != "call" || !is_database_query(query, source, &models) {
            return;
        }
        let Some(loop_node) = looping_ancestor(query, source) else {
            return;
        };
        if loop_receiver_is_constant(loop_node, source)
            || query_controls_loop(query, loop_node, source)
        {
            return;
        }
        if query_ranges.insert((query.start_byte(), query.end_byte())) {
            let issue = hoonarqube_ir::Issue::new(
                "rb/database-query-in-loop",
                "This call to a database query operation happens inside $@, and could be hoisted to a single call outside the loop.",
                map.range(query.start_byte(), query.end_byte()),
            )
            .with_flow(vec![hoonarqube_ir::FlowLocation::in_primary_file(
                "loop",
                map.range(loop_node.start_byte(), loop_node.end_byte()),
            )]);
            issues.push(issue);
        }
    });
}

fn resolved_framework_models(root: Node<'_>, source: &str) -> Option<HashSet<String>> {
    let mut declarations: Vec<(String, String)> = Vec::new();
    walk(root, &mut |node: Node<'_>| {
        if node.kind() != "class" {
            return;
        }
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        let name = node_text(name, source).trim().to_string();
        if name.is_empty() {
            return;
        }
        let superclass = node
            .child_by_field_name("superclass")
            .map(|parent| {
                node_text(parent, source)
                    .trim()
                    .trim_start_matches('<')
                    .trim()
                    .to_string()
            })
            .unwrap_or_default();
        declarations.push((name, superclass));
    });
    let mut models = HashSet::from([
        "ApplicationRecord".to_string(),
        "ActiveRecord::Base".to_string(),
    ]);
    let mut work_items = 0;
    let mut changed = true;
    while changed {
        changed = false;
        for (name, superclass) in &declarations {
            work_items += 1;
            if work_items > MAX_DATAFLOW_WORK_ITEMS {
                return None;
            }
            if models.contains(superclass) && models.insert(name.clone()) {
                changed = true;
            }
        }
    }
    Some(models)
}

fn is_database_query(node: Node<'_>, source: &str, models: &HashSet<String>) -> bool {
    let Some(receiver) = node.child_by_field_name("receiver") else {
        return false;
    };
    let Some(method) = node.child_by_field_name("method") else {
        return false;
    };
    let Some(model) = ultimate_receiver_name(receiver, source) else {
        return false;
    };
    let method = node_text(method, source).trim();
    let static_finder = matches!(
        method,
        "fifth"
            | "find"
            | "find!"
            | "find_by"
            | "find_by!"
            | "find_or_initialize_by"
            | "find_or_initialize_by!"
            | "find_or_create_by"
            | "find_or_create_by!"
            | "first"
            | "forty_two"
            | "fourth"
            | "last"
            | "second"
            | "second_to_last"
            | "take"
            | "third"
            | "third_to_last"
    );
    models.contains(&model) && (static_finder || method.starts_with("find_by_"))
}

fn ultimate_receiver_name(mut node: Node<'_>, source: &str) -> Option<String> {
    loop {
        if node.kind() == "call" {
            node = node.child_by_field_name("receiver")?;
            continue;
        }
        let text = node_text(node, source).trim();
        if text.is_empty()
            || !text
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_uppercase())
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_'))
        {
            return None;
        }
        return Some(text.to_string());
    }
}

fn looping_ancestor<'tree>(query: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let mut current = query.parent();
    while let Some(node) = current {
        if matches!(
            node.kind(),
            "method" | "singleton_method" | "lambda" | "class" | "module"
        ) {
            return None;
        }
        if matches!(
            node.kind(),
            "while" | "until" | "for" | "while_modifier" | "until_modifier"
        ) {
            return Some(node);
        }
        if matches!(node.kind(), "block" | "do_block")
            && let Some(call) = node.parent()
            && call.kind() == "call"
            && call
                .child_by_field_name("block")
                .is_some_and(|block| block.id() == node.id())
            && call.child_by_field_name("method").is_some_and(|method| {
                matches!(
                    node_text(method, source).trim(),
                    "each"
                        | "reverse_each"
                        | "map"
                        | "map!"
                        | "foreach"
                        | "find_each"
                        | "flat_map"
                        | "in_batches"
                        | "one?"
                        | "all?"
                        | "collect"
                        | "collect!"
                        | "select"
                        | "select!"
                        | "reject"
                        | "reject!"
                        | "loop"
                )
            })
        {
            return Some(call);
        }
        current = node.parent();
    }
    None
}

fn loop_receiver_is_constant(loop_node: Node<'_>, source: &str) -> bool {
    let Some(receiver) = loop_node.child_by_field_name("receiver") else {
        return false;
    };
    let text = node_text(receiver, source).trim();
    text.starts_with('[')
        || text.starts_with("%w")
        || text.starts_with("%W")
        || text.starts_with("%i")
        || text.starts_with("%I")
}

fn query_controls_loop(query: Node<'_>, loop_node: Node<'_>, source: &str) -> bool {
    let Some(body) = (if matches!(loop_node.kind(), "block" | "do_block") {
        Some(loop_node)
    } else {
        loop_node
            .child_by_field_name("body")
            .or_else(|| loop_node.child_by_field_name("block"))
    }) else {
        return false;
    };
    if has_direct_terminating_control_after(query, body) {
        return true;
    }
    let mut current = query.parent();
    while let Some(node) = current {
        if is_terminating_control(node.kind()) {
            return true;
        }
        if node.id() == body.id() {
            break;
        }
        current = node.parent();
    }
    let mut query_name = None;
    let mut current = query.parent();
    while let Some(node) = current {
        if node.kind() == "assignment"
            && let (Some(right), Some(left)) = (
                node.child_by_field_name("right"),
                node.child_by_field_name("left"),
            )
            && query.start_byte() >= right.start_byte()
            && query.end_byte() <= right.end_byte()
        {
            query_name = Some(node_text(left, source).trim().to_string());
            break;
        }
        if node.id() == body.id() {
            break;
        }
        current = node.parent();
    }
    let mut guarded = false;
    walk(body, &mut |node: Node<'_>| {
        if guarded {
            return;
        }
        if matches!(
            node.kind(),
            "if" | "unless" | "while" | "until" | "if_modifier" | "unless_modifier"
        ) && node
            .child_by_field_name("condition")
            .is_some_and(|condition| {
                let condition_text = node_text(condition, source);
                node_contains_terminating_control(node)
                    && (query.start_byte() >= condition.start_byte()
                        && query.end_byte() <= condition.end_byte()
                        || query_name.as_deref().is_some_and(|name| {
                            condition_text
                                .split(|character: char| {
                                    !character.is_ascii_alphanumeric() && character != '_'
                                })
                                .any(|part| part == name)
                        }))
            })
        {
            guarded = true;
        }
    });
    guarded
}

fn has_direct_terminating_control_after(query: Node<'_>, body: Node<'_>) -> bool {
    if !is_direct_loop_body_member(query, body) {
        return false;
    }
    let mut found = false;
    walk(body, &mut |node: Node<'_>| {
        if found
            || !is_terminating_control(node.kind())
            || node.start_byte() < query.end_byte()
            || !is_direct_loop_body_member(node, body)
        {
            return;
        }
        found = true;
    });
    found
}

fn is_direct_loop_body_member(node: Node<'_>, body: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.id() == body.id() {
            return true;
        }
        if matches!(
            parent.kind(),
            "if" | "unless"
                | "conditional"
                | "case"
                | "when"
                | "in_clause"
                | "while"
                | "until"
                | "for"
                | "while_modifier"
                | "until_modifier"
                | "rescue"
                | "ensure"
                | "begin"
                | "if_modifier"
                | "unless_modifier"
                | "block"
                | "do_block"
                | "lambda"
                | "method"
                | "singleton_method"
                | "class"
                | "module"
        ) {
            return false;
        }
        current = parent.parent();
    }
    false
}

fn is_terminating_control(kind: &str) -> bool {
    matches!(kind, "break" | "raise" | "return")
}

fn node_contains_terminating_control(node: Node<'_>) -> bool {
    let mut found = false;
    walk(node, &mut |child: Node<'_>| {
        if child.id() != node.id() && is_terminating_control(child.kind()) {
            found = true;
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_capture_methods_classes_blocks_and_closures() {
        let facts = analyze_facts(
            "class Box\n  def value(seed)\n    [seed].each { |item| puts seed; item }\n  end\nend\n",
        );
        assert!(
            facts
                .scopes
                .iter()
                .any(|scope| scope.kind == ScopeKind::Class)
        );
        assert!(
            facts
                .scopes
                .iter()
                .any(|scope| scope.kind == ScopeKind::Method)
        );
        assert!(
            facts
                .scopes
                .iter()
                .any(|scope| scope.kind == ScopeKind::Block)
        );
        assert!(
            facts
                .locals
                .iter()
                .any(|local| local.name == "seed" && local.kind == LocalFactKind::Read)
        );
        assert!(
            facts
                .calls
                .iter()
                .any(|call| call.method == "each" && call.block.is_some())
        );
    }

    #[test]
    fn pattern_captures_initialize_locals_without_false_findings() {
        let source = "def inspect(value)\n  case value\n  in {name: captured}\n    captured.length\n  else\n    value.to_s\n  end\nend\n";
        let facts = analyze_facts(source);
        assert!(!facts.malformed);
        assert!(facts.analysis_complete);
        let writes = facts
            .locals
            .iter()
            .filter(|local| local.name == "captured" && local.kind == LocalFactKind::Write)
            .count();
        let reads = facts
            .locals
            .iter()
            .filter(|local| local.name == "captured" && local.kind == LocalFactKind::Read)
            .count();
        assert_eq!(writes, 1);
        assert_eq!(reads, 1);
        assert!(
            github_quality(source)
                .into_iter()
                .all(|issue| issue.rule_key != "rb/uninitialized-local-variable"),
            "a case capture dominates its guarded receiver read"
        );
    }
    #[test]
    fn shorthand_keyword_patterns_bind_only_bare_locals() {
        let source = "def inspect(value)\n  case value\n  in {name:}\n    name.length\n  else\n    value.to_s\n  end\nend\n";
        let facts = analyze_facts(source);
        assert!(!facts.malformed);
        assert_eq!(
            facts
                .locals
                .iter()
                .filter(|local| local.name == "name" && local.kind == LocalFactKind::Write)
                .count(),
            1
        );
        assert_eq!(
            facts
                .locals
                .iter()
                .filter(|local| local.name == "name" && local.kind == LocalFactKind::Read)
                .count(),
            1
        );
        assert!(github_quality(source).is_empty());

        let conservative = "def inspect(value)\n  case value\n  in {Name:}\n    value\n  in {\"name\":}\n    value\n  end\nend\n";
        let facts = analyze_facts(conservative);
        assert!(
            facts
                .locals
                .iter()
                .all(|local| local.name != "Name" && local.name != "name")
        );
    }

    #[test]
    fn malformed_pattern_and_heredoc_recovery_fails_closed() {
        for source in [
            "def broken(value)\n  case value\n  in {name: captured}\n    captured.length\n",
            "def broken\n  query = <<~SQL\n    unfinished\n",
        ] {
            let facts = analyze_facts(source);
            assert!(facts.malformed);
            assert!(
                github_quality(source).is_empty(),
                "recovered fragments must not become quality findings"
            );
        }
    }

    #[test]
    fn nested_lambda_and_block_defaults_preserve_capture_scopes() {
        let source = "def build(seed, callback = -> { seed.length })\n  callback\nend\n\
def build_with_block(seed, callback = proc { seed.length })\n  callback\nend\n";
        let facts = analyze_facts(source);
        assert!(!facts.malformed);
        assert!(facts.analysis_complete);
        let nested_scopes: Vec<_> = facts
            .scopes
            .iter()
            .filter(|scope| matches!(scope.kind, ScopeKind::Lambda | ScopeKind::Block))
            .map(|scope| scope.id)
            .collect();
        assert!(nested_scopes.len() >= 2);
        for scope_id in nested_scopes {
            let seed = facts
                .locals
                .iter()
                .find(|local| {
                    local.name == "seed"
                        && local.kind == LocalFactKind::Read
                        && local.lexical_scope == scope_id
                })
                .expect("default closure read must retain its nested lexical scope");
            assert_ne!(seed.binding_scope, Some(scope_id));
        }
        assert!(
            facts
                .scopes
                .iter()
                .filter_map(|scope| scope.bindings.get("seed"))
                .any(|binding| binding.captured),
            "default closures must mark the method parameter as captured"
        );
        assert!(
            github_quality(source)
                .into_iter()
                .all(|issue| issue.rule_key != "rb/uninitialized-local-variable")
        );
    }

    #[test]
    fn endless_methods_modifiers_lambdas_and_heredocs_keep_scope_facts() {
        let source = "def label(value) = value&.to_s\n\ndef render(value)\n  outer = 1\n  worker = -> { outer }\n  [value].each { |item| item.to_s if item }\n  <<~SQL\n    # payload, not a Ruby comment\n  SQL\n  outer if value\n  worker.call\nend\n";
        let facts = analyze_facts(source);
        assert!(!facts.malformed);
        assert!(facts.analysis_complete);
        assert!(
            facts
                .scopes
                .iter()
                .any(|scope| scope.kind == ScopeKind::Lambda)
        );
        assert!(
            facts
                .calls
                .iter()
                .any(|call| call.method == "to_s" && call.safe_navigation)
        );
        assert!(
            facts
                .scopes
                .iter()
                .flat_map(|scope| scope.bindings.values())
                .any(|binding| binding.name == "outer" && binding.captured)
        );
        assert_eq!(facts.metrics.file.comment_lines, 0);
        assert!(
            github_quality(source).is_empty(),
            "initialized captures and modifier control flow must stay clean"
        );
    }
    #[test]
    fn only_call_receiver_reads_are_checked_for_uninitialized_use() {
        let issues = github_quality("def f\n  value.length\nend\n");
        assert!(
            issues
                .iter()
                .any(|issue| issue.rule_key == "rb/uninitialized-local-variable")
        );
        assert!(
            github_quality("def f\n  puts value\nend\n")
                .iter()
                .all(|issue| issue.rule_key != "rb/uninitialized-local-variable")
        );
    }

    #[test]
    fn cfg_join_is_conservative_for_conditional_definitions() {
        let source = "if flag\n  value = 1\nend\nvalue.length\n";
        let facts = analyze_facts(source);
        assert!(
            facts
                .cfg
                .nodes
                .iter()
                .any(|node| node.kind == CfgNodeKind::Condition)
        );
        let issues = github_quality(source);
        assert!(
            issues
                .iter()
                .any(|issue| issue.rule_key == "rb/uninitialized-local-variable")
        );
    }

    #[test]
    fn nil_guards_and_safe_navigation_are_indexed() {
        let facts = analyze_facts("if user.nil?\n  user\nend\nuser&.name\n");
        assert!(
            facts
                .nil_guards
                .iter()
                .any(|guard| guard.variable == "user" && guard.state == NilState::Nil)
        );
        assert!(
            facts
                .calls
                .iter()
                .any(|call| call.method == "name" && call.safe_navigation)
        );
    }

    #[test]
    fn rescue_ensure_retry_have_cfg_nodes_and_metrics() {
        let facts = analyze_facts(
            "begin\n  work\nrescue StandardError => error\n  retry\nensure\n  cleanup\nend\n",
        );
        assert!(facts.metrics.rescue_clauses >= 1);
        assert!(
            facts
                .cfg
                .nodes
                .iter()
                .any(|node| node.kind == CfgNodeKind::Rescue)
        );
        assert!(
            facts
                .cfg
                .nodes
                .iter()
                .any(|node| node.kind == CfgNodeKind::Ensure)
        );
        assert!(
            facts
                .cfg
                .nodes
                .iter()
                .any(|node| node.kind == CfgNodeKind::Retry)
        );
    }

    #[test]
    fn github_database_rule_requires_active_record_and_loop_control() {
        let finding =
            github_quality("class User < ApplicationRecord; end\nitems.each { User.find(1) }\n");
        assert!(
            finding
                .iter()
                .any(|issue| issue.rule_key == "rb/database-query-in-loop")
        );
        assert!(
            github_quality("items.each { user.where(active: true) }\n")
                .iter()
                .all(|issue| issue.rule_key != "rb/database-query-in-loop")
        );
        let find_each = github_quality(
            "class User < ApplicationRecord; end\nitems.find_each { User.find(1) }\n",
        );
        assert_eq!(
            find_each
                .iter()
                .filter(|issue| issue.rule_key == "rb/database-query-in-loop")
                .count(),
            1,
            "find_each is a real loop and must classify nested model queries"
        );
        let query_issue = find_each
            .iter()
            .find(|issue| issue.rule_key == "rb/database-query-in-loop")
            .expect("find_each query finding");
        assert_eq!(query_issue.range.start.line, 2);
        assert_eq!(query_issue.range.start.column, 18);
        assert_eq!(query_issue.flows.len(), 1);
        let near_miss =
            "class User < ApplicationRecord; end\nitems.find_each { |user| user.name }\n";
        assert!(
            github_quality(near_miss)
                .iter()
                .all(|issue| issue.rule_key != "rb/database-query-in-loop"),
            "ordinary receiver calls inside find_each are not database queries"
        );
    }

    #[test]
    fn github_database_rule_covers_native_loops_and_real_termination() {
        let source = "class User < ApplicationRecord; end\n\
def scan(items, done)\n\
  while !done\n\
    User.find(1)\n\
  end\n\
  until done\n\
    User.find(1)\n\
  end\n\
  for item in items\n\
    User.find(1)\n\
  end\n\
  loop do\n\
    User.find(1)\n\
  end\n\
end\n";
        let findings = github_quality(source)
            .into_iter()
            .filter(|issue| issue.rule_key == "rb/database-query-in-loop")
            .collect::<Vec<_>>();
        assert_eq!(findings.len(), 4);
        assert!(findings.iter().all(|issue| {
            issue.flows.len() == 1
                && issue.flows[0].locations.len() == 1
                && issue.flows[0].locations[0].message == "loop"
        }));

        let terminated = "class User < ApplicationRecord; end\n\
def stop(items, done)\n\
  while !done\n\
    User.find(1)\n\
    break\n\
  end\n\
  until done\n\
    User.find(1)\n\
    return\n\
  end\n\
  for item in items\n\
    User.find(1)\n\
    return\n\
  end\n\
  loop do\n\
    User.find(1)\n\
    break\n\
  end\n\
end\n";
        let terminated_findings: Vec<_> = github_quality(terminated)
            .into_iter()
            .filter(|issue| issue.rule_key == "rb/database-query-in-loop")
            .map(|issue| (issue.range.start.line, issue.range.start.column))
            .collect();
        assert!(
            terminated_findings.is_empty(),
            "unconditional break and return terminate each loop path: {terminated_findings:?}"
        );

        let conditional = "class User < ApplicationRecord; end\n\
def maybe(items, done)\n\
  while !done\n\
    User.find(1)\n\
    break if done\n\
  end\n\
  items.tap { User.find(1) }\n\
end\n";
        assert_eq!(
            github_quality(conditional)
                .into_iter()
                .filter(|issue| issue.rule_key == "rb/database-query-in-loop")
                .count(),
            1,
            "conditional break must not suppress a query, and tap is not a loop"
        );
    }

    #[test]
    fn metrics_and_positions_are_byte_safe() {
        let facts = analyze_facts("# π\nvalue = \"é\"\n");
        assert_eq!(facts.metrics.file.lines, 2);
        assert_eq!(facts.metrics.file.comment_lines, 1);
        assert!(facts.locals.iter().any(|local| local.range.start.line == 2));
    }
    #[test]
    fn local_dataflow_is_keyed_by_callable_scope() {
        let issues =
            github_quality("def first\n  value = 1\nend\n\ndef second\n  value.length\nend\n");
        assert!(
            issues
                .iter()
                .any(|issue| issue.rule_key == "rb/uninitialized-local-variable")
        );
    }

    #[test]
    fn parameter_defaults_read_outer_names_without_binding_them() {
        let facts = analyze_facts("def build(value = missing)\n  value\nend\n");
        assert!(
            facts
                .locals
                .iter()
                .any(|local| { local.name == "missing" && local.kind == LocalFactKind::Read })
        );
        assert!(
            !facts
                .locals
                .iter()
                .any(|local| { local.name == "missing" && local.kind == LocalFactKind::Write })
        );
    }

    #[test]
    fn symbol_array_loop_receivers_are_constant() {
        let issues = github_quality(
            "class User < ApplicationRecord; end\n%i[one two].each { User.where(active: true) }\n",
        );
        assert!(
            issues
                .iter()
                .all(|issue| issue.rule_key != "rb/database-query-in-loop")
        );
    }
    #[test]
    fn dataflow_budget_fails_closed() {
        let mut cfg = ControlFlowGraph::default();
        let entry = cfg.add(CfgNode::new(
            0,
            CfgNodeKind::Entry,
            hoonarqube_ir::Range::file_level(),
        ));
        let exit = cfg.add(CfgNode::new(
            1,
            CfgNodeKind::Exit,
            hoonarqube_ir::Range::file_level(),
        ));
        cfg.entry = entry;
        cfg.exit = exit;
        cfg.link(entry, exit);
        let (_, complete) = solve_dataflow_with_budget(&cfg, &[], 1);
        assert!(!complete);
    }
}
