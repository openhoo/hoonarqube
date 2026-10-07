//! S4158: reads of bindings that can only hold empty collections.
//!
//! Every reference participates: unknown aliases, calls, writes or additive
//! mutations invalidate the candidate, regardless of source order. Literal
//! member accesses are not variable usages and never qualify.
use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{AssignmentOperator, BindingPattern, Expression};
use oxc_semantic::Semantic;
use oxc_span::{GetSpan, Span};
use oxc_syntax::{node::NodeId, symbol::SymbolId};

const READING_METHODS: &[&str] = &[
    "copyWithin",
    "pop",
    "reverse",
    "shift",
    "sort",
    "clear",
    "delete",
    "concat",
    "flat",
    "flatMap",
    "includes",
    "indexOf",
    "join",
    "lastIndexOf",
    "slice",
    "toSource",
    "toString",
    "toLocaleString",
    "get",
    "has",
    "entries",
    "every",
    "filter",
    "find",
    "findIndex",
    "forEach",
    "keys",
    "map",
    "reduce",
    "reduceRight",
    "some",
    "values",
];

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    let Some(semantic) = ctx.semantic else {
        return sink.issues;
    };
    for node in semantic.nodes().iter() {
        let AstKind::VariableDeclarator(declaration) = node.kind() else {
            continue;
        };
        let BindingPattern::BindingIdentifier(binding) = &declaration.id else {
            continue;
        };
        let Some(symbol) = binding.symbol_id.get() else {
            continue;
        };
        if declaration
            .init
            .as_ref()
            .is_some_and(|init| !is_empty_collection(init))
        {
            continue;
        }
        let has_empty_initializer = declaration.init.as_ref().is_some_and(is_empty_collection);
        let Some(reads) = reads_of_always_empty(semantic, symbol, has_empty_initializer) else {
            continue;
        };
        for span in reads {
            sink.emit_span(
                RuleScope::Both,
                "S4158",
                &format!(
                    "Review this usage of \"{}\" as it can only be empty here.",
                    binding.name
                ),
                span,
            );
        }
    }
    sink.issues
}

/// Collect reads only when every resolved reference preserves emptiness.
/// A failed proof invalidates all reads, including reads before the mutation.
fn reads_of_always_empty(
    semantic: &Semantic<'_>,
    symbol: SymbolId,
    mut has_empty_assignment: bool,
) -> Option<Vec<Span>> {
    let mut reads = Vec::new();
    for reference in semantic.scoping().get_resolved_references(symbol) {
        if reference.is_write() {
            if reference.is_read() || !assigns_empty_collection(semantic, reference.node_id()) {
                return None;
            }
            has_empty_assignment = true;
            continue;
        }
        if !is_reading_usage(semantic, reference.node_id()) {
            return None;
        }
        reads.push(semantic.reference_span(reference));
    }
    has_empty_assignment.then_some(reads)
}

fn is_empty_collection(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::ArrayExpression(array) => array.elements.is_empty(),
        Expression::CallExpression(call) => {
            call.arguments.is_empty() && is_collection_constructor(&call.callee)
        }
        Expression::NewExpression(new) => {
            new.arguments.is_empty() && is_collection_constructor(&new.callee)
        }
        _ => false,
    }
}

fn is_collection_constructor(expression: &Expression<'_>) -> bool {
    matches!(unparenthesized(expression), Expression::Identifier(identifier)
        if matches!(identifier.name.as_str(), "Array" | "Map" | "Set" | "WeakSet" | "WeakMap"))
}

fn assigns_empty_collection(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    let nodes = semantic.nodes();
    let mut parent = nodes.parent_node(node_id);
    while matches!(parent.kind(), AstKind::ParenthesizedExpression(_)) {
        parent = nodes.parent_node(parent.id());
    }
    matches!(parent.kind(), AstKind::AssignmentExpression(assignment)
        if assignment.operator == AssignmentOperator::Assign
            && assignment.left.span() == nodes.get_node(node_id).kind().span()
            && is_empty_collection(&assignment.right)
            && matches!(nodes.parent_kind(parent.id()), AstKind::ExpressionStatement(_)))
}

fn is_reading_usage(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    let nodes = semantic.nodes();
    let span = nodes.get_node(node_id).kind().span();
    let parent = nodes.parent_node(node_id);
    match parent.kind() {
        AstKind::StaticMemberExpression(member) if member.object.span() == span => {
            READING_METHODS.contains(&member.property.name.as_str())
                && matches!(nodes.parent_kind(parent.id()), AstKind::CallExpression(call)
                    if call.callee.span() == member.span())
        }
        AstKind::ComputedMemberExpression(member) if member.object.span() == span => {
            !element_is_written(semantic, parent.id())
        }
        AstKind::ForOfStatement(statement) => statement.right.span() == span,
        AstKind::ForInStatement(statement) => statement.right.span() == span,
        _ => false,
    }
}

fn element_is_written(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    let nodes = semantic.nodes();
    let span = nodes.get_node(node_id).kind().span();
    for ancestor in nodes.ancestors(node_id) {
        match ancestor.kind() {
            AstKind::AssignmentExpression(assignment) => {
                return matches!(
                    assignment.operator,
                    AssignmentOperator::Assign
                        | AssignmentOperator::LogicalAnd
                        | AssignmentOperator::LogicalOr
                        | AssignmentOperator::LogicalNullish
                ) && assignment.left.span().contains_inclusive(span);
            }
            AstKind::ExpressionStatement(_) | AstKind::VariableDeclarator(_) => break,
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn empty_array_construction_and_mutation_are_not_noops() {
        // commander.js@ba6d13ddb4243e5913367734f8c159089ffe7834
        // lib/command.js:2325 constructs usage text via [].concat(...).join().
        let source = "const usage = [].concat('[options]', args).join(' ');\n                      [].push(value);\n                      [].unshift(value);\n                      [].splice(0, 0, value);\n                      const iterator = [][Symbol.iterator]();\n                      const method = [].map;\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S4158"), 0);
        assert_eq!(count_key(&ts_keys(source), "typescript:S4158"), 0);
    }

    #[test]
    fn scoped_empty_collection_reads_are_reported() {
        let source =
            "export function inspect() { const items = []; items.map(transform); items[0]; }\n";
        let report = js(source);
        let issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.rule_key == "javascript:S4158")
            .collect();
        assert_eq!(issues.len(), 2);
        for issue in issues {
            assert_eq!(
                issue.message,
                "Review this usage of \"items\" as it can only be empty here."
            );
            assert_eq!(issue.range.end.column - issue.range.start.column, 5);
        }
    }

    #[test]
    fn collection_constructors_reassignments_and_iteration_preserve_scope() {
        let source = "export {}; const map = new Map(); map.get(key); const set = Set(); set.has(value); let items; items = []; items.map(f); for (const item of items) consume(item); for (const key in items) consume(key);";
        assert_eq!(count_key(&js_keys(source), "javascript:S4158"), 5);
        assert_eq!(count_key(&ts_keys(source), "typescript:S4158"), 5);
        let shadowed =
            "export {}; const items = []; function nested(items) { items.push(1); } items.map(f);";
        assert_eq!(count_key(&js_keys(shadowed), "javascript:S4158"), 1);
    }

    #[test]
    fn mutation_escape_and_unknown_uses_invalidate_all_reads() {
        for source in [
            "const items = []; items.map(f); items.push(1);",
            "const items = []; items.map(f); items[0] = 1;",
            "const items = []; items.map(f); [items[0]] = input;",
            "const items = []; items.map(f); items[0] ||= 1;",
            "const items = []; items.map(f); items.length = 1;",
            "let items = []; items.map(f); items = [1];",
            "let items = []; items.map(f); items = external;",
            "const items = []; items.map(f); consume(items);",
            "const items = []; items.map(f); const alias = items;",
            "const items = []; items.map(f); const method = items.map;",
            "function inspect(items) { items.map(f); }",
            "const items = [1]; items.map(f);",
            "const items = new Array(1); items.map(f);",
        ] {
            assert_eq!(
                count_key(&js_keys(source), "javascript:S4158"),
                0,
                "{source}"
            );
            assert_eq!(
                count_key(&ts_keys(source), "typescript:S4158"),
                0,
                "{source}"
            );
        }
    }

    #[test]
    fn empty_array_noop_operations_still_report() {
        let source = "export {}; const items = []; items.map(transform); items.filter(predicate); items.forEach(visit); items.reduce(sum, 0); items[0];\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S4158"), 5);
        assert_eq!(count_key(&ts_keys(source), "typescript:S4158"), 5);
    }
}
