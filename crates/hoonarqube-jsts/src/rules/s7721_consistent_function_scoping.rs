// Rule module s7721_consistent_function_scoping (generated).
//
// `javascript:S7721` + `typescript:S7721` — decoration of
// eslint-plugin-unicorn `consistent-function-scoping` (v65.0.1, wrapped by
// SonarJS S7721 with the SonarJS default `{checkArrowFunctions: false}`, so
// arrow functions stay silent). A named function declaration or function
// expression is reported with "Move function 'X' to the outer scope." when
// its (normalized) parent scope is an inner function scope and the function
// captures nothing from exactly that scope:
//
// - the parent chain is normalized like the reference: `var f = function
//   ...` climbs from the declarator through the declaration, and a
//   function-body block climbs to its owner;
// - functions passed directly as call arguments are never reported (the
//   reference's `scopeManager.acquire` resolves call positions to nothing),
//   and neither are top-level functions (global parent scope), functions
//   inside IIFEs, callbacks of React hooks, or functions inside a
//   `jest.mock` factory argument;
// - functions that directly contain a JSX element are exempt (the
//   reference marks the innermost function enclosing each JSX node);
// - the capture check is the reference's `checkReferences`: a variable
//   referenced inside the candidate's scope subtree blocks the report when
//   it is also referenced from the parent scope, or when it is declared in
//   exactly the parent scope — except the candidate's own function name
//   (the reference's recursive-name skip). Unresolved (global) references
//   and declarations of any other scope never block;
// - the anchor is the function head (`function` keyword through the
//   parameter list closing paren), with the variable name for `var f =
//   function ...` shapes.
//
// The jest/vitest families and arrow candidates of the reference rule are
// out of this oracle-pinned subset and stay silent.
//
// SonarJS reports the rule with scope MAIN: test files (the pinned server's
// filename-based classification, shared with the analyzer's other rules)
// stay silent.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, binding_identifier_name, is_test_file};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{Expression, FunctionType};
use oxc_ast_visit::{Visit, walk};
use oxc_semantic::{NodeId, ScopeId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};
use oxc_syntax::scope::ScopeFlags;
use std::collections::{HashMap as FxHashMap, HashSet as FxHashSet};

/// React hook names whose callbacks are exempt, per the reference list
/// (`useState` … `useDebugValue`, each also as `React.<hook>`).
const REACT_HOOKS: [&str; 20] = [
    "useState",
    "useEffect",
    "useContext",
    "useReducer",
    "useCallback",
    "useMemo",
    "useRef",
    "useImperativeHandle",
    "useLayoutEffect",
    "useDebugValue",
    "React.useState",
    "React.useEffect",
    "React.useContext",
    "React.useReducer",
    "React.useCallback",
    "React.useMemo",
    "React.useRef",
    "React.useImperativeHandle",
    "React.useLayoutEffect",
    "React.useDebugValue",
];

/// Entry point: `javascript:S7721` + `typescript:S7721`
/// consistent-function-scoping check over the parsed program.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    if is_test_file(ctx.path) {
        // Scope MAIN: the pinned server classifies by filename.
        return Vec::new();
    }
    let Some(semantic) = ctx.semantic else {
        return Vec::new();
    };
    let mut analyzer = ScopeAnalyzer::new(ctx, semantic);
    analyzer.collect_candidates();
    analyzer.resolve_captures();
    analyzer.into_issues()
}

struct Candidate {
    parent_scope: ScopeId,
    name: Option<String>,
    /// Span of the candidate's own `id` binding, used for the reference's
    /// recursive-name skip.
    name_span: Option<Span>,
    head: Span,
}

struct ScopeAnalyzer<'a, 'ctx> {
    ctx: &'ctx AnalysisContext<'a>,
    semantic: &'a Semantic<'a>,
    /// Scope owned by each AST node (scope-owning nodes only); this is the
    /// reference's `scopeManager.acquire(node)`.
    scope_by_owner: FxHashMap<NodeId, ScopeId>,
    /// Spans of the innermost functions containing a JSX node (the
    /// reference's function-stack JSX marker).
    jsx_function_spans: FxHashSet<Span>,
    candidates: Vec<Candidate>,
    by_scope: FxHashMap<ScopeId, usize>,
    captured: FxHashSet<usize>,
    /// Origin scopes of every resolved reference, keyed by symbol — the
    /// reference's `variable.references` `from` set.
    reference_scopes: FxHashMap<SymbolId, Vec<ScopeId>>,
}

impl<'a, 'ctx> ScopeAnalyzer<'a, 'ctx> {
    fn new(ctx: &'ctx AnalysisContext<'a>, semantic: &'a Semantic<'a>) -> Self {
        let scoping = semantic.scoping();
        let mut scope_by_owner = FxHashMap::default();
        for scope_id in scoping.scope_descendants_from_root() {
            scope_by_owner.insert(scoping.get_node_id(scope_id), scope_id);
        }
        Self {
            ctx,
            semantic,
            scope_by_owner,
            jsx_function_spans: collect_jsx_function_spans(ctx.program),
            candidates: Vec::new(),
            by_scope: FxHashMap::default(),
            captured: FxHashSet::default(),
            reference_scopes: FxHashMap::default(),
        }
    }

    fn collect_candidates(&mut self) {
        let nodes = self.semantic.nodes();
        for node in nodes.iter() {
            let AstKind::Function(function) = node.kind() else {
                continue;
            };
            if !matches!(
                function.r#type,
                FunctionType::FunctionDeclaration | FunctionType::FunctionExpression
            ) {
                continue;
            }
            let candidate_id = node.id();
            // The reference marks only the innermost function containing a
            // JSX node; nested functions inside it stay eligible.
            if self.jsx_function_spans.contains(&function.span) {
                continue;
            }
            // `isInsideJestMockFactory` walks the whole ancestor chain.
            if self.is_inside_jest_mock_factory(candidate_id) {
                continue;
            }
            let Some((parent_id, name)) = self.normalized_parent(candidate_id, function) else {
                continue;
            };
            let Some(&parent_scope) = self.scope_by_owner.get(&parent_id) else {
                // `acquire` resolves nothing for statement parents such as
                // call arguments, bare blocks, and assignment expressions.
                continue;
            };
            if matches!(nodes.kind(parent_id), AstKind::Program(_))
                || self.is_react_hook_scope(parent_scope)
                || self.is_iife(parent_id)
            {
                continue;
            }
            let scope = self.scope_by_owner[&candidate_id];
            let index = self.candidates.len();
            self.candidates.push(Candidate {
                parent_scope,
                name,
                name_span: function.id.as_ref().map(|id| id.span),
                head: Span::new(function.span.start, function.params.span.end),
            });
            self.by_scope.insert(scope, index);
        }
    }

    /// Reference parent normalization: climb from the candidate through
    /// variable declarators/declarations and the function-body block, then
    /// return the normalized parent node and the reported function name.
    fn normalized_parent(
        &self,
        candidate_id: NodeId,
        function: &oxc_ast::ast::Function<'a>,
    ) -> Option<(NodeId, Option<String>)> {
        let nodes = self.semantic.nodes();
        let mut parent_id = nodes.parent_id(candidate_id);
        if parent_id == candidate_id {
            return None;
        }
        let mut name = None;
        if let AstKind::VariableDeclarator(declarator) = nodes.kind(parent_id) {
            name = binding_identifier_name(&declarator.id).map(str::to_string);
            parent_id = nodes.parent_id(parent_id);
        }
        if matches!(nodes.kind(parent_id), AstKind::VariableDeclaration(_)) {
            parent_id = nodes.parent_id(parent_id);
        }
        // OXC models the function body as `FunctionBody`, the counterpart of
        // the reference's `BlockStatement` climb.
        if matches!(
            nodes.kind(parent_id),
            AstKind::FunctionBody(_) | AstKind::BlockStatement(_)
        ) {
            parent_id = nodes.parent_id(parent_id);
        }
        if name.is_none() {
            name = function.id.as_ref().map(|id| id.name.to_string());
        }
        Some((parent_id, name))
    }

    /// `isInsideJestMockFactory`: any ancestor call `jest.mock(_, fn)` where
    /// the function is the second argument exempts the candidate.
    fn is_inside_jest_mock_factory(&self, candidate_id: NodeId) -> bool {
        let nodes = self.semantic.nodes();
        let mut current = candidate_id;
        loop {
            let parent = nodes.parent_id(current);
            if parent == current {
                return false;
            }
            if let AstKind::CallExpression(call) = nodes.kind(parent) {
                let is_second_argument = call
                    .arguments
                    .get(1)
                    .and_then(|argument| argument.as_expression())
                    .is_some_and(|expression| expression.span() == nodes.kind(current).span());
                if is_second_argument && dotted_path(&call.callee).as_deref() == Some("jest.mock") {
                    return true;
                }
            }
            current = parent;
        }
    }

    /// `isReactHook`: the parent scope's owner is a function passed to a
    /// React hook call.
    fn is_react_hook_scope(&self, parent_scope: ScopeId) -> bool {
        let scoping = self.semantic.scoping();
        let owner = scoping.get_node_id(parent_scope);
        let nodes = self.semantic.nodes();
        if !matches!(
            nodes.kind(owner),
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        ) {
            return false;
        }
        match nodes.parent_kind(owner) {
            AstKind::CallExpression(call) => {
                dotted_path(&call.callee).is_some_and(|path| REACT_HOOKS.contains(&path.as_str()))
            }
            _ => false,
        }
    }

    /// `isIife`: the normalized parent is a function expression invoked
    /// immediately (`(function () { ... })()`).
    fn is_iife(&self, parent_id: NodeId) -> bool {
        let nodes = self.semantic.nodes();
        if !matches!(
            nodes.kind(parent_id),
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        ) {
            return false;
        }
        // The reference compares `parent.callee === node`; this parser
        // preserves parentheses, so climb through them first.
        let mut ancestor = nodes.parent_id(parent_id);
        while matches!(nodes.kind(ancestor), AstKind::ParenthesizedExpression(_)) {
            ancestor = nodes.parent_id(ancestor);
        }
        match nodes.kind(ancestor) {
            AstKind::CallExpression(call) => {
                crate::support::unparenthesized(&call.callee).span() == nodes.kind(parent_id).span()
            }
            _ => false,
        }
    }

    /// The reference capture check (`checkReferences`): for every variable
    /// referenced inside the candidate's scope subtree, a reference from
    /// the parent scope blocks the report, and so does a declaration in
    /// exactly the parent scope.
    fn resolve_captures(&mut self) {
        let scoping = self.semantic.scoping();
        let nodes = self.semantic.nodes();
        // First pass: record every resolved reference's origin scope so the
        // `hitReference` "also referenced from the parent scope" check sees
        // the complete set regardless of reference iteration order.
        for symbol_id in scoping.symbol_ids() {
            for reference_id in scoping.get_resolved_reference_ids(symbol_id) {
                let reference = scoping.get_reference(*reference_id);
                let from_scope = nodes.get_node(reference.node_id()).scope_id();
                self.reference_scopes
                    .entry(symbol_id)
                    .or_default()
                    .push(from_scope);
            }
        }
        for symbol_id in scoping.symbol_ids() {
            let declaration_span = nodes.kind(scoping.symbol_declaration(symbol_id)).span();
            for reference_id in scoping.get_resolved_reference_ids(symbol_id) {
                let reference = scoping.get_reference(*reference_id);
                self.check_reference(symbol_id, declaration_span, reference.node_id());
            }
        }
    }

    /// One resolved reference: walk the scope chain from the reference's
    /// scope and mark every enclosing candidate scope whose parent scope
    /// the symbol escapes into.
    fn check_reference(&mut self, symbol_id: SymbolId, declaration_span: Span, node_id: NodeId) {
        let scoping = self.semantic.scoping();
        let mut scope = self.semantic.nodes().get_node(node_id).scope_id();
        loop {
            self.check_scope(scope, symbol_id, declaration_span);
            match scoping.scope_parent_id(scope) {
                Some(parent) => scope = parent,
                None => break,
            }
        }
    }

    /// The reference's `isSameScope`: identical scopes, or scopes owned by
    /// the same AST node (`scope1.block === scope2.block`).
    fn same_scope(&self, left: ScopeId, right: ScopeId) -> bool {
        left == right
            || self.semantic.scoping().get_node_id(left)
                == self.semantic.scoping().get_node_id(right)
    }

    /// `hitReference` for one scope on the walk: the symbol is also
    /// referenced from the parent scope itself, or it is declared in
    /// exactly the parent scope — unless it is the candidate's own
    /// function name (the recursive-name skip).
    fn check_scope(&mut self, scope: ScopeId, symbol_id: SymbolId, declaration_span: Span) {
        let Some(&candidate_index) = self.by_scope.get(&scope) else {
            return;
        };
        let candidate = &self.candidates[candidate_index];
        if self
            .reference_scopes
            .get(&symbol_id)
            .is_some_and(|from_scopes| {
                from_scopes
                    .iter()
                    .any(|&from| self.same_scope(from, candidate.parent_scope))
            })
        {
            self.captured.insert(candidate_index);
        }
        if self.same_scope(
            self.semantic.scoping().symbol_scope_id(symbol_id),
            candidate.parent_scope,
        ) && candidate.name_span != Some(declaration_span)
        {
            self.captured.insert(candidate_index);
        }
    }

    fn into_issues(self) -> Vec<Issue> {
        let mut sink = IssueSink {
            index: self.ctx.index,
            language: self.ctx.language,
            issues: Vec::new(),
        };
        for (index, candidate) in self.candidates.iter().enumerate() {
            if self.captured.contains(&index) {
                continue;
            }
            let message = match &candidate.name {
                Some(name) => format!("Move function '{name}' to the outer scope."),
                None => "Move function to the outer scope.".to_string(),
            };
            sink.emit_span(RuleScope::Both, "S7721", &message, candidate.head);
        }
        sink.issues
    }
}

/// Dotted path of a plain identifier/member receiver, or `None` when any
/// segment is computed, optional, or not a plain member chain (the
/// reference's `isNodeMatches`).
fn dotted_path(expression: &Expression<'_>) -> Option<String> {
    match expression {
        Expression::Identifier(identifier) => Some(identifier.name.to_string()),
        Expression::StaticMemberExpression(member) if !member.optional => {
            let mut path = dotted_path(&member.object)?;
            path.push('.');
            path.push_str(member.property.name.as_str());
            Some(path)
        }
        _ => None,
    }
}

/// Collects the spans of the innermost functions containing a JSX element
/// or fragment, mirroring the reference's function-stack JSX marker.
fn collect_jsx_function_spans(program: &oxc_ast::ast::Program<'_>) -> FxHashSet<Span> {
    struct JsxFunctionCollector {
        stack: Vec<Span>,
        spans: FxHashSet<Span>,
    }

    impl<'a> Visit<'a> for JsxFunctionCollector {
        fn visit_function(&mut self, function: &oxc_ast::ast::Function<'a>, flags: ScopeFlags) {
            self.stack.push(function.span);
            walk::walk_function(self, function, flags);
        }

        fn visit_arrow_function_expression(
            &mut self,
            arrow: &oxc_ast::ast::ArrowFunctionExpression<'a>,
        ) {
            self.stack.push(arrow.span);
            walk::walk_arrow_function_expression(self, arrow);
        }

        fn visit_jsx_element(&mut self, element: &oxc_ast::ast::JSXElement<'a>) {
            if let Some(span) = self.stack.last() {
                self.spans.insert(*span);
            }
            walk::walk_jsx_element(self, element);
        }

        fn visit_jsx_fragment(&mut self, fragment: &oxc_ast::ast::JSXFragment<'a>) {
            if let Some(span) = self.stack.last() {
                self.spans.insert(*span);
            }
            walk::walk_jsx_fragment(self, fragment);
        }

        fn leave_node(&mut self, kind: AstKind<'a>) {
            if matches!(
                kind,
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
            ) {
                self.stack.pop();
            }
        }
    }

    let mut collector = JsxFunctionCollector {
        stack: Vec::new(),
        spans: FxHashSet::default(),
    };
    collector.visit_program(program);
    collector.spans
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7721_flags_pinned_express_test_function_sites() {
        // Pinned oracle: express@3ce6d0e test/app.render.js:64
        // `function View(name, options){...}` and test/Router.js:94
        // `var handler = function (req, res) {...}`, both nested in `it`
        // callbacks and capturing nothing from them.
        let source = "\
var express = require('express');
it('render', function(done){
  var app = express();
  function View(name, options){
    this.name = name;
  }
  View.prototype.render = function(options, fn){ throw new Error('err!'); };
  app.render('email', function(err){ done(err); });
});
it('routes', function(done){
  var handler = function (req, res) { res.end(new Error('wrong handler')); };
  done(handler);
});
";
        let findings = js_keys(source);
        assert_eq!(count_key(&findings, "javascript:S7721"), 2);
        let report = js(source);
        let messages = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7721")
            .map(|issue| issue.message.clone())
            .collect::<Vec<_>>();
        assert!(messages.contains(&"Move function 'View' to the outer scope.".to_string()));
        assert!(messages.contains(&"Move function 'handler' to the outer scope.".to_string()));
        let view = report
            .issues
            .iter()
            .find(|issue| issue.message.contains("'View'"))
            .expect("View finding must exist");
        assert_eq!(view.range.start.line, 4);
        assert_eq!(view.range.start.column, 2);
    }

    #[test]
    fn s7721_flags_exceljs_nested_helpers_with_own_scope_names() {
        // Pinned oracle: exceljs@5bed18b worksheet-xform.js:154 `nextRid` and
        // pivot-cache-records-xform.js:54 `renderCell` — nested helpers that
        // capture nothing from the enclosing function.
        let source = "\
function build() {
  const sheet = {};
  function nextRid() {
    return Object.keys(sheet).length + 1;
  }
  function renderCell(cell) {
    return cell.value;
  }
  return nextRid() + renderCell({});
}
";
        let findings = js_keys(source);
        // `nextRid` captures `sheet` from the parent scope and stays silent;
        // `renderCell` captures nothing and is reported.
        assert_eq!(count_key(&findings, "javascript:S7721"), 1);
        let report = js(source);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S7721")
            .expect("renderCell must be reported");
        assert_eq!(
            issue.message,
            "Move function 'renderCell' to the outer scope."
        );
    }

    #[test]
    fn s7721_stays_silent_for_capturing_and_top_level_functions() {
        let silent = "\
function top() { return 1; }
function outer() {
  var used = 2;
  function inner() { return used; }
  function sibling() { return helper(); }
  function helper() { return 3; }
  return inner() + sibling();
}
var assigned = function uses(used2) { return outerFn(used2); };
";
        let findings = js_keys(silent);
        // `inner` captures `used`; `sibling` captures sibling `helper`
        // (declared in the parent scope); `helper` itself captures nothing
        // and is reported like the reference; `uses` is top-level.
        assert_eq!(count_key(&findings, "javascript:S7721"), 1);
        let report = js(silent);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S7721")
            .expect("helper must be reported");
        assert_eq!(issue.message, "Move function 'helper' to the outer scope.");
    }

    #[test]
    fn s7721_stays_silent_for_call_argument_callbacks_like_reference() {
        let silent = "\
describe('suite', function () {
  it('passes', function (done) {
    done();
  });
  it('uses jest mock', function () {
    jest.mock('dep', function factory() {
      function helper() { return 1; }
      return helper();
    });
  });
});
";
        // The `it` callbacks are call arguments; `factory` and its nested
        // `helper` are inside the `jest.mock` factory argument.
        assert_eq!(count_key(&js_keys(silent), "javascript:S7721"), 0);
    }

    #[test]
    fn s7721_stays_silent_for_iife_bare_block_and_react_hook_parents() {
        let silent = "\
(function () {
  function inside() { return 1; }
  return inside();
})();
function outer() {
  {
    function blocked() { return 2; }
    blocked();
  }
}
useEffect(function () {
  function hookHelper() { return 3; }
  hookHelper();
});
";
        assert_eq!(count_key(&js_keys(silent), "javascript:S7721"), 0);
    }

    #[test]
    fn s7721_stays_silent_for_jsx_containing_functions() {
        let source = "\
function outer() {
  function render() { return <div />; }
  function inner() { return 1; }
  return render() + inner();
}
";
        let report = jsx(source);
        let issues = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7721")
            .collect::<Vec<_>>();
        // `render` directly contains JSX and is exempt; `inner` is not the
        // innermost JSX function and stays reportable.
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].message,
            "Move function 'inner' to the outer scope."
        );
    }

    #[test]
    fn s7721_also_fires_for_typescript_files() {
        let source = "function outer() { function inner() { return 1; } return inner(); }\n";
        let report = crate::analyze(
            PathBuf::from("src/helpers.ts"),
            source,
            crate::JstsLanguage::TypeScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&report), "typescript:S7721"), 1);
    }

    #[test]
    fn s7721_stays_silent_in_test_files_like_reference_main_scope() {
        let source = "function outer() { function inner() { return 1; } return inner(); }\n";
        let test_report = crate::analyze(
            PathBuf::from("spec/unit/doc/range.spec.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&test_report), "javascript:S7721"), 0);
        let main_report = crate::analyze(
            PathBuf::from("test/app.use.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&main_report), "javascript:S7721"), 1);
    }
}
