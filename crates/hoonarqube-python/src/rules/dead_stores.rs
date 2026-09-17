use crate::AnalyzerOptions;
use crate::engine::scope::BindingKind;
use crate::engine::scope::FileFacts;
use crate::engine::scope::ScopeKind;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::scope_has_dynamic_declaration;
use crate::engine::scope::suite_range;
use crate::support::child_bodies;
use crate::support::for_each_expr;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use crate::support::unused_name_matches_pattern;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_ast::StmtIf;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;
use std::collections::HashMap;
use std::collections::HashSet;

// --- python:S1854 — dead stores ----------------------------------------------
//
// Per scope (module or function), a miniature control-flow graph of store and
// load events is built and solved with backward may-liveness. A store is dead
// exactly when the name is not live after it: no path reaches a load of the
// name before another store. This reports the classic final dead store and
// also first stores overwritten on every branch before the later read.

pub(crate) fn check_dead_stores(
    parsed: &Parsed<ModModule>,
    table: &SymbolTable,
    facts: &FileFacts,
    options: &AnalyzerOptions,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    if facts.dynamic_names {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for (scope_idx, suite) in scope_regions(parsed, table) {
        let flow = FlowBuilder::new(table, scope_idx).build(suite);
        for (name, range) in flow.dead_stores() {
            if is_reportable(table, scope_idx, &name, range, options)
                && !is_sentinel_assignment(suite, range)
            {
                let issue = issue_at(
                    "python:S1854",
                    &format!("Remove this useless assignment to local variable '{name}'."),
                    range,
                    index,
                    source,
                );
                let alternatives = crate::quickfix::bindings::alternatives_s1854(
                    parsed, index, source, table, facts, &issue,
                );
                let issue = alternatives.into_iter().fold(issue, |issue, alternative| {
                    issue.with_alternative(
                        alternative.id,
                        alternative.fix.message,
                        alternative.fix.edits,
                    )
                });
                issues.push(issue);
            }
        }
    }
    issues
}

/// Shared gates with the previous binding-based rule: underscore and ignore
/// patterns stay exempt, `global`/`nonlocal` declarations stay exempt, every
/// binding of the name must be a plain assignment (imports, parameters,
/// definitions, and except aliases keep the name out of scope), stores inside
/// loops are exempt, and names never loaded anywhere in the scope belong to
/// the unused-variable rule instead of this one. Loop depth comes from the
/// symbol table binding that owns the store range.
fn is_reportable(
    table: &SymbolTable,
    scope_idx: usize,
    name: &str,
    range: TextRange,
    options: &AnalyzerOptions,
) -> bool {
    if name.starts_with('_')
        || unused_name_matches_pattern(name, &options.unused_local_ignore_pattern)
    {
        return false;
    }
    let scope = &table.scopes[scope_idx];
    if scope_has_dynamic_declaration(scope, name) {
        return false;
    }
    let Some(bindings) = scope.bindings.get(name) else {
        return false;
    };
    if bindings
        .iter()
        .any(|binding| binding.kind != BindingKind::Assignment)
    {
        return false;
    }
    let Some(binding) = bindings.iter().find(|binding| binding.range == range) else {
        return false;
    };
    binding.loop_depth == 0
        && table
            .resolved_loads
            .iter()
            .any(|load| load.target == Some(scope_idx) && load.name == name)
        && !table.resolved_loads.iter().any(|load| {
            // A load from a nested function scope keeps the store live:
            // the reference's isUsedInSubFunction exemption.
            load.target == Some(scope_idx) && load.name == name && load.scope != scope_idx
        })
}

/// The reference exempts assignments of falsy literals, `True`, `1`, and
/// `-1` (sentinel initializations like `y = None` before a `try`).
fn is_sentinel_assignment(suite: &[Stmt], range: TextRange) -> bool {
    let mut found = false;
    crate::support::for_each_stmt(suite, &mut |stmt| {
        let value: Option<&Expr> = match stmt {
            Stmt::Assign(assign) if assign
                .targets
                .iter()
                .any(|target| target.range() == range) =>
            {
                Some(assign.value.as_ref())
            }
            Stmt::AnnAssign(assign) if assign.target.range() == range => {
                assign.value.as_deref()
            }
            _ => None,
        };
        if let Some(value) = value {
            found |= crate::support::constant_truth(value) == Some(false)
                || matches!(value, Expr::Name(name) if name.id.as_str() == "True")
                || matches!(value, Expr::NumberLiteral(n) if matches!(&n.value, ruff_python_ast::Number::Int(i) if i.as_i64() == Some(1)))
                || matches!(value, Expr::UnaryOp(u) if u.op == ruff_python_ast::UnaryOp::USub
                    && matches!(u.operand.as_ref(), Expr::NumberLiteral(n) if matches!(&n.value, ruff_python_ast::Number::Int(i) if i.as_i64() == Some(1))));
        }
    });
    found
}

/// Pairs every module/function scope with its own statement suite.
fn scope_regions<'a>(
    parsed: &'a Parsed<ModModule>,
    table: &SymbolTable,
) -> Vec<(usize, &'a [Stmt])> {
    let mut body_ranges: HashMap<TextRange, usize> = HashMap::new();
    for (idx, scope) in table.scopes.iter().enumerate() {
        if matches!(scope.kind, ScopeKind::Function)
            && let Some(range) = scope.body_range
        {
            body_ranges.insert(range, idx);
        }
    }
    let mut found = Vec::new();
    collect_regions(parsed.syntax().body.as_slice(), &body_ranges, &mut found);
    found
}

fn collect_regions<'a>(
    suite: &'a [Stmt],
    body_ranges: &HashMap<TextRange, usize>,
    found: &mut Vec<(usize, &'a [Stmt])>,
) {
    for stmt in suite {
        if let Stmt::FunctionDef(function) = stmt
            && let Some(&idx) = body_ranges.get(&suite_range(&function.body))
        {
            found.push((idx, function.body.as_ref()));
        }
        for body in child_bodies(stmt) {
            collect_regions(body, body_ranges, found);
        }
    }
}

enum Event {
    Load(String),
    Store { name: String, range: TextRange },
}

#[derive(Default)]
struct Block {
    events: Vec<Event>,
    succs: Vec<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Term {
    Return,
    Raise,
    Break,
    Continue,
}

struct SuiteExit {
    exit: Option<usize>,
    terminals: Vec<(usize, Term)>,
}

struct LoopContext {
    break_target: usize,
    continue_target: usize,
}

struct FlowBuilder<'a> {
    table: &'a SymbolTable,
    scope_idx: usize,
    blocks: Vec<Block>,
    loops: Vec<LoopContext>,
    live_in: Vec<HashSet<String>>,
    live_out: Vec<HashSet<String>>,
}

impl<'a> FlowBuilder<'a> {
    fn new(table: &'a SymbolTable, scope_idx: usize) -> Self {
        Self {
            table,
            scope_idx,
            blocks: vec![Block::default()],
            loops: Vec::new(),
            live_in: Vec::new(),
            live_out: Vec::new(),
        }
    }

    fn build(mut self, suite: &[Stmt]) -> Self {
        self.build_suite(suite, 0);
        self
    }

    fn new_block(&mut self) -> usize {
        self.blocks.push(Block::default());
        self.blocks.len() - 1
    }

    fn edge(&mut self, from: usize, to: usize) {
        if !self.blocks[from].succs.contains(&to) {
            self.blocks[from].succs.push(to);
        }
    }

    /// Joins branch exits; `None` when every branch terminated.
    fn join(&mut self, exits: Vec<usize>) -> Option<usize> {
        if exits.is_empty() {
            return None;
        }
        let join = self.new_block();
        for exit in exits {
            self.edge(exit, join);
        }
        Some(join)
    }

    fn build_suite(&mut self, suite: &[Stmt], entry: usize) -> SuiteExit {
        self.build_suite_inner(suite, entry, false)
    }

    /// Per-statement blocks: used for `try` bodies so the exception edge
    /// leaves before each statement's stores (a statement that raises never
    /// performs its store, so earlier stores stay live into handlers).
    fn build_suite_atomic(&mut self, suite: &[Stmt], entry: usize) -> SuiteExit {
        self.build_suite_inner(suite, entry, true)
    }

    fn build_suite_inner(&mut self, suite: &[Stmt], entry: usize, atomic: bool) -> SuiteExit {
        let mut current = Some(entry);
        let mut terminals = Vec::new();
        for stmt in suite {
            if atomic && let Some(block) = current {
                let fresh = self.new_block();
                self.edge(block, fresh);
                current = Some(fresh);
            }
            let Some(block) = current else { break };
            if let Some(term) = self.terminator_events(stmt, block) {
                terminals.push((block, term));
                current = None;
                continue;
            }
            match stmt {
                Stmt::If(if_stmt) => {
                    let (exit, branch_terminals) = self.build_if(if_stmt, block);
                    current = exit;
                    terminals.extend(branch_terminals);
                }
                Stmt::While(while_stmt) => {
                    let (exit, loop_terminals) = self.build_loop(
                        |builder, header| builder.expr_events(header, &while_stmt.test),
                        &while_stmt.body,
                        &while_stmt.orelse,
                        block,
                    );
                    current = exit;
                    terminals.extend(loop_terminals);
                }
                Stmt::For(for_stmt) => {
                    let (exit, loop_terminals) = self.build_loop(
                        |builder, header| {
                            builder.expr_events(header, &for_stmt.iter);
                            builder.store_target_events(header, &for_stmt.target);
                        },
                        &for_stmt.body,
                        &for_stmt.orelse,
                        block,
                    );
                    current = exit;
                    terminals.extend(loop_terminals);
                }
                Stmt::With(with_stmt) => {
                    for item in &with_stmt.items {
                        self.expr_events(block, &item.context_expr);
                        if let Some(vars) = item.optional_vars.as_deref() {
                            self.store_target_events(block, vars);
                        }
                    }
                    let result = self.build_suite(&with_stmt.body, block);
                    current = result.exit;
                    terminals.extend(result.terminals);
                }
                Stmt::Match(match_stmt) => {
                    let (exit, case_terminals) = self.build_match(match_stmt, block);
                    current = exit;
                    terminals.extend(case_terminals);
                }
                Stmt::Try(try_stmt) => {
                    let (exit, try_terminals) = self.build_try(try_stmt, block);
                    current = exit;
                    terminals.extend(try_terminals);
                }
                _ => self.simple_statement_events(stmt, block),
            }
        }
        SuiteExit {
            exit: current,
            terminals,
        }
    }

    /// Emits events for a terminator statement; `Some(term)` when it ends the
    /// flow through its block.
    fn terminator_events(&mut self, stmt: &Stmt, block: usize) -> Option<Term> {
        match stmt {
            Stmt::Return(s) => {
                if let Some(value) = s.value.as_deref() {
                    self.expr_events(block, value);
                }
                Some(Term::Return)
            }
            Stmt::Raise(s) => {
                if let Some(exc) = s.exc.as_deref() {
                    self.expr_events(block, exc);
                }
                if let Some(cause) = s.cause.as_deref() {
                    self.expr_events(block, cause);
                }
                Some(Term::Raise)
            }
            Stmt::Break(_) => Some(Term::Break),
            Stmt::Continue(_) => Some(Term::Continue),
            _ => None,
        }
    }

    /// Non-structural statements: plain event extraction, flow continues.
    fn simple_statement_events(&mut self, stmt: &Stmt, block: usize) {
        match stmt {
            Stmt::FunctionDef(function) => {
                self.definition_load_events(block, function.body.as_ref());
            }
            Stmt::ClassDef(class) => {
                self.definition_load_events(block, class.body.as_ref());
            }
            Stmt::TypeAlias(type_alias) => {
                self.store_target_events(block, &type_alias.name);
                for expr in stmt_exprs(stmt) {
                    self.expr_events(block, expr);
                }
            }
            Stmt::Assign(assign) => {
                self.expr_events(block, &assign.value);
                for target in &assign.targets {
                    self.store_target_events(block, target);
                }
            }
            Stmt::AnnAssign(assignment) => {
                self.expr_events(block, &assignment.annotation);
                if let Some(value) = assignment.value.as_deref() {
                    self.expr_events(block, value);
                }
                self.store_target_events(block, &assignment.target);
            }
            Stmt::AugAssign(assignment) => {
                if let Expr::Name(name) = assignment.target.as_ref() {
                    self.push_load(block, name.id.as_str());
                    self.push_store(block, name.id.as_str(), name.range());
                } else {
                    self.expr_events(block, &assignment.target);
                }
            }
            _ => {
                for expr in stmt_exprs(stmt) {
                    self.expr_events(block, expr);
                }
            }
        }
    }

    fn build_if(&mut self, if_stmt: &StmtIf, block: usize) -> (Option<usize>, Vec<(usize, Term)>) {
        self.expr_events(block, &if_stmt.test);
        let mut exits = Vec::new();
        let mut terminals = Vec::new();
        let then_entry = self.new_block();
        self.edge(block, then_entry);
        let then_exit = self.build_suite(&if_stmt.body, then_entry);
        if let Some(exit) = then_exit.exit {
            exits.push(exit);
        }
        terminals.extend(then_exit.terminals);
        let mut false_chain = block;
        let mut has_else = false;
        for clause in &if_stmt.elif_else_clauses {
            let clause_entry = self.new_block();
            if let Some(test) = clause.test.as_ref() {
                self.edge(false_chain, clause_entry);
                self.expr_events(clause_entry, test);
                let body_entry = self.new_block();
                self.edge(clause_entry, body_entry);
                let body_exit = self.build_suite(&clause.body, body_entry);
                false_chain = clause_entry;
                if let Some(exit) = body_exit.exit {
                    exits.push(exit);
                }
                terminals.extend(body_exit.terminals);
            } else {
                has_else = true;
                self.edge(false_chain, clause_entry);
                let body_exit = self.build_suite(&clause.body, clause_entry);
                if let Some(exit) = body_exit.exit {
                    exits.push(exit);
                }
                terminals.extend(body_exit.terminals);
            }
        }
        if !has_else {
            exits.push(false_chain);
        }
        (self.join(exits), terminals)
    }

    fn build_loop(
        &mut self,
        header_events: impl FnOnce(&mut Self, usize),
        body: &[Stmt],
        orelse: &[Stmt],
        block: usize,
    ) -> (Option<usize>, Vec<(usize, Term)>) {
        let header = self.new_block();
        self.edge(block, header);
        header_events(self, header);
        let loop_exit = self.new_block();
        self.loops.push(LoopContext {
            break_target: loop_exit,
            continue_target: header,
        });
        let body_entry = self.new_block();
        self.edge(header, body_entry);
        let result = self.build_suite(body, body_entry);
        if let Some(exit) = result.exit {
            self.edge(exit, header);
        }
        let mut loop_terminals = result.terminals;
        if orelse.is_empty() {
            self.edge(header, loop_exit);
        } else {
            let orelse_entry = self.new_block();
            self.edge(header, orelse_entry);
            let result = self.build_suite(orelse, orelse_entry);
            if let Some(exit) = result.exit {
                self.edge(exit, loop_exit);
            } else {
                self.edge(header, loop_exit);
            }
            loop_terminals.extend(result.terminals);
        }
        let loop_context = self.loops.pop();
        if let Some(context) = &loop_context {
            for (blk, term) in &loop_terminals {
                self.route_loop_terminal(*blk, *term, context);
            }
        }
        (Some(loop_exit), Vec::new())
    }

    fn route_loop_terminal(&mut self, blk: usize, term: Term, context: &LoopContext) {
        match term {
            Term::Break => self.edge(blk, context.break_target),
            Term::Continue => self.edge(blk, context.continue_target),
            Term::Return | Term::Raise => {}
        }
    }

    fn build_match(
        &mut self,
        match_stmt: &ruff_python_ast::StmtMatch,
        block: usize,
    ) -> (Option<usize>, Vec<(usize, Term)>) {
        self.expr_events(block, &match_stmt.subject);
        let mut exits = Vec::new();
        let mut terminals = Vec::new();
        let mut false_chain = block;
        for case in &match_stmt.cases {
            let case_entry = self.new_block();
            self.edge(false_chain, case_entry);
            self.pattern_events(case_entry, &case.pattern);
            if let Some(guard) = case.guard.as_deref() {
                self.expr_events(case_entry, guard);
            }
            let result = self.build_suite(&case.body, case_entry);
            if let Some(exit) = result.exit {
                exits.push(exit);
            }
            terminals.extend(result.terminals);
            false_chain = case_entry;
        }
        exits.push(false_chain);
        (self.join(exits), terminals)
    }

    fn build_try(
        &mut self,
        try_stmt: &ruff_python_ast::StmtTry,
        block: usize,
    ) -> (Option<usize>, Vec<(usize, Term)>) {
        let body_entry = self.new_block();
        self.edge(block, body_entry);
        let watermark = self.blocks.len();
        let body_result = self.build_suite_atomic(&try_stmt.body, body_entry);
        let body_region: Vec<usize> = (watermark..self.blocks.len()).collect();

        let (orelse_region, mut pre_finally_exits, mut pre_finally_terminals) =
            self.build_try_orelse(try_stmt, body_result);
        let (handler_exits, handler_terminals) = self.build_try_handlers(try_stmt, &body_region);
        pre_finally_terminals.extend(handler_terminals);
        pre_finally_exits.extend(handler_exits);

        if try_stmt.finalbody.is_empty() {
            return self.finish_try_without_finally(pre_finally_exits, pre_finally_terminals);
        }
        self.finish_try_with_finally(
            try_stmt,
            &orelse_region,
            &pre_finally_exits,
            &pre_finally_terminals,
        )
    }

    /// Builds the `else` suite and collects the normal-flow exits and
    /// terminals entering the handler/finally assembly.
    fn build_try_orelse(
        &mut self,
        try_stmt: &ruff_python_ast::StmtTry,
        body_result: SuiteExit,
    ) -> (Vec<usize>, Vec<usize>, Vec<(usize, Term)>) {
        if try_stmt.orelse.is_empty() {
            let exits = body_result.exit.into_iter().collect();
            return (Vec::new(), exits, body_result.terminals);
        }
        let orelse_entry = self.new_block();
        if let Some(exit) = body_result.exit {
            self.edge(exit, orelse_entry);
        }
        let watermark = self.blocks.len();
        let result = self.build_suite(&try_stmt.orelse, orelse_entry);
        let region: Vec<usize> = (watermark..self.blocks.len()).collect();
        let exits = result.exit.into_iter().collect();
        (region, exits, result.terminals)
    }

    /// Builds the handler chain: exceptions from anywhere in the `try` body
    /// can enter any handler; the previous handler's non-match falls through.
    fn build_try_handlers(
        &mut self,
        try_stmt: &ruff_python_ast::StmtTry,
        body_region: &[usize],
    ) -> (Vec<usize>, Vec<(usize, Term)>) {
        let mut handler_exits = Vec::new();
        let mut handler_terminals = Vec::new();
        let mut prev_false: Option<usize> = None;
        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(handler) = handler;
            let handler_entry = self.new_block();
            for &blk in body_region {
                self.edge(blk, handler_entry);
            }
            if let Some(prev) = prev_false {
                self.edge(prev, handler_entry);
            }
            if let Some(type_expr) = handler.type_.as_deref() {
                self.expr_events(handler_entry, type_expr);
            }
            let result = self.build_suite(&handler.body, handler_entry);
            if let Some(exit) = result.exit {
                handler_exits.push(exit);
            }
            handler_terminals.extend(result.terminals);
            prev_false = Some(handler_entry);
        }
        (handler_exits, handler_terminals)
    }

    /// Without `finally`: break/continue route to their loop targets and the
    /// surviving exits join after the statement.
    fn finish_try_without_finally(
        &mut self,
        exits: Vec<usize>,
        terminals: Vec<(usize, Term)>,
    ) -> (Option<usize>, Vec<(usize, Term)>) {
        for (blk, term) in &terminals {
            if let Some(target) = self.terminal_target(*term) {
                self.edge(*blk, target);
            }
        }
        let propagated: Vec<(usize, Term)> = terminals
            .into_iter()
            .filter(|(_, term)| matches!(term, Term::Return | Term::Raise))
            .collect();
        (self.join(exits), propagated)
    }

    /// With `finally`: every path (normal, handler, exception escape, and
    /// in-body terminators) runs the `finally` suite first.
    fn finish_try_with_finally(
        &mut self,
        try_stmt: &ruff_python_ast::StmtTry,
        orelse_region: &[usize],
        exits: &[usize],
        terminals: &[(usize, Term)],
    ) -> (Option<usize>, Vec<(usize, Term)>) {
        let finally_entry = self.new_block();
        for exit in exits {
            self.edge(*exit, finally_entry);
        }
        for &blk in orelse_region {
            self.edge(blk, finally_entry);
        }
        for (blk, _) in terminals {
            self.edge(*blk, finally_entry);
        }
        let finally_result = self.build_suite(&try_stmt.finalbody, finally_entry);
        match finally_result.exit {
            Some(finally_exit) => {
                let after = self.new_block();
                self.edge(finally_exit, after);
                for (_, term) in terminals {
                    if let Some(target) = self.terminal_target(*term) {
                        self.edge(finally_exit, target);
                    }
                }
                (Some(after), finally_result.terminals)
            }
            None => (None, finally_result.terminals),
        }
    }

    /// Loop target for break/continue terminals; `None` for return/raise.
    fn terminal_target(&self, term: Term) -> Option<usize> {
        let context = self.loops.last()?;
        match term {
            Term::Break => Some(context.break_target),
            Term::Continue => Some(context.continue_target),
            Term::Return | Term::Raise => None,
        }
    }

    /// Loads from closures nested inside a definition: reads of this scope's
    /// names happen whenever the nested definition is called, so they keep
    /// stores before the definition conservatively live.
    fn definition_load_events(&mut self, block: usize, suite: &[Stmt]) {
        let range = suite_range(suite);
        for load in &self.table.resolved_loads {
            if load.target == Some(self.scope_idx)
                && range.contains(load.range.start())
                && range.contains(load.range.end())
            {
                self.push_load(block, &load.name);
            }
        }
    }

    /// Every `Name` load (and `del`) in an expression counts as a use of this
    /// scope. Nested lambdas and comprehensions are folded in conservatively.
    fn expr_events(&mut self, block: usize, expr: &Expr) {
        for_each_expr(expr, &mut |expr| {
            if let Expr::Name(name) = expr
                && matches!(
                    name.ctx,
                    ruff_python_ast::ExprContext::Load | ruff_python_ast::ExprContext::Del
                )
            {
                self.push_load(block, name.id.as_str());
            }
        });
    }

    fn store_target_events(&mut self, block: usize, target: &Expr) {
        match target {
            Expr::Name(name) => self.push_store(block, name.id.as_str(), name.range()),
            Expr::Tuple(tuple) => {
                for element in &tuple.elts {
                    self.store_target_events(block, element);
                }
            }
            Expr::List(list) => {
                for element in &list.elts {
                    self.store_target_events(block, element);
                }
            }
            Expr::Starred(starred) => self.store_target_events(block, &starred.value),
            _ => self.expr_events(block, target),
        }
    }

    /// Match-pattern events: loads from value/class/mapping expressions plus
    /// capture stores, mirroring the symbol table's binding of patterns.
    fn pattern_events(&mut self, block: usize, pattern: &ruff_python_ast::Pattern) {
        match pattern {
            ruff_python_ast::Pattern::MatchValue(value) => self.expr_events(block, &value.value),
            ruff_python_ast::Pattern::MatchSingleton(_) => {}
            ruff_python_ast::Pattern::MatchSequence(sequence) => {
                for element in &sequence.patterns {
                    self.pattern_events(block, element);
                }
            }
            ruff_python_ast::Pattern::MatchMapping(mapping) => {
                self.mapping_pattern_events(block, mapping);
            }
            ruff_python_ast::Pattern::MatchClass(class) => {
                self.class_pattern_events(block, class);
            }
            ruff_python_ast::Pattern::MatchStar(star) => {
                if let Some(name) = &star.name {
                    self.push_store(block, name.as_str(), name.range());
                }
            }
            ruff_python_ast::Pattern::MatchAs(as_pattern) => {
                self.as_pattern_events(block, as_pattern);
            }
            ruff_python_ast::Pattern::MatchOr(or_pattern) => {
                for alternative in &or_pattern.patterns {
                    self.pattern_events(block, alternative);
                }
            }
        }
    }

    fn mapping_pattern_events(
        &mut self,
        block: usize,
        mapping: &ruff_python_ast::PatternMatchMapping,
    ) {
        for key in &mapping.keys {
            self.expr_events(block, key);
        }
        for subpattern in &mapping.patterns {
            self.pattern_events(block, subpattern);
        }
        if let Some(rest) = &mapping.rest {
            self.push_store(block, rest.as_str(), rest.range());
        }
    }

    fn class_pattern_events(&mut self, block: usize, class: &ruff_python_ast::PatternMatchClass) {
        self.expr_events(block, &class.cls);
        for argument in &class.arguments.patterns {
            self.pattern_events(block, argument);
        }
        for keyword in &class.arguments.keywords {
            self.pattern_events(block, &keyword.pattern);
        }
    }

    fn as_pattern_events(&mut self, block: usize, as_pattern: &ruff_python_ast::PatternMatchAs) {
        if let Some(pattern) = as_pattern.pattern.as_deref() {
            self.pattern_events(block, pattern);
        }
        if let Some(name) = &as_pattern.name {
            self.push_store(block, name.as_str(), name.range());
        }
    }

    fn push_load(&mut self, block: usize, name: &str) {
        self.blocks[block]
            .events
            .push(Event::Load(name.to_string()));
    }

    fn push_store(&mut self, block: usize, name: &str, range: TextRange) {
        self.blocks[block].events.push(Event::Store {
            name: name.to_string(),
            range,
        });
    }

    /// Solves backward may-liveness to a fixed point and reports every store
    /// whose name is not live after it.
    fn dead_stores(mut self) -> Vec<(String, TextRange)> {
        let empty = vec![HashSet::new(); self.blocks.len()];
        self.live_in = empty.clone();
        self.live_out = empty;
        self.solve_liveness();
        self.collect_dead()
    }

    /// Iterates the backward transfer function over every block until no
    /// liveness set changes.
    fn solve_liveness(&mut self) {
        let mut changed = true;
        while changed {
            changed = false;
            for b in (0..self.blocks.len()).rev() {
                changed = self.recompute_block(b) || changed;
            }
        }
    }

    /// Recomputes liveness for one block; returns whether anything changed.
    fn recompute_block(&mut self, b: usize) -> bool {
        let mut out: HashSet<String> = HashSet::new();
        for &succ in &self.blocks[b].succs {
            out.extend(self.live_in[succ].iter().cloned());
        }
        let live = self.transfer_backward(b, out.clone());
        if out != self.live_out[b] || live != self.live_in[b] {
            self.live_out[b] = out;
            self.live_in[b] = live;
            true
        } else {
            false
        }
    }

    /// Walks a block's events in reverse: loads generate liveness, stores kill.
    fn transfer_backward(&self, b: usize, mut live: HashSet<String>) -> HashSet<String> {
        for event in self.blocks[b].events.iter().rev() {
            match event {
                Event::Load(name) => {
                    live.insert(name.clone());
                }
                Event::Store { name, .. } => {
                    live.remove(name);
                }
            }
        }
        live
    }

    /// Reports stores whose names are not live immediately after them.
    fn collect_dead(&self) -> Vec<(String, TextRange)> {
        let mut dead = Vec::new();
        for (b, block_live_out) in self.live_out.iter().enumerate() {
            let mut live = block_live_out.clone();
            for event in self.blocks[b].events.iter().rev() {
                match event {
                    Event::Load(name) => {
                        live.insert(name.clone());
                    }
                    Event::Store { name, range } => {
                        if !live.contains(name) {
                            dead.push((name.clone(), *range));
                        }
                        live.remove(name);
                    }
                }
            }
        }
        dead
    }
}
