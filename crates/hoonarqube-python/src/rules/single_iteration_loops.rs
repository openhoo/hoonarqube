use std::collections::HashMap;

use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Stmt, StmtIf, StmtMatch};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

// Possible destinations that still matter to an enclosing loop. A return or
// raise leaves the function and contributes none of these destinations.
const NEXT: u8 = 1;
const BREAK: u8 = 2;
const CONTINUE: u8 = 4;

pub(crate) fn check_single_iteration_loops(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut flow = LoopFlow::default();
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::While(loop_stmt) = stmt
            && flow.body(loop_stmt.start(), &loop_stmt.body) & (NEXT | CONTINUE) == 0
        {
            issues.push(issue_at(
                "python:S1751",
                "Refactor this loop to do more than one iteration.",
                TextRange::at(loop_stmt.start(), TextSize::of("while")),
                index,
                source,
            ));
        }
    }
    issues
}

#[derive(Default)]
struct LoopFlow {
    // The file inventory also visits each nested while separately.
    bodies: HashMap<TextSize, u8>,
}

impl LoopFlow {
    fn body(&mut self, start: TextSize, body: &[Stmt]) -> u8 {
        if let Some(&paths) = self.bodies.get(&start) {
            return paths;
        }
        let paths = self.suite(body);
        self.bodies.insert(start, paths);
        paths
    }

    fn suite(&mut self, suite: &[Stmt]) -> u8 {
        let mut paths = NEXT;
        for stmt in suite {
            if paths & NEXT == 0 {
                break;
            }
            paths = (paths & !NEXT) | self.statement(stmt);
        }
        paths
    }

    fn statement(&mut self, stmt: &Stmt) -> u8 {
        match stmt {
            Stmt::Return(_) | Stmt::Raise(_) => 0,
            Stmt::Break(_) => BREAK,
            Stmt::Continue(_) => CONTINUE,
            Stmt::If(branch) => self.if_paths(branch),
            Stmt::Match(branch) => self.match_paths(branch),
            Stmt::For(inner) => self.nested_loop(inner.start(), &inner.body, &inner.orelse),
            Stmt::While(inner) => self.nested_loop(inner.start(), &inner.body, &inner.orelse),
            // The context manager may suppress an exception before a jump.
            Stmt::With(context) => NEXT | self.suite(&context.body),
            // A handler or finally suite may redirect a jump. Leave uncertain
            // paths open rather than claiming the loop cannot repeat.
            Stmt::Try(_) => NEXT | CONTINUE | BREAK,
            _ => NEXT,
        }
    }

    fn if_paths(&mut self, branch: &StmtIf) -> u8 {
        let mut paths = self.suite(&branch.body);
        for arm in &branch.elif_else_clauses {
            paths |= self.suite(&arm.body);
            if arm.test.is_none() {
                return paths;
            }
        }
        paths | NEXT
    }

    fn match_paths(&mut self, branch: &StmtMatch) -> u8 {
        let mut paths = 0;
        for case in &branch.cases {
            paths |= self.suite(&case.body);
            if case.guard.is_none() && case.pattern.is_irrefutable() {
                return paths;
            }
        }
        paths | NEXT
    }

    fn nested_loop(&mut self, start: TextSize, body: &[Stmt], otherwise: &[Stmt]) -> u8 {
        // A break in the inner body skips its else and continues here. A
        // break or continue in its else targets the *enclosing* loop.
        let breaks = self.body(start, body) & BREAK != 0;
        self.suite(otherwise) | if breaks { NEXT } else { 0 }
    }
}
