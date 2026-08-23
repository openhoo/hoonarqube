use crate::AnalyzerOptions;
use crate::support::child_bodies;
use crate::support::child_exprs;
use crate::support::for_each_function_def;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::BoolOp;
use ruff_python_ast::Comprehension;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_ast::StmtClassDef;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;

// --- python:FunctionComplexity / ClassComplexity / FileComplexity / S3776 ------
//
// One shared unit measurer drives the whole family. Cyclomatic counts follow
// the catalog decision-point enumeration (if/elif, loops, except handlers,
// boolean operator chains, comprehension filters, match cases) with a +1
// baseline per function; nested definitions are units of their own. Cognitive
// weights follow the Sonar model already used by the jsts crate: control
// structures add `1 + nesting` with contents nested one level deeper,
// `elif` chains stay flat, `else` is free, and logical-operator chains count
// once per consecutive run of the same operator.

pub(crate) fn check_cognitive_complexity(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    flag_functions(parsed, |function, cognitive, _cyclomatic| {
        if cognitive > options.maximum_cognitive_complexity {
            issues.push(issue_at(
                "python:S3776",
                &format!(
                    "Refactor this function to reduce its Cognitive Complexity from {cognitive} to the {} allowed.",
                    options.maximum_cognitive_complexity
                ),
                function.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}

pub(crate) fn check_function_complexity(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    flag_functions(parsed, |function, _cognitive, cyclomatic| {
        let total = cyclomatic + 1;
        if total > options.maximum_function_complexity {
            issues.push(issue_at(
                "python:FunctionComplexity",
                &format!(
                    "The Cyclomatic Complexity of this function is {total} which is greater than {} authorized.",
                    options.maximum_function_complexity
                ),
                function.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}

pub(crate) fn check_file_complexity(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut total = 0u32;
    let mut issues = Vec::new();
    flag_functions(parsed, |_function, _cognitive, cyclomatic| {
        total = total.saturating_add(cyclomatic + 1);
    });
    if total > options.maximum_file_complexity {
        issues.push(issue_at(
            "python:FileComplexity",
            &format!(
                "The Cyclomatic Complexity of this file is {total} which is greater than {} authorized.",
                options.maximum_file_complexity
            ),
            TextRange::empty(TextSize::default()),
            index,
            source,
        ));
    }
    issues
}

pub(crate) fn check_class_complexity(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_classes(parsed.syntax().body.as_slice(), &mut |class| {
        let mut total = 0u32;
        for stmt in &class.body {
            if let Stmt::FunctionDef(method) = stmt {
                total += measure_unit(&method.body).1 + 1;
            }
        }
        if total > options.maximum_class_complexity {
            issues.push(issue_at(
                "python:ClassComplexity",
                &format!(
                    "The Cyclomatic Complexity of this class is {total} which is greater than {} authorized.",
                    options.maximum_class_complexity
                ),
                class.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}

/// Applies `visit` to every function definition in the file together with its
/// measured `(cognitive, cyclomatic)` pair.
fn flag_functions(
    parsed: &Parsed<ModModule>,
    mut visit: impl FnMut(&ruff_python_ast::StmtFunctionDef, u32, u32),
) {
    let mut sink = |function: &ruff_python_ast::StmtFunctionDef, _in_class_body: bool| {
        let (cognitive, cyclomatic) = measure_unit(&function.body);
        visit(function, cognitive, cyclomatic);
    };
    for_each_function_def(parsed.syntax().body.as_slice(), false, &mut sink);
}

/// Recurses over every class definition in the tree.
fn visit_classes(suite: &[Stmt], visit: &mut impl FnMut(&StmtClassDef)) {
    for stmt in suite {
        if let Stmt::ClassDef(class) = stmt {
            visit(class);
            visit_classes(&class.body, visit);
        } else {
            for body in child_bodies(stmt) {
                visit_classes(body, visit);
            }
        }
    }
}

/// `(cognitive, cyclomatic)` of one function body.
fn measure_unit(body: &[Stmt]) -> (u32, u32) {
    let mut measurer = Measurer {
        cognitive: 0,
        cyclomatic: 0,
        nesting: 0,
        logic_chain: None,
    };
    measurer.walk_suite(body);
    (measurer.cognitive, measurer.cyclomatic)
}

struct Measurer {
    cognitive: u32,
    cyclomatic: u32,
    nesting: u32,
    logic_chain: Option<BoolOp>,
}

impl Measurer {
    fn walk_suite(&mut self, suite: &[Stmt]) {
        for stmt in suite {
            match stmt {
                // Nested definitions are units of their own.
                Stmt::FunctionDef(_) | Stmt::ClassDef(_) => continue,
                Stmt::If(if_) => {
                    self.process_if(if_);
                    continue;
                }
                Stmt::Try(try_) => {
                    self.process_try(try_);
                    continue;
                }
                Stmt::Match(match_) => {
                    self.process_match(match_);
                    continue;
                }
                Stmt::For(_) | Stmt::While(_) => {
                    // Loops nest everything they contain, header included.
                    self.enter_nested(|measurer| {
                        for expr in stmt_exprs(stmt) {
                            measurer.walk_expr(expr);
                        }
                        for body in child_bodies(stmt) {
                            measurer.walk_suite(body);
                        }
                    });
                    continue;
                }
                _ => {}
            }
            for expr in stmt_exprs(stmt) {
                self.walk_expr(expr);
            }
            for body in child_bodies(stmt) {
                self.walk_suite(body);
            }
        }
    }

    /// One `if` increment; `elif` links are processed flat so a chained
    /// conditional adds no extra nesting weight, and a plain `else` is free.
    fn process_if(&mut self, if_: &ruff_python_ast::StmtIf) {
        self.cognitive += 1 + self.nesting;
        self.cyclomatic += 1;
        self.walk_expr(&if_.test);
        let saved = self.nesting;
        self.nesting += 1;
        self.walk_suite(&if_.body);
        for clause in &if_.elif_else_clauses {
            match &clause.test {
                Some(test) => {
                    self.cognitive += 1 + saved;
                    self.cyclomatic += 1;
                    self.walk_expr(test);
                    self.walk_suite(&clause.body);
                }
                None => self.walk_suite(&clause.body),
            }
        }
        self.nesting = saved;
    }

    /// The `try` body shares its nesting level; each handler costs
    /// `1 + nesting` and nests its contents one level deeper.
    fn process_try(&mut self, try_: &ruff_python_ast::StmtTry) {
        self.walk_suite(&try_.body);
        for handler in &try_.handlers {
            let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = handler;
            self.cognitive += 1 + self.nesting;
            self.cyclomatic += 1;
            if let Some(type_) = &handler.type_ {
                self.walk_expr(type_);
            }
            let saved = self.nesting;
            self.nesting += 1;
            self.walk_suite(&handler.body);
            self.nesting = saved;
        }
        self.walk_suite(&try_.orelse);
        self.walk_suite(&try_.finalbody);
    }

    /// A `match` behaves like a switch: one increment plus one per case,
    /// with every case body nested.
    fn process_match(&mut self, match_: &ruff_python_ast::StmtMatch) {
        self.cognitive += 1 + self.nesting;
        self.cyclomatic += u32::try_from(match_.cases.len()).unwrap_or(u32::MAX);
        let saved = self.nesting;
        self.nesting += 1;
        for case in &match_.cases {
            if let Some(guard) = &case.guard {
                self.walk_expr(guard);
            }
            self.walk_suite(&case.body);
        }
        self.nesting = saved;
    }

    /// Walks one loop-like construct: `1 + nesting` increments with all
    /// contents nested one level deeper.
    fn enter_nested(&mut self, walk_children: impl FnOnce(&mut Self)) {
        self.cognitive += 1 + self.nesting;
        self.cyclomatic += 1;
        let saved = self.nesting;
        self.nesting += 1;
        walk_children(self);
        self.nesting = saved;
    }

    fn walk_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::BoolOp(bool_op) => {
                self.cyclomatic += bool_op
                    .values
                    .len()
                    .saturating_sub(1)
                    .try_into()
                    .unwrap_or(u32::MAX);
                if self.logic_chain != Some(bool_op.op) {
                    self.cognitive += 1;
                }
                let saved_chain = self.logic_chain;
                self.logic_chain = Some(bool_op.op);
                for value in &bool_op.values {
                    self.walk_expr(value);
                }
                self.logic_chain = saved_chain;
            }
            Expr::If(if_exp) => {
                self.cognitive += 1 + self.nesting;
                let saved = self.nesting;
                self.nesting += 1;
                self.walk_expr(&if_exp.test);
                self.walk_expr(&if_exp.body);
                self.walk_expr(&if_exp.orelse);
                self.nesting = saved;
            }
            Expr::ListComp(comp) => self.walk_comprehensions(&comp.generators),
            Expr::SetComp(comp) => self.walk_comprehensions(&comp.generators),
            Expr::Generator(comp) => self.walk_comprehensions(&comp.generators),
            Expr::DictComp(comp) => self.walk_comprehensions(&comp.generators),
            other => {
                for child in child_exprs(other) {
                    self.walk_expr(child);
                }
            }
        }
    }

    /// Comprehension filters are decision points; `for` clauses stay out of
    /// both counters per the catalog enumeration.
    fn walk_comprehensions(&mut self, generators: &[Comprehension]) {
        for generator in generators {
            self.cyclomatic += u32::try_from(generator.ifs.len()).unwrap_or(u32::MAX);
            self.walk_expr(&generator.target);
            self.walk_expr(&generator.iter);
            for filter in &generator.ifs {
                self.walk_expr(filter);
            }
        }
    }
}
