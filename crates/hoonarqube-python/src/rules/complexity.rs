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
                    "Function has a complexity of {total} which is greater than {} authorized.",
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
    _index: &LineIndex,
    _source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut total = 0u32;
    let mut issues = Vec::new();
    flag_functions(parsed, |_function, _cognitive, cyclomatic| {
        total = total.saturating_add(cyclomatic + 1);
    });
    if total > options.maximum_file_complexity {
        issues.push(Issue {
            rule_key: "python:FileComplexity".to_string(),
            message: format!(
                "File has a complexity of {total} which is greater than {} authorized.",
                options.maximum_file_complexity
            ),
            range: hoonarqube_ir::Range::file_level(),
            fix: None,
        });
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
                    "Class has a complexity of {total} which is greater than {} authorized.",
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

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::test_support::{findings, scan};
    use crate::{AnalyzerOptions, analyze};

    #[test]
    fn s3776_scores_nesting_weighted_structures() {
        let source = concat!(
            "def f(a, b):\n",
            "    if a:\n",
            "        if b:\n",
            "            if a and b:\n",
            "                pass\n",
        );
        // cognitive = if(1) + nested if(2) + nested if(3) + boolop chain(1) = 7.
        for (threshold, expected) in [(6, 1), (7, 0)] {
            let options = AnalyzerOptions {
                maximum_cognitive_complexity: threshold,
                ..AnalyzerOptions::default()
            };
            let report = analyze(PathBuf::from("t.py"), source, &options);
            assert_eq!(findings(&report, "python:S3776").len(), expected);
        }
    }

    #[test]
    fn s3776_threshold_is_configurable() {
        let options = AnalyzerOptions {
            maximum_cognitive_complexity: 1,
            ..AnalyzerOptions::default()
        };
        // Two sequential ifs score 2 cognitive points.
        let report = analyze(
            PathBuf::from("t.py"),
            "def f(a, b):\n    if a:\n        pass\n    if b:\n        pass\n",
            &options,
        );
        let found = findings(&report, "python:S3776");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Refactor this function to reduce its Cognitive Complexity from 2 to the 1 allowed."
        );
    }

    #[test]
    fn function_complexity_flags_past_threshold_with_baseline() {
        // if(1) + elif(1) + for(1) + while(1) + boolop values-1(1) + baseline(1)
        // = 6, which exceeds the lowered threshold of 4.
        let source = concat!(
            "def f(a, b, c):\n",
            "    if a:\n",
            "        pass\n",
            "    elif b:\n",
            "        pass\n",
            "    else:\n",
            "        pass\n",
            "    for x in []:\n",
            "        while c or a:\n",
            "            pass\n",
        );
        let options = AnalyzerOptions {
            maximum_function_complexity: 4,
            ..AnalyzerOptions::default()
        };
        // if(1) + elif(1) + for(1) + while(1) + boolop values-1(1) + baseline(1) = 6
        let report = analyze(PathBuf::from("t.py"), source, &options);
        assert_eq!(findings(&report, "python:FunctionComplexity").len(), 1);
    }

    #[test]
    fn file_complexity_sums_all_function_units() {
        let source = concat!(
            "def f():\n",
            "    if a:\n",
            "        pass\n",
            "\n",
            "def g():\n",
            "    if b:\n",
            "        pass\n",
        );
        // Each unit: baseline 1 + one if = 2; total 4 exceeds the lowered bar.
        let options = AnalyzerOptions {
            maximum_file_complexity: 3,
            ..AnalyzerOptions::default()
        };
        let report = analyze(PathBuf::from("t.py"), source, &options);
        assert_eq!(findings(&report, "python:FileComplexity").len(), 1);
        assert!(findings(&scan(source), "python:FileComplexity").is_empty());
    }

    #[test]
    fn class_complexity_sums_direct_methods() {
        let source = concat!(
            "class C:\n",
            "    def m(self):\n",
            "        if a:\n",
            "            pass\n",
            "    def n(self):\n",
            "        try:\n",
            "            pass\n",
            "        except ValueError:\n",
            "            pass\n",
        );
        // Methods: (1 + 1) + (1 + 1 handler) = 4.
        let options = AnalyzerOptions {
            maximum_class_complexity: 3,
            ..AnalyzerOptions::default()
        };
        let report = analyze(PathBuf::from("t.py"), source, &options);
        assert_eq!(findings(&report, "python:ClassComplexity").len(), 1);
        assert!(findings(&scan(source), "python:ClassComplexity").is_empty());
    }

    #[test]
    fn complexity_units_exclude_nested_definitions_and_count_match_cases() {
        let source = concat!(
            "def outer(v):\n",
            "    match v:\n",
            "        case 1:\n",
            "            pass\n",
            "        case _:\n",
            "            def inner(x):\n",
            "                if x:\n",
            "                    pass\n",
            "                return [y for y in v if y]\n",
        );
        // outer: match cases(2) + baseline(1) = 3; the comprehension filter
        // and the `if` belong to inner's own unit, which also scores 3.
        let options = AnalyzerOptions {
            maximum_function_complexity: 2,
            ..AnalyzerOptions::default()
        };
        let report = analyze(PathBuf::from("t.py"), source, &options);
        assert_eq!(findings(&report, "python:FunctionComplexity").len(), 2);
        assert!(findings(&scan(source), "python:FunctionComplexity").is_empty());
    }
}
