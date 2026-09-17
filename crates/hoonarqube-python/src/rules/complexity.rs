use crate::AnalyzerOptions;
use crate::support::child_bodies;
use crate::support::child_exprs;
use crate::support::for_each_expr;
use crate::support::for_each_function_def;
use crate::support::for_each_stmt;
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
// FunctionComplexity follows SonarPython's ComplexityVisitor independently of
// the legacy class/file totals: non-elif `if`, loops, conditional expressions,
// boolean operators and comprehension filters, plus one per function. Nested
// functions are separate units, but nested class bodies belong to their parent.
// The shared measurer below retains class/file cyclomatic behavior and cognitive
// weights from the SonarPython CognitiveComplexityVisitor: `if` costs `1 + nesting`, `elif`
// links and plain `else` branches cost one flat point, control structures
// nest their contents one level deeper, logical-operator chains count once
// per consecutive run of the same operator, and the control flow inside
// nested definitions rolls into the enclosing score with the nested nesting
// level (wrapper functions lend their own level, class bodies reset it).

pub(crate) fn check_cognitive_complexity(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    flag_functions(parsed, |function, cognitive, _cyclomatic, nested| {
        if !nested && cognitive > options.maximum_cognitive_complexity {
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
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::FunctionDef(function) = stmt else {
            return;
        };
        let total = measure_function(stmt);
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

/// Function-specific traversal mirroring the upstream reference visitor:
/// include the root's header, skip nested functions entirely, and walk classes.
fn measure_function(root: &Stmt) -> u32 {
    let mut total = 1;
    let mut pending = vec![root];
    while let Some(stmt) = pending.pop() {
        if matches!(stmt, Stmt::FunctionDef(_)) && !std::ptr::eq(stmt, root) {
            continue;
        }
        if matches!(stmt, Stmt::If(_) | Stmt::For(_) | Stmt::While(_)) {
            total += 1;
        }
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, &mut |expr| total += expression_decisions(expr));
        }
        total += type_parameter_decisions(stmt);
        for body in child_bodies(stmt) {
            pending.extend(body);
        }
    }
    total
}

fn type_parameter_decisions(stmt: &Stmt) -> u32 {
    let parameters = match stmt {
        Stmt::FunctionDef(function) => function.type_params.as_deref(),
        Stmt::ClassDef(class) => class.type_params.as_deref(),
        _ => None,
    };
    let Some(parameters) = parameters else {
        return 0;
    };
    let mut total = 0;
    for parameter in &parameters.type_params {
        use ruff_python_ast::TypeParam;
        let (bound, default) = match parameter {
            TypeParam::TypeVar(param) => (param.bound.as_deref(), param.default.as_deref()),
            TypeParam::TypeVarTuple(param) => (None, param.default.as_deref()),
            TypeParam::ParamSpec(param) => (None, param.default.as_deref()),
        };
        for expr in [bound, default].into_iter().flatten() {
            for_each_expr(expr, &mut |expr| total += expression_decisions(expr));
        }
    }
    total
}

fn expression_decisions(expr: &Expr) -> u32 {
    let generators = match expr {
        Expr::If(_) => return 1,
        Expr::BoolOp(boolean) => {
            return u32::try_from(boolean.values.len().saturating_sub(1)).unwrap_or(u32::MAX);
        }
        Expr::ListComp(comp) => &comp.generators,
        Expr::SetComp(comp) => &comp.generators,
        Expr::DictComp(comp) => &comp.generators,
        Expr::Generator(comp) => &comp.generators,
        _ => return 0,
    };
    generators
        .iter()
        .map(|generator| u32::try_from(generator.ifs.len()).unwrap_or(u32::MAX))
        .sum()
}

pub(crate) fn check_file_complexity(
    parsed: &Parsed<ModModule>,
    _index: &LineIndex,
    _source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut total = 0u32;
    let mut issues = Vec::new();
    flag_functions(parsed, |_function, _cognitive, cyclomatic, _nested| {
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
            flows: Vec::new(),
            alternatives: Vec::new(),
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
    mut visit: impl FnMut(&ruff_python_ast::StmtFunctionDef, u32, u32, bool),
) {
    // Track which functions are nested inside another function: the
    // reference's cognitive check skips reporting them (their control flow
    // already rolls into the enclosing score), while the cyclomatic family
    // still scores them as units of their own.
    let mut nested_ranges = std::collections::HashSet::new();
    for_each_function_def(
        parsed.syntax().body.as_slice(),
        false,
        &mut |function, _| {
            for_each_function_def(function.body.as_slice(), false, &mut |inner, _| {
                nested_ranges.insert(inner.name.range());
            });
        },
    );
    for_each_function_def(
        parsed.syntax().body.as_slice(),
        false,
        &mut |function, _in_class_body| {
            let (cognitive, cyclomatic) = measure_unit(&function.body);
            let nested = nested_ranges.contains(&function.name.range());
            visit(function, cognitive, cyclomatic, nested);
        },
    );
}

/// Visits every class definition in the tree.
fn visit_classes(suite: &[Stmt], visit: &mut impl FnMut(&StmtClassDef)) {
    for_each_stmt(suite, &mut |stmt| {
        if let Stmt::ClassDef(class) = stmt {
            visit(class);
        }
    });
}

/// `(cognitive, cyclomatic)` of one function body.
fn measure_unit(body: &[Stmt]) -> (u32, u32) {
    let mut measurer = Measurer {
        cognitive: 0,
        cyclomatic: 0,
        nesting: 0,
        logic_chain: None,
        nested_definitions: 0,
        frames: vec![Frame::Function(body)],
    };
    measurer.walk_suite(body);
    (measurer.cognitive, measurer.cyclomatic)
}

struct Measurer<'a> {
    cognitive: u32,
    cyclomatic: u32,
    nesting: u32,
    logic_chain: Option<BoolOp>,
    /// Depth of nested definition bodies currently walked. Structures inside
    /// a nested definition keep contributing cognitive weight to the
    /// enclosing unit (the `SonarPython` visitor never skips them), while their
    /// decision points stay owned by the inner unit's own cyclomatic score.
    nested_definitions: u32,
    /// Directly enclosing definitions for the `SonarPython` nesting rules: a
    /// nested function inherits a wrapper function's level, otherwise adds
    /// one over a function parent, and class bodies reset the level to zero.
    frames: Vec<Frame<'a>>,
}

enum Frame<'a> {
    /// Enclosing function with its direct body statements (wrapper check).
    Function(&'a [Stmt]),
    Class,
}

enum ExprWork<'a> {
    Visit(&'a Expr),
    RestoreLogic(Option<BoolOp>),
    RestoreNesting(u32),
}

impl<'a> Measurer<'a> {
    fn walk_suite(&mut self, suite: &'a [Stmt]) {
        for stmt in suite {
            match stmt {
                // Nested definitions roll their control flow into the
                // enclosing cognitive score without inflating its
                // cyclomatic count.
                Stmt::FunctionDef(function) => {
                    self.walk_nested_function(function, stmt);
                    continue;
                }
                Stmt::ClassDef(_) => {
                    self.walk_nested_class(stmt);
                    continue;
                }
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

    /// One `if` increment at `1 + nesting`; `elif` links and plain `else`
    /// branches cost one flat point each, matching the `SonarPython`
    /// cognitive fixture.
    fn process_if(&mut self, if_: &'a ruff_python_ast::StmtIf) {
        self.cognitive += 1 + self.nesting;
        if self.nested_definitions == 0 {
            self.cyclomatic += 1;
        }
        self.walk_expr(&if_.test);
        let saved = self.nesting;
        self.nesting += 1;
        self.walk_suite(&if_.body);
        for clause in &if_.elif_else_clauses {
            self.cognitive += 1;
            if clause.test.is_some() && self.nested_definitions == 0 {
                self.cyclomatic += 1;
            }
            if let Some(test) = &clause.test {
                self.walk_expr(test);
            }
            self.nesting += 1;
            self.walk_suite(&clause.body);
            self.nesting = saved;
        }
        self.nesting = saved;
    }

    /// The `try` body shares its nesting level; each handler costs
    /// `1 + nesting` and nests its contents one level deeper.
    fn process_try(&mut self, try_: &'a ruff_python_ast::StmtTry) {
        self.walk_suite(&try_.body);
        for handler in &try_.handlers {
            let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = handler;
            self.cognitive += 1 + self.nesting;
            if self.nested_definitions == 0 {
                self.cyclomatic += 1;
            }
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
    fn process_match(&mut self, match_: &'a ruff_python_ast::StmtMatch) {
        self.cognitive += 1 + self.nesting;
        if self.nested_definitions == 0 {
            self.cyclomatic += u32::try_from(match_.cases.len()).unwrap_or(u32::MAX);
        }
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
        if self.nested_definitions == 0 {
            self.cyclomatic += 1;
        }
        let saved = self.nesting;
        self.nesting += 1;
        walk_children(self);
        self.nesting = saved;
    }

    fn walk_expr(&mut self, expr: &'a Expr) {
        let mut pending = vec![ExprWork::Visit(expr)];
        while let Some(work) = pending.pop() {
            match work {
                ExprWork::Visit(expr) => match expr {
                    Expr::BoolOp(bool_op) => self.walk_bool_op(bool_op, &mut pending),
                    Expr::If(if_exp) => self.walk_conditional(if_exp, &mut pending),
                    Expr::ListComp(comp) => {
                        pending.push(ExprWork::Visit(&comp.elt));
                        self.push_comprehensions(&comp.generators, &mut pending);
                    }
                    Expr::SetComp(comp) => {
                        pending.push(ExprWork::Visit(&comp.elt));
                        self.push_comprehensions(&comp.generators, &mut pending);
                    }
                    Expr::Generator(comp) => {
                        pending.push(ExprWork::Visit(&comp.elt));
                        self.push_comprehensions(&comp.generators, &mut pending);
                    }
                    Expr::DictComp(comp) => {
                        pending.push(ExprWork::Visit(&comp.value));
                        if let Some(key) = &comp.key {
                            pending.push(ExprWork::Visit(key));
                        }
                        self.push_comprehensions(&comp.generators, &mut pending);
                    }
                    other => {
                        pending.extend(child_exprs(other).into_iter().rev().map(ExprWork::Visit));
                    }
                },
                ExprWork::RestoreLogic(saved) => self.logic_chain = saved,
                ExprWork::RestoreNesting(saved) => self.nesting = saved,
            }
        }
    }
    fn push_comprehensions<'b>(
        &mut self,
        generators: &'b [Comprehension],
        pending: &mut Vec<ExprWork<'b>>,
    ) {
        if self.nested_definitions == 0 {
            for generator in generators {
                self.cyclomatic += u32::try_from(generator.ifs.len()).unwrap_or(u32::MAX);
            }
        }
        for generator in generators.iter().rev() {
            pending.extend(generator.ifs.iter().rev().map(ExprWork::Visit));
            pending.push(ExprWork::Visit(&generator.iter));
            pending.push(ExprWork::Visit(&generator.target));
        }
    }

    /// Rolls one nested function definition into the enclosing cognitive
    /// score at the `SonarPython` level: a wrapper parent lends its own level,
    /// any other function parent adds one, and a class parent resets to 0.
    fn walk_nested_function(
        &mut self,
        function: &'a ruff_python_ast::StmtFunctionDef,
        stmt: &'a Stmt,
    ) {
        let level = match self.frames.last() {
            Some(Frame::Function(body)) if is_wrapper_function(body, stmt) => self.nesting,
            Some(Frame::Function(_)) => self.nesting + 1,
            _ => 0,
        };
        let saved_nesting = self.nesting;
        let saved_definitions = self.nested_definitions;
        self.nesting = level;
        self.nested_definitions += 1;
        self.frames.push(Frame::Function(&function.body));
        self.walk_suite(&function.body);
        self.frames.pop();
        self.nested_definitions = saved_definitions;
        self.nesting = saved_nesting;
    }

    /// Rolls one nested class definition into the enclosing cognitive score;
    /// class bodies reset the nesting level to zero.
    fn walk_nested_class(&mut self, stmt: &'a Stmt) {
        let saved_nesting = self.nesting;
        let saved_definitions = self.nested_definitions;
        self.nesting = 0;
        self.nested_definitions += 1;
        self.frames.push(Frame::Class);
        for body in child_bodies(stmt) {
            self.walk_suite(body);
        }
        self.frames.pop();
        self.nested_definitions = saved_definitions;
        self.nesting = saved_nesting;
    }

    /// Scores a boolean-operator chain: its decision points count
    /// cyclomatically only outside nested definitions, the cognitive weight
    /// falls once per consecutive run of the same operator, and the chain's
    /// logic context is restored after its operands.
    fn walk_bool_op(
        &mut self,
        bool_op: &'a ruff_python_ast::ExprBoolOp,
        pending: &mut Vec<ExprWork<'a>>,
    ) {
        if self.nested_definitions == 0 {
            self.cyclomatic += bool_op
                .values
                .len()
                .saturating_sub(1)
                .try_into()
                .unwrap_or(u32::MAX);
        }
        if self.logic_chain != Some(bool_op.op) {
            self.cognitive += 1;
        }
        let saved_chain = self.logic_chain;
        self.logic_chain = Some(bool_op.op);
        pending.push(ExprWork::RestoreLogic(saved_chain));
        pending.extend(bool_op.values.iter().rev().map(ExprWork::Visit));
    }

    /// Scores a conditional expression at `1 + nesting` with its three
    /// sub-expressions one nesting level deeper.
    fn walk_conditional(
        &mut self,
        if_exp: &'a ruff_python_ast::ExprIf,
        pending: &mut Vec<ExprWork<'a>>,
    ) {
        self.cognitive += 1 + self.nesting;
        let saved = self.nesting;
        self.nesting += 1;
        pending.push(ExprWork::RestoreNesting(saved));
        pending.push(ExprWork::Visit(&if_exp.orelse));
        pending.push(ExprWork::Visit(&if_exp.body));
        pending.push(ExprWork::Visit(&if_exp.test));
    }
}

/// The `SonarPython` wrapper rule: a nested function whose enclosing function
/// holds nothing besides it and plain `return name` statements inherits the
/// enclosing nesting level instead of adding one.
fn is_wrapper_function(body: &[Stmt], nested: &Stmt) -> bool {
    body.iter()
        .filter(|stmt| !std::ptr::eq(*stmt, nested))
        .all(|stmt| {
            matches!(
                stmt,
                Stmt::Return(return_) if matches!(return_.value.as_deref(), Some(Expr::Name(_)))
            )
        })
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
    fn complexity_walks_comprehension_result_expressions() {
        let source = "def choose(values):\n    return [(1 if value else 2) for value in values]\n";
        let options = AnalyzerOptions {
            maximum_cognitive_complexity: 0,
            maximum_function_complexity: 1,
            ..AnalyzerOptions::default()
        };
        let report = analyze(PathBuf::from("t.py"), source, &options);
        assert_eq!(findings(&report, "python:S3776").len(), 1);
        assert_function_complexity(source, 2);

        let bool_source =
            "def choose(values):\n    return [value > 0 and value < 10 for value in values]\n";
        let report = analyze(PathBuf::from("t.py"), bool_source, &options);
        assert_eq!(findings(&report, "python:FunctionComplexity").len(), 1);
    }

    #[test]
    fn function_complexity_flags_past_threshold_with_baseline() {
        // if(1) + for(1) + while(1) + boolean operator(1) + baseline(1) = 5.
        // The elif itself is not a decision point in the reference visitor.
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
        assert_function_complexity(source, 5);
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
    fn complexity_units_exclude_nested_functions_and_match_cases() {
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
        // Match cases add nothing: outer scores 1. The filter and if are
        // owned by inner's separate unit, which scores 3.
        let options = AnalyzerOptions {
            maximum_function_complexity: 2,
            ..AnalyzerOptions::default()
        };
        let report = analyze(PathBuf::from("t.py"), source, &options);
        let found = findings(&report, "python:FunctionComplexity");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 6);
        assert!(findings(&scan(source), "python:FunctionComplexity").is_empty());
    }

    fn assert_function_complexity(source: &str, expected: u32) {
        // Both sides of the threshold pin the numeric score without coupling
        // the regression to diagnostic wording.
        for (maximum, count) in [(expected - 1, 1), (expected, 0)] {
            let options = AnalyzerOptions {
                maximum_function_complexity: maximum,
                ..AnalyzerOptions::default()
            };
            let report = analyze(PathBuf::from("t.py"), source, &options);
            assert_eq!(findings(&report, "python:FunctionComplexity").len(), count);
        }
    }

    #[test]
    fn function_complexity_matches_pinned_django_counts() {
        // SonarQube Community 26.8.0.126808, Django
        // 8cbdd4a814397f81adf0129288f32b615bd1f94f; issue #671.
        // AppConfig.create: native 24 -> reference 19 (four handlers, one elif).
        assert_function_complexity(
            include_str!("../../../../tests/fixtures/function-complexity/django_app_config.py"),
            19,
        );
        // ModelAdmin._changeform_view: native 39 -> reference 40
        // (one elif removed, two conditional expressions added).
        assert_function_complexity(
            include_str!("../../../../tests/fixtures/function-complexity/django_changeform.py"),
            40,
        );
    }

    #[test]
    fn function_complexity_walks_unscored_branches_and_boolean_chains() {
        let source = concat!(
            "def f(a, b, c):\n",
            "    try:\n",
            "        if a:\n",
            "            pass\n",
            "        elif a and b and c:\n",
            "            pass\n",
            "    except (ValueError if a else TypeError):\n",
            "        match a or b:\n",
            "            case 1 if a and b:\n",
            "                return a if b else c\n",
            "            case _:\n",
            "                return [x for x in c if a if b or c]\n",
        );
        // baseline + if + two ands + handler conditional + match-subject or
        // + guard and + return conditional + two filters + filter or = 11.
        assert_function_complexity(source, 11);
    }

    #[test]
    fn function_complexity_includes_headers_classes_and_lambdas() {
        let source = concat!(
            "@(decorate if flag else identity)\n",
            "def outer(arg: A if flag else B = left or right) -> A if flag else B:\n",
            "    @decorate(left or right)\n",
            "    class Local(Base if flag else Other):\n",
            "        if flag:\n",
            "            value = lambda: left if flag else right\n",
            "        def method(arg=left or right):\n",
            "            return left if flag else right\n",
            "    def inner(arg=left or right):\n",
            "        return left if flag else right\n",
            "    return Local\n",
        );
        // Root header (4), class header (2), class if + lambda conditional (2),
        // baseline (1). Inner function headers and bodies belong only to them.
        assert_function_complexity(source, 9);
    }

    #[test]
    fn function_complexity_includes_generic_bounds() {
        let source = concat!(
            "def outer[T: (A if flag else B)]():\n",
            "    class Local[U: (A if flag else B)]:\n",
            "        pass\n",
            "    def inner[V: (A if flag else B)]():\n",
            "        pass\n",
            "    return Local\n",
        );
        // Root and class bounds count; the nested function's bound does not.
        assert_function_complexity(source, 3);
    }

    #[test]
    fn s3776_rolls_nested_definitions_into_the_parent_score() {
        // SonarPython keeps counting control flow inside nested definitions
        // toward the enclosing function; the nested `if` sits one nesting
        // level deeper than `outer`'s own `if`.
        let nested = "def outer(a):\n    def inner(x):\n        if x:\n            pass\n    if a:\n        pass\n";
        let options = AnalyzerOptions {
            maximum_cognitive_complexity: 2,
            ..AnalyzerOptions::default()
        };
        let report = analyze(PathBuf::from("t.py"), nested, &options);
        let found = findings(&report, "python:S3776");
        assert_eq!(found.len(), 1);
        assert!(found[0].message.contains("from 3 to the 2 allowed."));

        // A wrapper whose only other statements are plain `return name`
        // lends the wrapper's own nesting level to the inner definition.
        let wrapper = concat!(
            "def make(a):\n",
            "    def inner(x):\n",
            "        if x:\n",
            "            if a:\n",
            "                pass\n",
            "    return inner\n",
        );
        let options = AnalyzerOptions {
            maximum_cognitive_complexity: 2,
            ..AnalyzerOptions::default()
        };
        let report = analyze(PathBuf::from("t.py"), wrapper, &options);
        let found = findings(&report, "python:S3776");
        // The reference skips reporting nested functions entirely: only
        // `make` is flagged, with inner's control flow rolled into its score
        // at the inherited wrapper level (3 = if(x) 1 + if(a) 2).
        assert_eq!(found.len(), 1);
        assert!(found[0].message.contains("from 3 to the 2 allowed."));
    }

    #[test]
    fn s3776_charges_flat_points_for_plain_else_and_elif() {
        // A plain `else` costs one flat point.
        let flat_else = "def f(a):\n    if a:\n        pass\n    else:\n        pass\n";
        let options = AnalyzerOptions {
            maximum_cognitive_complexity: 1,
            ..AnalyzerOptions::default()
        };
        let report = analyze(PathBuf::from("t.py"), flat_else, &options);
        let found = findings(&report, "python:S3776");
        assert_eq!(found.len(), 1);
        assert!(found[0].message.contains("from 2 to the 1 allowed."));

        // An `elif` link also stays flat even in nested contexts.
        let chained = concat!(
            "def f(a, b):\n",
            "    if a:\n",
            "        if b:\n",
            "            pass\n",
            "        elif a:\n",
            "            pass\n",
        );
        let options = AnalyzerOptions {
            maximum_cognitive_complexity: 3,
            ..AnalyzerOptions::default()
        };
        let report = analyze(PathBuf::from("t.py"), chained, &options);
        let found = findings(&report, "python:S3776");
        assert_eq!(found.len(), 1);
        assert!(found[0].message.contains("from 4 to the 3 allowed."));
    }
}
