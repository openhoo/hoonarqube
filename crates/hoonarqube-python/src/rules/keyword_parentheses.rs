
use crate::engine::file_context::FileContext;
use crate::support::to_range;
use hoonarqube_ir::{Issue, TextEdit, apply_fixes};
use ruff_python_ast::token::{TokenKind, Tokens, parenthesized_range};
use ruff_python_ast::{AnyNodeRef, Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

/// python:S1721 — parentheses after the `assert`, `del`, `elif`, `except`,
/// `for`, `if`, `not`, `raise`, `return`, `while`, and `yield` keywords, and
/// after `in` in a `for` loop (`while (x < 10):`, `return (value)`,
/// `for lib in ("a", "b"):`).  `SonarPython` runs this production-only, so
/// test-scope sources stay silent.
///
/// A keyword clause is reported once, for the outermost parenthesis pair that
/// hugs the whole clause expression: `return ((a))` reports one finding for
/// `return`, `del (x), (y)` only for the first target, and `for (i) in (1, 2)`
/// reports both the `for` and the `in` keyword.  Tuples keep their finding —
/// `return (1, 2)` unparenthesizes to the equivalent `return 1, 2` — while
/// parentheses that removal would break or repurpose stay silent: precedence
/// (`return (a or b) and b`), conditionals (`return (a) if a else (b)`),
/// generator expressions, empty tuples (`return ()`), walrus conditions, and
/// except tuples (`except (A, B):`).  `raise` keeps reporting tuples because
/// the reference analyzer reports them regardless (`raise (ValueError, TypeError)`).
pub(crate) fn check_keyword_parentheses(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let ctx = ClauseCtx {
        tokens: parsed.tokens(),
        parsed,
        index,
        source,
    };
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        report_statement_clauses(&mut issues, stmt, &ctx);
    }
    for expr in &file_ctx.exprs {
        report_expression_clauses(&mut issues, expr, &ctx);
    }
    issues
}

/// Analysis inputs shared by the keyword-clause walkers.
struct ClauseCtx<'a> {
    tokens: &'a Tokens,
    parsed: &'a Parsed<ModModule>,
    index: &'a LineIndex,
    source: &'a str,
}

/// Reports parenthesized clauses on the statement keyword roles.
fn report_statement_clauses(issues: &mut Vec<Issue>, stmt: &Stmt, ctx: &ClauseCtx) {
    match stmt {
        Stmt::Return(return_stmt) => report_clause(
            issues,
            ClauseRole::Return,
            return_stmt.value.as_deref(),
            AnyNodeRef::StmtReturn(return_stmt),
            ctx,
        ),
        Stmt::Delete(delete_stmt) => {
            // One finding per keyword occurrence: only the first target.
            if let Some(target) = delete_stmt.targets.first() {
                report_clause(
                    issues,
                    ClauseRole::Delete,
                    Some(target),
                    AnyNodeRef::StmtDelete(delete_stmt),
                    ctx,
                );
            }
        }
        Stmt::Assert(assert_stmt) => report_clause(
            issues,
            ClauseRole::Assert,
            Some(assert_stmt.test.as_ref()),
            AnyNodeRef::StmtAssert(assert_stmt),
            ctx,
        ),
        Stmt::Raise(raise_stmt) => report_clause(
            issues,
            ClauseRole::Raise,
            raise_stmt.exc.as_deref(),
            AnyNodeRef::StmtRaise(raise_stmt),
            ctx,
        ),
        Stmt::If(if_stmt) => {
            report_clause(
                issues,
                ClauseRole::If,
                Some(if_stmt.test.as_ref()),
                AnyNodeRef::StmtIf(if_stmt),
                ctx,
            );
            for clause in &if_stmt.elif_else_clauses {
                if let Some(test) = clause.test.as_ref() {
                    report_clause(
                        issues,
                        ClauseRole::Elif,
                        Some(test),
                        AnyNodeRef::ElifElseClause(clause),
                        ctx,
                    );
                }
            }
        }
        Stmt::While(while_stmt) => report_clause(
            issues,
            ClauseRole::While,
            Some(while_stmt.test.as_ref()),
            AnyNodeRef::StmtWhile(while_stmt),
            ctx,
        ),
        Stmt::For(for_stmt) => {
            report_clause(
                issues,
                ClauseRole::For,
                Some(for_stmt.target.as_ref()),
                AnyNodeRef::StmtFor(for_stmt),
                ctx,
            );
            report_clause(
                issues,
                ClauseRole::In,
                Some(for_stmt.iter.as_ref()),
                AnyNodeRef::StmtFor(for_stmt),
                ctx,
            );
        }
        Stmt::Try(try_stmt) => {
            for handler in &try_stmt.handlers {
                report_clause(
                    issues,
                    ClauseRole::Except,
                    handler_type(handler),
                    AnyNodeRef::from(handler),
                    ctx,
                );
            }
        }
        _ => {}
    }
}

/// Reports parenthesized clauses on the expression keyword roles.
fn report_expression_clauses(issues: &mut Vec<Issue>, expr: &Expr, ctx: &ClauseCtx) {
    match expr {
        Expr::UnaryOp(unary_op) if unary_op.op == ruff_python_ast::UnaryOp::Not => {
            report_clause(
                issues,
                ClauseRole::Not,
                Some(unary_op.operand.as_ref()),
                AnyNodeRef::ExprUnaryOp(unary_op),
                ctx,
            );
        }
        Expr::Yield(yield_expr) => report_clause(
            issues,
            ClauseRole::Yield,
            yield_expr.value.as_deref(),
            AnyNodeRef::ExprYield(yield_expr),
            ctx,
        ),
        _ => {}
    }
}

/// The keyword a parenthesized clause hangs off, with its message text and
/// removal-equivalence guards.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ClauseRole {
    Return,
    Yield,
    Assert,
    Delete,
    If,
    Elif,
    While,
    Not,
    Raise,
    Except,
    For,
    In,
}

impl ClauseRole {
    fn keyword(self) -> &'static str {
        match self {
            ClauseRole::Return => "return",
            ClauseRole::Yield => "yield",
            ClauseRole::Assert => "assert",
            ClauseRole::Delete => "del",
            ClauseRole::If => "if",
            ClauseRole::Elif => "elif",
            ClauseRole::While => "while",
            ClauseRole::Not => "not",
            ClauseRole::Raise => "raise",
            ClauseRole::Except => "except",
            ClauseRole::For => "for",
            ClauseRole::In => "in",
        }
    }
}

/// Reports the outermost parenthesis pair hugging `clause` when it is the
/// entire clause expression of the role keyword.
fn report_clause(
    issues: &mut Vec<Issue>,
    role: ClauseRole,
    clause: Option<&Expr>,
    parent: AnyNodeRef<'_>,
    ctx: &ClauseCtx<'_>,
) {
    let Some(clause) = clause else {
        return;
    };
    // Tuple/generator ranges include their own required delimiters, so their
    // pair is the node range itself; every other expression carries its
    // grouping parens just outside its range.
    let clause_pair = match clause {
        Expr::Tuple(tuple) if tuple.parenthesized => Some(tuple.range()),
        Expr::Generator(generator) if generator.parenthesized => Some(generator.range()),
        clause => parenthesized_range(clause.into(), parent, ctx.tokens),
    };
    let Some(pair) = clause_pair else {
        return;
    };
    if !removal_preserves_semantics(role, ctx.parsed, ctx.source, pair) {
        return;
    }
    let mut issue = Issue {
        rule_key: "python:S1721".to_string(),
        message: format!(
            "Remove the parentheses after this \"{}\" keyword.",
            role.keyword()
        ),
        range: to_range(pair, ctx.index, ctx.source),
        fix: None,
        alternatives: Vec::new(),
        flows: Vec::new(),
    };
    // The opening parenthesis is replaced by a separator rather than deleted,
    // so `return(1)` unparenthesizes to `return 1`, and an empty interior
    // (`return()`) would change meaning, so it stays fix-less.
    let edits = vec![
        TextEdit {
            range: to_range(
                TextRange::at(pair.start(), TextSize::of('(')),
                ctx.index,
                ctx.source,
            ),
            replacement: " ".to_string(),
        },
        TextEdit {
            range: to_range(
                TextRange::at(pair.end() - TextSize::of(')'), TextSize::of(')')),
                ctx.index,
                ctx.source,
            ),
            replacement: String::new(),
        },
    ];
    if fix_preserves_syntax(ctx.source, &edits) {
        issue = issue.with_fix("Remove redundant parentheses", edits);
    }
    issues.push(issue);
}

/// Decides whether unparenthesizing `pair` keeps the program equivalent.
///
/// The interior must stay non-empty and single-line at pair depth (a masked
/// newline would terminate the statement once the parentheses are gone), the
/// role's guards reject removals that repurpose the bare text (`assert (a, b)`
/// becomes an assertion message, `del (a, b)` two targets, `not (a and b)`
/// rebinding to `(not a) and b`), and the unparenthesized source must still
/// parse (`if (x := 5):`, `except (A, B):`, generator iterators).
fn removal_preserves_semantics(
    role: ClauseRole,
    parsed: &Parsed<ModModule>,
    source: &str,
    pair: TextRange,
) -> bool {
    let interior = TextRange::new(
        pair.start() + TextSize::of('('),
        pair.end() - TextSize::of(')'),
    );
    let mut depth = 0u32;
    let mut depth0_comma = false;
    let mut depth0_boolean = false;
    let mut masked_newline = false;
    let mut significant = false;
    for token in parsed.tokens().in_range(interior) {
        match token.kind() {
            TokenKind::Lpar | TokenKind::Lsqb | TokenKind::Lbrace => depth += 1,
            TokenKind::Rpar | TokenKind::Rsqb | TokenKind::Rbrace => {
                depth = depth.saturating_sub(1);
            }
            TokenKind::Comma if depth == 0 => depth0_comma = true,
            TokenKind::And | TokenKind::Or if depth == 0 => depth0_boolean = true,
            // Walrus assignments keep their conventional parentheses even in
            // statement-test positions where the grammar would allow dropping
            // them (`if (x := 5):` — the reference analyzer stays silent).
            TokenKind::ColonEqual if depth == 0 => return false,
            // A newline the parentheses currently mask would end the
            // statement once they are gone. Newlines inside string literals
            // are part of the string token, so they never hit this arm.
            TokenKind::NonLogicalNewline => masked_newline = true,
            _ => {}
        }
        if !token.kind().is_trivia() {
            significant = true;
        }
    }
    if !significant {
        // `return ()` unparenthesizes to a bare statement: different value.
        return false;
    }
    if masked_newline {
        return false;
    }
    if role != ClauseRole::Raise {
        // A depth-0 comma inside `return`/`yield`/`for` clauses stays a tuple
        // when unparenthesized; in every other clause it either repurposes the
        // statement (`assert (a, b)` becomes an assertion message, `del (a,
        // b)` two targets) or is required by Python 3 (`except (A, B):`).
        if depth0_comma
            && matches!(
                role,
                ClauseRole::Assert
                    | ClauseRole::Delete
                    | ClauseRole::Not
                    | ClauseRole::If
                    | ClauseRole::Elif
                    | ClauseRole::While
                    | ClauseRole::Except
            )
        {
            return false;
        }
        if depth0_boolean && role == ClauseRole::Not {
            return false;
        }
        if spaced_removal_reparses(source, pair).is_none() {
            return false;
        }
    }
    true
}

/// Replaces the opening parenthesis with a separating space and deletes the
/// closing one; `None` when the rewritten module no longer parses.
fn spaced_removal_reparses(
    source: &str,
    pair: TextRange,
) -> Option<ruff_python_parser::Parsed<ruff_python_ast::ModModule>> {
    let start = pair.start().to_u32() as usize;
    let end = pair.end().to_u32() as usize;
    let mut fixed = String::with_capacity(source.len() - 1);
    fixed.push_str(&source[..start]);
    fixed.push(' ');
    fixed.push_str(&source[start + 1..end - 1]);
    fixed.push_str(&source[end..]);
    ruff_python_parser::parse_module(&fixed).ok()
}

fn handler_type(handler: &ruff_python_ast::ExceptHandler) -> Option<&Expr> {
    match handler {
        ruff_python_ast::ExceptHandler::ExceptHandler(inner) => inner.type_.as_deref(),
    }
}

/// Rejects suggestions whose parentheses carry Python grammar, such as a
/// multiline continuation or generator expression. The analyzer parses
/// broken sources tolerantly, so fix eligibility needs this strict check;
/// otherwise re-analysis could mistake a new syntax error for resolution.
fn fix_preserves_syntax(source: &str, edits: &[TextEdit]) -> bool {
    let refs: Vec<&TextEdit> = edits.iter().collect();
    apply_fixes(source, &refs)
        .ok()
        .is_some_and(|fixed| ruff_python_parser::parse_module(&fixed).is_ok())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::test_support::{findings, scan};
    use crate::{AnalyzerOptions, analyze};

    fn findings_in(source: &str) -> Vec<String> {
        findings(&scan(source), "python:S1721")
            .iter()
            .map(|issue| issue.message.clone())
            .collect()
    }

    fn messages_for(path: &str, source: &str) -> Vec<String> {
        findings(
            &analyze(PathBuf::from(path), source, &AnalyzerOptions::default()),
            "python:S1721",
        )
        .iter()
        .map(|issue| issue.message.clone())
        .collect()
    }

    #[test]
    fn s1721_flags_the_requests_oracle_sites() {
        // requests compat.py:39 / packages.py:8 — `in` in a for loop.
        for source in [
            "def f(libs):\n    for lib in (\"chardet\", \"charset_normalizer\"):\n        pass\n",
            "for package in (\"urllib3\", \"idna\"):\n    pass\n",
        ] {
            assert_eq!(
                findings_in(source),
                vec![String::from(
                    "Remove the parentheses after this \"in\" keyword."
                )]
            );
        }
        // requests utils.py:271 — tuple after `return`.
        assert_eq!(
            findings_in("def f(n):\n    return (n[0] or \"\", n[2] or \"\")\n"),
            vec![String::from(
                "Remove the parentheses after this \"return\" keyword."
            )]
        );
    }

    #[test]
    fn s1721_covers_every_reference_keyword_with_spaced_or_adjacent_parens() {
        let cases = [
            ("def f(a):\n    assert (a)\n", "\"assert\""),
            ("def f():\n    x = 1\n    del (x)\n", "\"del\""),
            ("def f(a):\n    if (a):\n        pass\n", "\"if\""),
            (
                "def f(a):\n    if a:\n        pass\n    elif (a):\n        pass\n",
                "\"elif\"",
            ),
            ("def f(a):\n    while (a):\n        break\n", "\"while\""),
            ("def f(a):\n    return not (a)\n", "\"not\""),
            ("def f():\n    raise (ValueError)\n", "\"raise\""),
            (
                "def f():\n    try:\n        pass\n    except (ValueError):\n        pass\n",
                "\"except\"",
            ),
            ("def f(a):\n    yield (a)\n", "\"yield\""),
            ("def f():\n    return(1)\n", "\"return\""),
        ];
        for (source, fragment) in cases {
            let messages = findings_in(source);
            assert_eq!(messages.len(), 1, "{source}");
            assert!(messages[0].contains(fragment), "{source}");
        }
    }

    #[test]
    fn s1721_reports_for_and_in_independently() {
        let messages = findings_in("for (i) in (1, 2):\n    pass\n");
        assert_eq!(messages.len(), 2);
        assert!(messages.iter().any(|message| message.contains("\"for\"")));
        assert!(messages.iter().any(|message| message.contains("\"in\"")));
    }

    #[test]
    fn s1721_flags_tuples_after_return_yield_and_in() {
        assert_eq!(findings_in("def f():\n    return (1, 2)\n").len(), 1);
        assert_eq!(findings_in("def f():\n    yield (1, 2)\n").len(), 1);
        assert_eq!(
            findings_in("def f():\n    for i in (1, 2):\n        pass\n").len(),
            1
        );
        assert_eq!(
            findings_in("def f(p):\n    for (a, b) in p:\n        pass\n").len(),
            1
        );
    }

    #[test]
    fn s1721_stays_silent_when_removal_is_not_equivalent() {
        // Precedence-needed parentheses.
        assert!(findings_in("def f(a, b):\n    return (a or b) and b\n").is_empty());
        assert!(findings_in("def f(a, b):\n    return not (a and b) or b\n").is_empty());
        // A conditional is not the whole clause.
        assert!(findings_in("def f(a):\n    return (a) if a else (2)\n").is_empty());
        assert!(findings_in("def f(a, b):\n    return (a), b\n").is_empty());
        // Attribute access and calls keep their parentheses.
        assert!(findings_in("def f():\n    return (1).real\n").is_empty());
        assert!(findings_in("def f(a):\n    return (a)(1)\n").is_empty());
        // Generator expressions and empty tuples depend on the parentheses.
        assert!(findings_in("def f(y):\n    return (x for x in y)\n").is_empty());
        assert!(findings_in("def f(y):\n    for w in (x for x in y):\n        pass\n").is_empty());
        assert!(findings_in("def f():\n    return ()\n").is_empty());
        // Walrus conditions require the parentheses.
        assert!(findings_in("def f():\n    if (x := 5):\n        print(x)\n").is_empty());
        // Except tuples are required in Python 3.
        assert!(
            findings_in("def f():\n    try:\n        pass\n    except (ValueError, TypeError):\n        pass\n")
                .is_empty()
        );
        // The `in` operator is only covered in a for loop.
        assert!(findings_in("def f(a):\n    return a in (1, 2)\n").is_empty());
        assert!(findings_in("def f(a):\n    if a in (1, 2):\n        pass\n").is_empty());
        assert!(findings_in("def f(a):\n    return [x for x in (1, 2) if x in a]\n").is_empty());
        // Multiline continuations keep their parentheses.
        assert!(findings_in("def f():\n    return (\n        1\n    )\n").is_empty());
        // A parenthesized walrus keeps its parentheses.
        assert!(findings_in("def f():\n    return (x := 5)\n").is_empty());
    }

    #[test]
    fn s1721_raise_reports_even_when_removal_would_not_parse() {
        assert_eq!(
            findings_in("def f():\n    raise (ValueError, TypeError)\n").len(),
            1
        );
        assert_eq!(findings_in("def f(e):\n    raise (e) from e\n").len(), 1);
    }

    #[test]
    fn s1721_reports_once_per_keyword_occurrence() {
        assert_eq!(findings_in("def f(a):\n    return ((a))\n").len(), 1);
        assert_eq!(
            findings_in("def f():\n    x, y = 1, 2\n    del (x), (y)\n").len(),
            1
        );
    }

    #[test]
    fn s1721_flags_methods_and_stays_silent_on_test_scope_files() {
        let source = "class K:\n    def m(self):\n        return (1)\n";
        assert_eq!(findings_in(source).len(), 1);
        assert!(messages_for("tests/test_probe.py", source).is_empty());
        assert!(messages_for("conftest.py", source).is_empty());
    }

    #[test]
    fn return_parentheses_carry_a_working_quick_fix() {
        let report = scan("def f():\n    return(1)\n");
        let issues = findings(&report, "python:S1721");
        assert_eq!(issues.len(), 1);

        let fix = issues[0].fix.as_ref().expect("quick fix attached");
        assert_eq!(fix.message, "Remove redundant parentheses");

        let source = "def f():\n    return(1)\n";
        let refs: Vec<&hoonarqube_ir::TextEdit> = fix.edits.iter().collect();
        let fixed = hoonarqube_ir::apply_fixes(source, &refs).expect("applies cleanly");
        assert_eq!(fixed, "def f():\n    return 1\n");
    }

    #[test]
    fn empty_interiors_and_walrus_stay_silent() {
        // Pinned against the reference analyzer: `return ()` unparenthesizes
        // to a different statement, and `if (x := 5):` keeps its walrus
        // parentheses; neither is reported.
        assert!(findings_in("def f():\n    return ()\n").is_empty());
        assert!(findings_in("def f():\n    return()\n").is_empty());
        assert!(findings_in("def f():\n    if (x := 5):\n        print(x)\n").is_empty());

        // `del(x)` is a normal finding with a working fix.
        let source = "def f(flag):\n    x = flag\n    del(x)\n";
        let report = scan(source);
        let issues = findings(&report, "python:S1721");
        assert_eq!(issues.len(), 1);
        let fix = issues[0].fix.as_ref().expect("del fix");
        let refs: Vec<&hoonarqube_ir::TextEdit> = fix.edits.iter().collect();
        let fixed = hoonarqube_ir::apply_fixes(source, &refs).expect("applies cleanly");
        assert!(fixed.contains("del x\n"));
    }

    #[test]
    fn generator_parentheses_stay_fixless() {
        let report = scan("def f(xs):\n    return(x for x in xs)\n");
        // Removal does not parse, so the site is not reported at all.
        assert!(findings(&report, "python:S1721").is_empty());
    }
}
