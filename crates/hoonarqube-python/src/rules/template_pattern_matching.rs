use crate::engine::file_context::FileContext;
use crate::rules::scope_values::collect_target_names;
use crate::support::{flow_location, issue_at};
use hoonarqube_ir::{Issue, IssueFlow};
use ruff_python_ast::{Expr, Stmt, StmtFor, StmtIf};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
const RULE_KEY: &str = "python:S7945";
const MESSAGE: &str = "Use structural pattern matching (match/case) instead of isinstance() checks for template string processing.";
const SECONDARY_MESSAGE: &str =
    "Replace this isinstance with the appropriate pattern matching case.";

/// python:S7945 — PEP 750 recommends structural pattern matching for
/// template processing; `isinstance` chains over `str`/`Interpolation`
/// components are the verbose form. Scope `ALL`.
///
/// Mirrors `TemplateStringStructuralPatternMatchingCheck`: for each `for`
/// loop, the `isinstance(<loop-var>, <type>)` calls appearing in the
/// conditions of the loop body's top-level `if`/`elif`/`else` chains are
/// collected (conditions may combine checks with binary operators; `else`
/// bodies recurse). When at least two of them check against `str` or
/// `string.templatelib.Interpolation`, the first collected `isinstance`
/// callee is flagged and the remaining checks become secondary locations.
/// `isinstance` calls nested inside `if` bodies or other statements are not
/// collected, matching the reference's direct-statement walk.
pub(crate) fn check_template_pattern_matching(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let interpolation_names = interpolation_names(file_ctx);
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::For(for_stmt) = stmt else {
            continue;
        };
        check_for(for_stmt, &interpolation_names, index, source, &mut issues);
    }
    issues
}

/// Names bound to `string.templatelib.Interpolation` by the file's imports
/// (`from string.templatelib import Interpolation`, `import
/// string.templatelib`, `from string import templatelib`, aliases, and
/// wildcard imports).
fn interpolation_names(file_ctx: &FileContext) -> Vec<String> {
    let mut names = Vec::new();
    for import in &file_ctx.imports {
        match import {
            crate::engine::file_context::AnyImport::From(stmt) => {
                names_from_import(stmt, &mut names);
            }
            crate::engine::file_context::AnyImport::Plain(stmt) => {
                for alias in &stmt.names {
                    if alias.name.as_str() == "string.templatelib" {
                        let bound = alias
                            .asname
                            .as_ref()
                            .map_or("string.templatelib", ruff_python_ast::Identifier::as_str);
                        names.push(format!("{bound}.Interpolation"));
                    }
                }
            }
        }
    }
    names
}

/// `Interpolation` names bound by one `from <module> import ...` statement.
fn names_from_import(stmt: &ruff_python_ast::StmtImportFrom, names: &mut Vec<String>) {
    let Some(module) = &stmt.module else {
        return;
    };
    match module.as_str() {
        "string.templatelib" => templatelib_names(&stmt.names, names),
        "string" => string_names(&stmt.names, names),
        _ => {}
    }
}

/// `from string.templatelib import Interpolation[ as x]` / `*` bindings.
fn templatelib_names(aliases: &[ruff_python_ast::Alias], names: &mut Vec<String>) {
    for alias in aliases {
        if alias.name.as_str() == "Interpolation" {
            names.push(
                alias
                    .asname
                    .as_ref()
                    .unwrap_or(&alias.name)
                    .as_str()
                    .to_string(),
            );
        } else if alias.name.as_str() == "*" {
            names.push("Interpolation".to_string());
        }
    }
}

/// `from string import templatelib[ as x]` / `*` bindings.
fn string_names(aliases: &[ruff_python_ast::Alias], names: &mut Vec<String>) {
    for alias in aliases {
        if alias.name.as_str() == "templatelib" {
            let bound = alias.asname.as_ref().unwrap_or(&alias.name).as_str();
            names.push(format!("{bound}.Interpolation"));
        } else if alias.name.as_str() == "*" {
            names.push("templatelib.Interpolation".to_string());
        }
    }
}

fn check_for(
    for_stmt: &StmtFor,
    interpolation_names: &[String],
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if for_stmt.body.is_empty() {
        return;
    }
    let mut targets = Vec::new();
    collect_target_names(&for_stmt.target, &mut targets);
    if targets.is_empty() {
        return;
    }
    let mut checks: Vec<&ruff_python_ast::ExprCall> = Vec::new();
    find_isinstance_checks(&for_stmt.body, &targets, &mut checks);
    let template_checks = checks
        .iter()
        .filter(|call| is_template_type_check(call, interpolation_names))
        .count();
    if template_checks < 2 {
        return;
    }
    let mut issue = issue_at(RULE_KEY, MESSAGE, checks[0].func.range(), index, source);
    issue.flows.push(IssueFlow {
        locations: checks[1..]
            .iter()
            .map(|call| flow_location(SECONDARY_MESSAGE, call.func.range(), index, source))
            .collect(),
    });
    issues.push(issue);
}

/// Whether the second `isinstance` argument names `str` or
/// `string.templatelib.Interpolation`.
fn is_template_type_check(
    call: &ruff_python_ast::ExprCall,
    interpolation_names: &[String],
) -> bool {
    let Some(Expr::Name(type_name)) = second_regular_arg(call) else {
        return false;
    };
    type_name.id.as_str() == "str"
        || interpolation_names
            .iter()
            .any(|name| name == type_name.id.as_str())
}

/// The second regular (non-starred) argument expression of a call.
fn second_regular_arg(call: &ruff_python_ast::ExprCall) -> Option<&Expr> {
    let mut regular: Vec<&Expr> = call
        .arguments
        .args
        .iter()
        .filter(|arg| !matches!(arg, Expr::Starred(_)))
        .collect();
    regular.extend(
        call.arguments
            .keywords
            .iter()
            .filter(|keyword| keyword.arg.is_some())
            .map(|keyword| &keyword.value),
    );
    regular.into_iter().nth(1)
}

/// Collects `isinstance(<target>, <name>)` calls from the conditions of the
/// `if`/`elif`/`else` chains that are direct statements of `body`; `else`
/// bodies recurse. Mirrors `findIsInstanceChecks`.
fn find_isinstance_checks<'a>(
    body: &'a [Stmt],
    targets: &[&str],
    checks: &mut Vec<&'a ruff_python_ast::ExprCall>,
) {
    for stmt in body {
        let Stmt::If(if_stmt) = stmt else {
            continue;
        };
        collect_from_if(if_stmt, targets, checks);
    }
}

fn collect_from_if<'a>(
    if_stmt: &'a StmtIf,
    targets: &[&str],
    checks: &mut Vec<&'a ruff_python_ast::ExprCall>,
) {
    extract_isinstance_checks(&if_stmt.test, targets, checks);
    for clause in &if_stmt.elif_else_clauses {
        if let Some(test) = &clause.test {
            extract_isinstance_checks(test, targets, checks);
        } else {
            find_isinstance_checks(&clause.body, targets, checks);
        }
    }
}

/// Extracts `isinstance` calls from a condition expression; binary
/// expressions recurse into both operands, everything else stops.
fn extract_isinstance_checks<'a>(
    expr: &'a Expr,
    targets: &[&str],
    checks: &mut Vec<&'a ruff_python_ast::ExprCall>,
) {
    match expr {
        Expr::Call(call) => {
            if is_isinstance_of_target(call, targets) {
                checks.push(call);
            }
        }
        Expr::BinOp(binop) => {
            extract_isinstance_checks(&binop.left, targets, checks);
            extract_isinstance_checks(&binop.right, targets, checks);
        }
        Expr::BoolOp(boolop) => {
            for value in &boolop.values {
                extract_isinstance_checks(value, targets, checks);
            }
        }
        _ => {}
    }
}

/// `isinstance(<target-name>, <name>)` with exactly two regular arguments.
fn is_isinstance_of_target(call: &ruff_python_ast::ExprCall, targets: &[&str]) -> bool {
    if !matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "isinstance") {
        return false;
    }
    let mut regular: Vec<&Expr> = call
        .arguments
        .args
        .iter()
        .filter(|arg| !matches!(arg, Expr::Starred(_)))
        .collect();
    regular.extend(
        call.arguments
            .keywords
            .iter()
            .filter(|keyword| keyword.arg.is_some())
            .map(|keyword| &keyword.value),
    );
    if regular.len() != 2 {
        return false;
    }
    let (Some(Expr::Name(first)), Some(Expr::Name(_))) = (regular.first(), regular.get(1)) else {
        return false;
    };
    targets.contains(&first.id.as_str())
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S7945";

    /// Sonar's own pair: the `isinstance` chain over `str`/`Interpolation`
    /// flags the first callee; the `match`/`case` rewrite is clean.
    #[test]
    fn s7945_flags_sonar_example() {
        let flagged = scan(concat!(
            "from string.templatelib import Interpolation\n",
            "def process_template(template):\n",
            "    result = []\n",
            "    for item in template:\n",
            "        if isinstance(item, str):\n",
            "            result.append(item.lower())\n",
            "        elif isinstance(item, Interpolation):\n",
            "            result.append(str(item.value).upper())\n",
            "    return ''.join(result)\n",
        ));
        let hits = findings(&flagged, KEY);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].range.start.line, 5);
        assert_eq!(hits[0].flows[0].locations.len(), 1);
        let clean = scan(concat!(
            "from string.templatelib import Interpolation\n",
            "def process_template(template):\n",
            "    result = []\n",
            "    for item in template:\n",
            "        match item:\n",
            "            case str() as s:\n",
            "                result.append(s.lower())\n",
            "            case Interpolation() as interp:\n",
            "                result.append(str(interp.value).upper())\n",
            "    return ''.join(result)\n",
        ));
        assert!(findings(&clean, KEY).is_empty());
    }

    /// Fewer than two template-type checks, non-target isinstance calls, and
    /// isinstance checks nested inside if bodies stay silent.
    #[test]
    fn s7945_negative_controls() {
        let single = scan(concat!(
            "for item in template:\n",
            "    if isinstance(item, str):\n",
            "        pass\n",
        ));
        assert!(findings(&single, KEY).is_empty());
        let nested = scan(concat!(
            "for item in template:\n",
            "    if flag:\n",
            "        if isinstance(item, str):\n",
            "            pass\n",
            "        elif isinstance(item, Interpolation):\n",
            "            pass\n",
        ));
        assert!(findings(&nested, KEY).is_empty());
        let other_var = scan(concat!(
            "for item in template:\n",
            "    if isinstance(other, str):\n",
            "        pass\n",
            "    elif isinstance(other, Interpolation):\n",
            "        pass\n",
        ));
        assert!(findings(&other_var, KEY).is_empty());
    }

    /// Combined conditions and `else`-chain recursion still collect checks;
    /// the first collected callee anchors the issue.
    #[test]
    fn s7945_combined_conditions() {
        let report = scan(concat!(
            "for item in template:\n",
            "    if isinstance(item, str) or isinstance(item, Interpolation):\n",
            "        pass\n",
            "    else:\n",
            "        if isinstance(item, str):\n",
            "            pass\n",
        ));
        let hits = findings(&report, KEY);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].flows[0].locations.len(), 2);
    }
}
