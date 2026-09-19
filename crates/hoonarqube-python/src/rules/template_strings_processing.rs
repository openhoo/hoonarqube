use crate::engine::file_context::FileContext;
use crate::rules::scope_values::{
    NameResolution, comprehension_target_names, for_each_expr_scoped, for_each_stmt_scoped,
    is_name, pushed_scope, resolve_in_scopes,
};
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{CmpOp, Expr, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const RULE_KEY: &str = "python:S7942";
const MESSAGE: &str = "This template string should be processed before use.";
const BUILTIN_CALLEES: [&str; 5] = ["print", "str", "int", "float", "bool"];
const LOGGING_CALLEES: [&str; 5] = [
    "logging.debug",
    "logging.info",
    "logging.warning",
    "logging.error",
    "logging.critical",
];

/// python:S7942 — a t-string evaluates to a `string.templatelib.Template`,
/// not a `str`; using one where a string is expected prints the object
/// representation or passes the wrong type. Scope `ALL`.
///
/// Mirrors `UnprocessedTemplateStringCheck`: the flagged positions are
/// `if`/`elif`/`while` conditions, comprehension `if` clauses, conditional
/// expression branches, comparison operands (`==`, `<`, `in`, … — `is` is
/// not subscribed), every argument of `print`/`str`/`int`/`float`/`bool`,
/// `logging.debug|info|warning|error|critical`, `str.format`, and the
/// elements of list/tuple arguments to `str.join`. A position is flagged
/// when it is a t-string literal or a name whose single assignment in the
/// enclosing lexical scope chain resolves to one (the reference's
/// `singleAssignedNonNameValue`). `and`/`or` operands and `for`/`match`
/// subjects are not subscribed and stay silent.
pub(crate) fn check_template_strings_processing(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_scoped(file_ctx.module_body, &mut |stmt, scopes| match stmt {
        Stmt::If(if_stmt) => {
            report_if_template(&mut issues, &if_stmt.test, scopes, index, source);
            for clause in &if_stmt.elif_else_clauses {
                if let Some(test) = &clause.test {
                    report_if_template(&mut issues, test, scopes, index, source);
                }
            }
        }
        Stmt::While(while_stmt) => {
            report_if_template(&mut issues, &while_stmt.test, scopes, index, source);
        }
        _ => {}
    });
    for_each_expr_scoped(file_ctx.module_body, &mut |expr, scopes| {
        match expr {
            Expr::If(if_expr) => {
                report_if_template(&mut issues, &if_expr.body, scopes, index, source);
                report_if_template(&mut issues, &if_expr.orelse, scopes, index, source);
            }
            Expr::Compare(compare) => {
                // `is`/`is not` comparisons are not subscribed.
                if compare
                    .ops
                    .iter()
                    .all(|op| !matches!(op, CmpOp::Is | CmpOp::IsNot))
                {
                    report_if_template(&mut issues, &compare.left, scopes, index, source);
                    for comparator in &compare.comparators {
                        report_if_template(&mut issues, comparator, scopes, index, source);
                    }
                }
            }
            Expr::Call(call) => check_call(&mut issues, call, scopes, index, source),
            Expr::ListComp(comp) => {
                report_comprehension_ifs(&mut issues, &comp.generators, scopes, index, source);
            }
            Expr::SetComp(comp) => {
                report_comprehension_ifs(&mut issues, &comp.generators, scopes, index, source);
            }
            Expr::Generator(comp) => {
                report_comprehension_ifs(&mut issues, &comp.generators, scopes, index, source);
            }
            Expr::DictComp(comp) => {
                report_comprehension_ifs(&mut issues, &comp.generators, scopes, index, source);
            }
            _ => {}
        }
    });
    issues
}

/// Flags comprehension `if` clauses; they resolve against the comprehension
/// scope, which binds the `for` targets.
fn report_comprehension_ifs<'a>(
    issues: &mut Vec<Issue>,
    generators: &'a [ruff_python_ast::Comprehension],
    scopes: &[(&'a [Stmt], &[&'a str], bool)],
    index: &LineIndex,
    source: &str,
) {
    let bound = comprehension_target_names(generators);
    let comp_scopes = pushed_scope(scopes, &bound);
    for generator in generators {
        for condition in &generator.ifs {
            report_if_template(issues, condition, &comp_scopes, index, source);
        }
    }
}

/// Checks the call shapes the reference subscribes: builtin/logging/format
/// calls flag every argument; `str.join` flags list/tuple argument elements.
fn check_call<'a>(
    issues: &mut Vec<Issue>,
    call: &'a ruff_python_ast::ExprCall,
    scopes: &[(&'a [Stmt], &[&'a str], bool)],
    index: &LineIndex,
    source: &str,
) {
    let checks_args = match &call.func.as_ref() {
        Expr::Name(name) => BUILTIN_CALLEES.contains(&name.id.as_str()),
        Expr::Attribute(attribute) => {
            if attribute.attr.as_str() == "format" {
                is_str_qualifier(&attribute.value)
            } else if attribute.attr.as_str() == "join" {
                // `str.join` arguments are not checked as regular arguments;
                // only list/tuple elements below.
                false
            } else {
                crate::support::dotted_name(&call.func)
                    .is_some_and(|path| LOGGING_CALLEES.contains(&path.as_str()))
            }
        }
        _ => false,
    };
    if checks_args {
        for arg in &call.arguments.args {
            if matches!(arg, Expr::Starred(_)) {
                continue;
            }
            report_if_template(issues, arg, scopes, index, source);
        }
        for keyword in &call.arguments.keywords {
            if keyword.arg.is_none() {
                continue;
            }
            report_if_template(issues, &keyword.value, scopes, index, source);
        }
    }
    // `str.join` additionally inspects list/tuple argument elements.
    if let Expr::Attribute(attribute) = call.func.as_ref()
        && attribute.attr.as_str() == "join"
        && is_str_qualifier(&attribute.value)
    {
        for arg in &call.arguments.args {
            let elements: &[Expr] = match arg {
                Expr::List(list) => &list.elts,
                Expr::Tuple(tuple) => &tuple.elts,
                _ => &[],
            };
            for element in elements {
                report_if_template(issues, element, scopes, index, source);
            }
        }
    }
}

/// Whether a `.format`/`.join` qualifier denotes `str`: the bare `str` name
/// or a string literal (`"sep".join(...)`).
fn is_str_qualifier(expr: &Expr) -> bool {
    is_name(expr, "str") || matches!(expr, Expr::StringLiteral(_))
}

fn report_if_template<'a>(
    issues: &mut Vec<Issue>,
    expr: &'a Expr,
    scopes: &[(&'a [Stmt], &[&'a str], bool)],
    index: &LineIndex,
    source: &str,
) {
    if is_unprocessed_template(expr, scopes) {
        issues.push(issue_at(RULE_KEY, MESSAGE, expr.range(), index, source));
    }
}

/// Whether `expr` is a t-string literal or a name whose single assignment in
/// the scope chain resolves to one.
fn is_unprocessed_template<'a>(expr: &'a Expr, scopes: &[(&'a [Stmt], &[&'a str], bool)]) -> bool {
    match expr {
        Expr::TString(_) => true,
        Expr::Name(name) => matches!(
            resolve_in_scopes(scopes, name.id.as_str(), false),
            NameResolution::Single(Expr::TString(_))
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S7942";

    /// Sonar's own pair: `print(template)` where `template` is singly
    /// assigned a t-string is flagged; passing it through a processing
    /// function is clean.
    #[test]
    fn s7942_flags_sonar_example() {
        let flagged = scan(concat!(
            "name = \"World\"\n",
            "template = t\"Hello {name}\"\n",
            "print(template)\n",
        ));
        let hits = findings(&flagged, KEY);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].range.start.line, 3);
        let clean = scan(concat!(
            "name = \"World\"\n",
            "template = t\"Hello {name}\"\n",
            "print(process_template(template))\n",
        ));
        assert!(findings(&clean, KEY).is_empty());
    }

    /// Every subscribed position shape: conditions, comprehension filters,
    /// conditional branches, comparisons, builtin/logging/format calls, and
    /// join list/tuple elements.
    #[test]
    fn s7942_flags_each_position() {
        let report = scan(concat!(
            "if t\"x\":\n",
            "    pass\n",
            "while t\"y\":\n",
            "    pass\n",
            "v = t\"a\" if cond else t\"b\"\n",
            "eq = t\"c\" == other\n",
            "member = t\"d\" in pool\n",
            "print(t\"e\")\n",
            "text = str(t\"f\")\n",
            "logging.info(t\"g\")\n",
            "out = \"{0}\".format(t\"h\")\n",
            "joined = \"-\".join([t\"i\", plain])\n",
            "seen = [i for i in items if t\"j\"]\n",
        ));
        assert_eq!(findings(&report, KEY).len(), 12);
    }

    /// Negative controls: processed templates, unsubscribed positions, and
    /// ambiguous bindings stay silent.
    #[test]
    fn s7942_negative_controls() {
        let clean = scan(concat!(
            "name = \"World\"\n",
            "template = t\"Hello {name}\"\n",
            "print(template, template)\n",
            "x = t\"a\" and other\n",
            "for item in t\"b\":\n",
            "    pass\n",
            "ok = t\"c\" is not None\n",
            "sep = \"-\"\n",
            "joined = sep.join(t\"d\")\n",
        ));
        // `print(template, template)` flags both arguments — the reference
        // checks every argument of a builtin call.
        assert_eq!(findings(&clean, KEY).len(), 2);
        let rebound = scan(concat!(
            "template = t\"a\"\n",
            "template = t\"b\"\n",
            "print(template)\n",
        ));
        assert!(findings(&rebound, KEY).is_empty());
    }
}
