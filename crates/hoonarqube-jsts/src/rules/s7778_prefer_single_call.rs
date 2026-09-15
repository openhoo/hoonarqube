// Rule module s7778_prefer_single_call (generated).
//
// `javascript:S7778` + `typescript:S7778` — eslint-plugin-unicorn
// `prefer-single-call` (v65.0.1, wrapped by SonarJS S7778 with its
// type-aware decorator): two consecutive expression statements in the
// same statement list that call the same variadic method on the same
// reference are reported on the second call's method property with
// "Do not call `X()` multiple times.". Covered callees mirror the
// reference cases: `Array#push()` (`x.push(...)`), `Array#unshift()`
// (`x.unshift(...)`), `Element#classList.add()`/`remove()`
// (`el.classList.add(...)`), and `importScripts(...)`. The reference
// ignore list (`stream.push`, `this.push`, `this.stream.push`,
// `process.stdin.push`, `process.stdout.push`, `process.stderr.push`,
// and the `unshift` mirrors) stays silent, as do optional member/call
// forms (`a?.push`, `a.push?.()`), non-adjacent calls, calls on
// different references, and calls nested inside other expressions.
// Reference identity is the callee's dotted path (`this` included), so
// `pets.push(a); pets.push(b)` and `this.list.push(a); this.list.push(b)`
// are flagged while `a.push(x); b.push(x)` is not. The SonarJS decorator
// suppresses reports only when resolved call signatures prove the callee
// cannot take multiple arguments; without whole-program type information
// this module reports the same syntactic candidates (the decorator's own
// conservative fallback). No auto-fix is offered.
//
// SonarJS reports the rule with scope MAIN: test files (the pinned
// server's filename-based classification, shared with the analyzer's
// other rules) stay silent.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, is_test_file, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{CallExpression, Expression, Statement};
use oxc_span::GetSpan;

/// Callee dotted paths the reference rule ignores for `push`/`unshift`.
const IGNORED_PUSH_CALLEES: [&str; 6] = [
    "stream.push",
    "this.push",
    "this.stream.push",
    "process.stdin.push",
    "process.stdout.push",
    "process.stderr.push",
];
const IGNORED_UNSHIFT_CALLEES: [&str; 6] = [
    "stream.unshift",
    "this.unshift",
    "this.stream.unshift",
    "process.stdin.unshift",
    "process.stdout.unshift",
    "process.stderr.unshift",
];

/// One reference case: how a call expression qualifies and what the
/// finding calls it.
struct Case {
    description: &'static str,
}

/// Entry point: `javascript:S7778` + `typescript:S7778`
/// prefer-single-call check over the parsed program.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    if is_test_file(ctx.path) {
        // Scope MAIN: the pinned server classifies by filename.
        return sink.issues;
    }
    let Some(semantic) = ctx.semantic else {
        return sink.issues;
    };
    for node in semantic.nodes().iter() {
        match node.kind() {
            AstKind::Program(program) => check_statement_list(&mut sink, &program.body),
            AstKind::FunctionBody(body) => check_statement_list(&mut sink, &body.statements),
            AstKind::BlockStatement(block) => check_statement_list(&mut sink, &block.body),
            AstKind::SwitchCase(case) => check_statement_list(&mut sink, &case.consequent),
            _ => {}
        }
    }
    sink.issues
}

/// Flags every call after the first in a run of consecutive identical
/// variadic calls, matching the reference's per-second-call reporting.
fn check_statement_list(sink: &mut IssueSink<'_>, statements: &[Statement<'_>]) {
    for pair in statements.windows(2) {
        let [first, second] = pair else { continue };
        let (Statement::ExpressionStatement(first_stmt), Statement::ExpressionStatement(second_stmt)) =
            (first, second)
        else {
            continue;
        };
        let (Expression::CallExpression(first_call), Expression::CallExpression(second_call)) = (
            unparenthesized(&first_stmt.expression),
            unparenthesized(&second_stmt.expression),
        ) else {
            continue;
        };
        let Some(case) = matching_case(first_call, second_call) else {
            continue;
        };
        // Report node: the method property for member calls, the callee
        // identifier for `importScripts`.
        let span = match &second_call.callee {
            Expression::StaticMemberExpression(member) => member.property.span(),
            _ => second_call.callee.span(),
        };
        sink.emit_span(
            RuleScope::Both,
            "S7778",
            &format!("Do not call `{}` multiple times.", case.description),
            span,
        );
    }
}

/// Whether two calls are the same covered callee on the same reference.
fn matching_case<'a>(
    first: &'a CallExpression<'a>,
    second: &'a CallExpression<'a>,
) -> Option<Case> {
    let first_kind = callee_kind(first)?;
    let second_kind = callee_kind(second)?;
    if first_kind != second_kind {
        return None;
    }
    if !same_reference(&first.callee, &second.callee) {
        return None;
    }
    let description = match first_kind {
        CalleeKind::Push => "Array#push()",
        CalleeKind::Unshift => "Array#unshift()",
        CalleeKind::ClassListAdd => "Element#classList.add()",
        CalleeKind::ClassListRemove => "Element#classList.remove()",
        CalleeKind::ImportScripts => "importScripts()",
    };
    Some(Case { description })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CalleeKind {
    Push,
    Unshift,
    ClassListAdd,
    ClassListRemove,
    ImportScripts,
}

/// Classifies a call against the reference cases, applying the
/// non-optional call/member requirements and the push/unshift ignore
/// lists.
fn callee_kind(call: &CallExpression<'_>) -> Option<CalleeKind> {
    if call.optional {
        return None;
    }
    if let Expression::Identifier(identifier) = &call.callee {
        return (identifier.name == "importScripts").then_some(CalleeKind::ImportScripts);
    }
    let Expression::StaticMemberExpression(member) = &call.callee else {
        return None;
    };
    if member.optional {
        return None;
    }
    let method = member.property.name.as_str();
    match method {
        "push" | "unshift" => push_unshift_kind(member, method),
        "add" | "remove" => class_list_kind(member, method),
        _ => None,
    }
}

/// `Array#push`/`Array#unshift` on a dotted receiver, minus the
/// reference ignore lists.
fn push_unshift_kind(
    member: &oxc_ast::ast::StaticMemberExpression<'_>,
    method: &str,
) -> Option<CalleeKind> {
    let dotted = dotted_path(&member.object).map(|path| format!("{path}.{method}"))?;
    let ignored = if method == "push" {
        IGNORED_PUSH_CALLEES.contains(&dotted.as_str())
    } else {
        IGNORED_UNSHIFT_CALLEES.contains(&dotted.as_str())
    };
    if ignored {
        return None;
    }
    Some(if method == "push" {
        CalleeKind::Push
    } else {
        CalleeKind::Unshift
    })
}

/// `Element#classList.add/remove`: the receiver must be a non-optional
/// `.classList` member access.
fn class_list_kind(
    member: &oxc_ast::ast::StaticMemberExpression<'_>,
    method: &str,
) -> Option<CalleeKind> {
    let Expression::StaticMemberExpression(class_list) = &member.object else {
        return None;
    };
    if class_list.optional || class_list.property.name != "classList" {
        return None;
    }
    Some(if method == "add" {
        CalleeKind::ClassListAdd
    } else {
        CalleeKind::ClassListRemove
    })
}

/// Reference identity for callee expressions: identifiers by name,
/// `this` by itself, member chains by recursive object identity plus
/// property name. Anything else (calls, computed members, literals)
/// never matches.
fn same_reference(first: &Expression<'_>, second: &Expression<'_>) -> bool {
    match (unparenthesized(first), unparenthesized(second)) {
        (Expression::Identifier(a), Expression::Identifier(b)) => a.name == b.name,
        (Expression::ThisExpression(_), Expression::ThisExpression(_)) => true,
        (
            Expression::StaticMemberExpression(a),
            Expression::StaticMemberExpression(b),
        ) => {
            !a.optional
                && !b.optional
                && a.property.name == b.property.name
                && same_reference(&a.object, &b.object)
        }
        _ => false,
    }
}

/// Dotted path of a plain identifier/`this`/member receiver, or `None`
/// when any segment is computed, optional, or not a plain member chain.
fn dotted_path(expression: &Expression<'_>) -> Option<String> {
    match unparenthesized(expression) {
        Expression::Identifier(identifier) => Some(identifier.name.to_string()),
        Expression::ThisExpression(_) => Some("this".to_string()),
        Expression::StaticMemberExpression(member) if !member.optional => {
            let mut path = dotted_path(&member.object)?;
            path.push('.');
            path.push_str(member.property.name.as_str());
            Some(path)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7778_flags_pinned_express_and_exceljs_sites() {
        // Pinned oracle: express@3ce6d0e examples/mvc/db.js:8-10,15-16
        // (`pets.push`/`users.push` runs — every call after the first is
        // reported) and exceljs@5bed18b lib/utils/xml-stream.js:109-110.
        let source = "\
var pets = exports.pets = [];
pets.push({ name: 'Tobi', id: 0 });
pets.push({ name: 'Loki', id: 1 });
pets.push({ name: 'Jane', id: 2 });
pets.push({ name: 'Raul', id: 3 });
var users = exports.users = [];
users.push({ name: 'TJ', id: 0 });
users.push({ name: 'Guillermo', id: 1 });
users.push({ name: 'Nathan', id: 2 });
";
        let findings = js_keys(source);
        assert_eq!(count_key(&findings, "javascript:S7778"), 5);
        let issue = js(source)
            .issues
            .into_iter()
            .find(|issue| issue.rule_key == "javascript:S7778")
            .expect("pinned express push run must be reported");
        assert_eq!(issue.message, "Do not call `Array#push()` multiple times.");
        assert_eq!(issue.range.start.line, 3);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("pets.".len()).unwrap()
        );
    }

    #[test]
    fn s7778_flags_unshift_classlist_and_importscripts() {
        let source = "\
list.unshift(a);
list.unshift(b);
el.classList.add('x');
el.classList.add('y');
el.classList.remove('x');
el.classList.remove('y');
importScripts('a.js');
importScripts('b.js');
";
        let findings = js_keys(source);
        assert_eq!(count_key(&findings, "javascript:S7778"), 4);
        let messages: Vec<String> = js(source)
            .issues
            .into_iter()
            .filter(|issue| issue.rule_key == "javascript:S7778")
            .map(|issue| issue.message)
            .collect();
        assert!(messages.contains(&"Do not call `Array#unshift()` multiple times.".to_string()));
        assert!(
            messages.contains(&"Do not call `Element#classList.add()` multiple times.".to_string())
        );
        assert!(
            messages
                .contains(&"Do not call `Element#classList.remove()` multiple times.".to_string())
        );
        assert!(messages.contains(&"Do not call `importScripts()` multiple times.".to_string()));
    }

    #[test]
    fn s7778_ignored_stream_and_this_callees_stay_silent() {
        let source = "\
stream.push(a);
stream.push(b);
this.push(a);
this.push(b);
this.stream.push(a);
this.stream.push(b);
process.stdout.push(a);
process.stdout.push(b);
stream.unshift(a);
stream.unshift(b);
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7778"), 0);
    }

    #[test]
    fn s7778_non_adjacent_different_or_optional_calls_stay_silent() {
        let source = "\
a.push(x);
other();
a.push(y);
c.push(x);
b.push(y);
a?.push(x);
a?.push(y);
a.push?.(x);
a.push?.(y);
const z = [a.push(1), a.push(2)];
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7778"), 0);
    }

    #[test]
    fn s7778_flags_inside_blocks_and_functions() {
        let source = "\
function f() {
  if (ok) {
    xml.push(OPEN);
    xml.push(name);
  }
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7778"), 1);
    }

    #[test]
    fn s7778_reports_in_both_languages() {
        let source = "a.push(x);\na.push(y);\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7778"), 1);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7778"), 1);
    }

    #[test]
    fn s7778_stays_silent_in_test_files_like_reference_main_scope() {
        let source = "a.push(x);\na.push(y);\n";
        let test_report = crate::analyze(
            PathBuf::from("test/app.router.spec.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&test_report), "javascript:S7778"), 0);
        let main_report = crate::analyze(
            PathBuf::from("test/app.router.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&main_report), "javascript:S7778"), 1);
    }
}

