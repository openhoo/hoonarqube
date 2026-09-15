// Rule module s7732_instanceof_builtins (generated).
//
// `javascript:S7732` + `typescript:S7732` — eslint-plugin-unicorn
// `no-instanceof-builtins` (v65.0.1, wrapped by SonarJS S7732, default
// options): a `x instanceof C` binary expression whose right side is a
// plain identifier naming one of the loose-strategy built-ins — `Array`,
// `Function`, or a primitive wrapper (`String`, `Number`, `Boolean`,
// `BigInt`, `Symbol`) — is reported on the whole binary expression with
// "Avoid using `instanceof` for type checking as it can lead to
// unreliable results.". The reference rule is purely syntactic: it does
// not check whether the constructor identifier is shadowed, and the
// default `strategy: "loose"` reports only the constructors above (the
// strict-strategy list — `Map`, `Set`, `RegExp`, `Date`, typed arrays,
// and friends — stays silent, as does `Error` without `useErrorIsError`).
// Non-identifier right sides (`x instanceof ns.Array`, computed members)
// stay silent. No auto-fix is offered (the unicorn fixer rewrites the
// expression, which the analyzer does not reproduce).
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
use oxc_ast::ast::{BinaryExpression, Expression};
use oxc_span::GetSpan;

/// Constructors reported under the reference rule's default loose
/// strategy: `Array` and `Function` (dedicated fixes upstream) plus the
/// primitive wrappers (suggestion-only upstream).
const LOOSE_BUILTINS: [&str; 7] = [
    "Array", "Function", "String", "Number", "Boolean", "BigInt", "Symbol",
];

/// Entry point: `javascript:S7732` + `typescript:S7732`
/// instanceof-builtins check over the parsed program.
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
        if let AstKind::BinaryExpression(binary) = node.kind() {
            check_instanceof(&mut sink, binary);
        }
    }
    sink.issues
}

/// The reference report: `instanceof` against a bare built-in
/// constructor identifier, anchored on the whole binary expression.
fn check_instanceof(sink: &mut IssueSink<'_>, binary: &BinaryExpression<'_>) {
    if !binary.operator.is_instance_of() {
        return;
    }
    let Expression::Identifier(constructor) = unparenthesized(&binary.right) else {
        return;
    };
    if !LOOSE_BUILTINS.contains(&constructor.name.as_str()) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S7732",
        "Avoid using `instanceof` for type checking as it can lead to unreliable results.",
        binary.span(),
    );
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7732_flags_pinned_exceljs_sites() {
        // Pinned oracle: exceljs@5bed18b lib/csv/stream-converter.js:56
        // (`encoding instanceof Function`), lib/doc/cell.js:834
        // (`v instanceof String`), lib/doc/column.js:74
        // (`this._header instanceof Array`), spec/utils/tools.js:8 and
        // spec/utils/under-dash.js:29 (`obj instanceof Array`).
        let source = "\
function write(data, encoding, callback) {
  if (encoding instanceof Function) {
    callback = encoding;
    encoding = undefined;
  }
  if (v instanceof String || typeof v === 'string') {
    return 'string';
  }
  return this._header && this._header instanceof Array ? this._header : [this._header];
}
if (obj instanceof Array) {
  clone = [];
}
";
        let findings = js_keys(source);
        assert_eq!(count_key(&findings, "javascript:S7732"), 4);
        let issue = js(source)
            .issues
            .into_iter()
            .find(|issue| issue.rule_key == "javascript:S7732")
            .expect("pinned exceljs instanceof must be reported");
        assert_eq!(
            issue.message,
            "Avoid using `instanceof` for type checking as it can lead to unreliable results."
        );
        assert_eq!(issue.range.start.line, 2);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("  if (".len()).unwrap()
        );
    }

    #[test]
    fn s7732_flags_every_loose_builtin() {
        let source = "\
if (a instanceof Array) {}
if (b instanceof Function) {}
if (c instanceof String) {}
if (d instanceof Number) {}
if (e instanceof Boolean) {}
if (f instanceof BigInt) {}
if (g instanceof Symbol) {}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7732"), 7);
    }

    #[test]
    fn s7732_strict_only_constructors_stay_silent() {
        // The default loose strategy does not report the strict-strategy
        // constructor list or `Error`.
        let source = "\
if (a instanceof Map) {}
if (b instanceof Set) {}
if (c instanceof RegExp) {}
if (d instanceof Date) {}
if (e instanceof Promise) {}
if (f instanceof Error) {}
if (g instanceof Object) {}
if (h instanceof Uint8Array) {}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7732"), 0);
    }

    #[test]
    fn s7732_non_identifier_right_side_stays_silent() {
        let source = "\
if (a instanceof ns.Array) {}
if (b instanceof ctors['Array']) {}
if (c instanceof getArray()) {}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7732"), 0);
    }

    #[test]
    fn s7732_reports_in_both_languages() {
        let source = "if (value instanceof Array) {}\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7732"), 1);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7732"), 1);
    }

    #[test]
    fn s7732_stays_silent_in_test_files_like_reference_main_scope() {
        let source = "if (obj instanceof Array) {}\n";
        let test_report = crate::analyze(
            PathBuf::from("spec/utils/tools.spec.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&test_report), "javascript:S7732"), 0);
        // `spec/utils/tools.js` is MAIN for the pinned server: the
        // filename carries no `.test`/`.spec` marker.
        let main_report = crate::analyze(
            PathBuf::from("spec/utils/tools.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&main_report), "javascript:S7732"), 1);
    }
}
