// Rule module s7742_unnecessary_polyfills (generated).
//
// `javascript:S7742` + `typescript:S7742` — eslint-plugin-unicorn
// `no-unnecessary-polyfills` (v65.0.1, wrapped by SonarJS S7742, default
// options): a `require('core-js/modules/es.<feature>')` or
// `import 'core-js/modules/es.<feature>'` (also the `core-js-pure`
// mirror) whose single polyfilled feature is a built-in in every
// reasonable target is reported on the module literal with
// "Use built-in instead.". The reference rule resolves the project's
// `browserslist`/`engines` targets through `core-js-compat` and reports
// only features available there; this module implements the
// true-positive-by-construction subset — the 205 `es.*` features that
// `core-js-compat` reports as available even at the most conservative
// observed target (`node >= 8.3.0`, the pinned exceljs engines range) —
// so every finding is one the reference rule would also emit for any
// project whose targets include that floor. Features unavailable at
// that floor (`es.promise`, `es.promise.finally`,
// `es.symbol.async-iterator`, `es.array.iterator`, `es.array.flat`,
// `es.string.match-all`, `es.object.from-entries`, newer `es.*`/`esnext.*`
// surfaces, and all `web.*` features) stay silent, as do non-`modules`
// entry paths (`stable/`, `actual/`, `features/`, `full/`, `proposals/`,
// `stage/`, `web/`), bare `core-js`/`core-js-pure` bundles, and
// non-core-js polyfill packages (`regenerator-runtime`, `es6-promise`,
// `polyfill-*`, `mdn-polyfills/*`): the reference rule either cannot
// prove them unnecessary without project targets or does not match them
// at all. No auto-fix is offered.
//
// SonarJS reports the rule with scope MAIN: test files (the pinned
// server's filename-based classification, shared with the analyzer's
// other rules) stay silent.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, is_test_file};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{Argument, Expression};
use oxc_span::GetSpan;

/// `es.*` features `core-js-compat` reports as built-in even at
/// `node >= 8.3.0` — the conservative floor under which every flagged
/// import is a true positive for any plausible target set.
const BUILTIN_FEATURES: &[&str] = &[
    "es.aggregate-error.constructor",
    "es.array-buffer.constructor",
    "es.array-buffer.is-view",
    "es.array-buffer.slice",
    "es.array.concat",
    "es.array.copy-within",
    "es.array.every",
    "es.array.fill",
    "es.array.filter",
    "es.array.find",
    "es.array.find-index",
    "es.array.for-each",
    "es.array.from",
    "es.array.includes",
    "es.array.index-of",
    "es.array.is-array",
    "es.array.join",
    "es.array.last-index-of",
    "es.array.map",
    "es.array.of",
    "es.array.reduce",
    "es.array.reduce-right",
    "es.array.reverse",
    "es.array.slice",
    "es.array.some",
    "es.array.species",
    "es.array.splice",
    "es.data-view",
    "es.data-view.constructor",
    "es.date.get-year",
    "es.date.now",
    "es.date.set-year",
    "es.date.to-gmt-string",
    "es.date.to-iso-string",
    "es.date.to-json",
    "es.date.to-primitive",
    "es.date.to-string",
    "es.error.to-string",
    "es.escape",
    "es.function.bind",
    "es.function.has-instance",
    "es.function.name",
    "es.json.to-string-tag",
    "es.map",
    "es.map.constructor",
    "es.math.acosh",
    "es.math.asinh",
    "es.math.atanh",
    "es.math.cbrt",
    "es.math.clz32",
    "es.math.cosh",
    "es.math.expm1",
    "es.math.fround",
    "es.math.imul",
    "es.math.log10",
    "es.math.log1p",
    "es.math.log2",
    "es.math.sign",
    "es.math.sinh",
    "es.math.tanh",
    "es.math.to-string-tag",
    "es.math.trunc",
    "es.number.constructor",
    "es.number.epsilon",
    "es.number.is-finite",
    "es.number.is-integer",
    "es.number.is-nan",
    "es.number.is-safe-integer",
    "es.number.max-safe-integer",
    "es.number.min-safe-integer",
    "es.number.parse-float",
    "es.number.parse-int",
    "es.number.to-exponential",
    "es.number.to-fixed",
    "es.number.to-precision",
    "es.object.assign",
    "es.object.create",
    "es.object.define-properties",
    "es.object.define-property",
    "es.object.entries",
    "es.object.freeze",
    "es.object.get-own-property-descriptor",
    "es.object.get-own-property-descriptors",
    "es.object.get-own-property-names",
    "es.object.get-own-property-symbols",
    "es.object.get-prototype-of",
    "es.object.is",
    "es.object.is-extensible",
    "es.object.is-frozen",
    "es.object.is-sealed",
    "es.object.keys",
    "es.object.prevent-extensions",
    "es.object.proto",
    "es.object.seal",
    "es.object.set-prototype-of",
    "es.object.to-string",
    "es.object.values",
    "es.parse-float",
    "es.parse-int",
    "es.promise.all",
    "es.promise.catch",
    "es.promise.constructor",
    "es.promise.race",
    "es.promise.reject",
    "es.promise.resolve",
    "es.reflect.apply",
    "es.reflect.construct",
    "es.reflect.define-property",
    "es.reflect.delete-property",
    "es.reflect.get",
    "es.reflect.get-own-property-descriptor",
    "es.reflect.get-prototype-of",
    "es.reflect.has",
    "es.reflect.is-extensible",
    "es.reflect.own-keys",
    "es.reflect.prevent-extensions",
    "es.reflect.set",
    "es.reflect.set-prototype-of",
    "es.regexp.sticky",
    "es.regexp.test",
    "es.regexp.to-string",
    "es.set",
    "es.set.constructor",
    "es.string.anchor",
    "es.string.big",
    "es.string.blink",
    "es.string.bold",
    "es.string.code-point-at",
    "es.string.ends-with",
    "es.string.fixed",
    "es.string.fontcolor",
    "es.string.fontsize",
    "es.string.from-code-point",
    "es.string.includes",
    "es.string.italics",
    "es.string.iterator",
    "es.string.link",
    "es.string.match",
    "es.string.pad-end",
    "es.string.pad-start",
    "es.string.raw",
    "es.string.repeat",
    "es.string.search",
    "es.string.small",
    "es.string.split",
    "es.string.starts-with",
    "es.string.strike",
    "es.string.sub",
    "es.string.substr",
    "es.string.sup",
    "es.string.trim",
    "es.string.trim-left",
    "es.string.trim-right",
    "es.symbol",
    "es.symbol.constructor",
    "es.symbol.for",
    "es.symbol.has-instance",
    "es.symbol.is-concat-spreadable",
    "es.symbol.iterator",
    "es.symbol.key-for",
    "es.symbol.match",
    "es.symbol.replace",
    "es.symbol.search",
    "es.symbol.species",
    "es.symbol.split",
    "es.symbol.to-primitive",
    "es.symbol.to-string-tag",
    "es.symbol.unscopables",
    "es.typed-array.copy-within",
    "es.typed-array.every",
    "es.typed-array.fill",
    "es.typed-array.filter",
    "es.typed-array.find",
    "es.typed-array.find-index",
    "es.typed-array.float32-array",
    "es.typed-array.float64-array",
    "es.typed-array.for-each",
    "es.typed-array.from",
    "es.typed-array.includes",
    "es.typed-array.index-of",
    "es.typed-array.int16-array",
    "es.typed-array.int32-array",
    "es.typed-array.int8-array",
    "es.typed-array.iterator",
    "es.typed-array.join",
    "es.typed-array.last-index-of",
    "es.typed-array.map",
    "es.typed-array.of",
    "es.typed-array.reduce",
    "es.typed-array.reduce-right",
    "es.typed-array.slice",
    "es.typed-array.some",
    "es.typed-array.subarray",
    "es.typed-array.to-locale-string",
    "es.typed-array.to-string",
    "es.typed-array.uint16-array",
    "es.typed-array.uint32-array",
    "es.typed-array.uint8-array",
    "es.typed-array.uint8-clamped-array",
    "es.unescape",
    "es.weak-map",
    "es.weak-map.constructor",
    "es.weak-set",
    "es.weak-set.constructor",
];

/// Entry point: `javascript:S7742` + `typescript:S7742`
/// unnecessary-polyfills check over the parsed program.
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
            AstKind::ImportDeclaration(import) => {
                check_module_literal(
                    &mut sink,
                    import.source.value.as_str(),
                    import.source.span(),
                );
            }
            AstKind::CallExpression(call) => {
                check_require(&mut sink, call);
            }
            AstKind::ImportExpression(import) => {
                if let Expression::StringLiteral(literal) = &import.source {
                    check_module_literal(&mut sink, literal.value.as_str(), literal.span);
                }
            }
            _ => {}
        }
    }
    sink.issues
}

/// `require('core-js/...')` calls: the reference rule matches static
/// requires and import sources alike.
fn check_require(sink: &mut IssueSink<'_>, call: &oxc_ast::ast::CallExpression<'_>) {
    if !matches!(&call.callee, Expression::Identifier(id) if id.name == "require") {
        return;
    }
    let Some(Argument::StringLiteral(literal)) = call.arguments.first() else {
        return;
    };
    check_module_literal(sink, literal.value.as_str(), literal.span());
}

/// Reports a `core-js/modules/es.<feature>` (or `core-js-pure` mirror)
/// module specifier whose feature is a proven built-in.
fn check_module_literal(sink: &mut IssueSink<'_>, specifier: &str, span: oxc_span::Span) {
    let feature = specifier
        .strip_prefix("core-js/modules/")
        .or_else(|| specifier.strip_prefix("core-js-pure/modules/"));
    let Some(feature) = feature else {
        return;
    };
    if !BUILTIN_FEATURES.contains(&feature) {
        return;
    }
    sink.emit_span(RuleScope::Both, "S7742", "Use built-in instead.", span);
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7742_flags_pinned_exceljs_sites() {
        // Pinned oracle: exceljs@5bed18b lib/exceljs.browser.js:4-22 and
        // spec/utils/verquire.js:11-13 — the ten `core-js/modules/es.*`
        // requires whose features are built-ins at the project's
        // `engines.node >= 8.3.0` target. `es.promise`,
        // `es.promise.finally`, `es.symbol.async-iterator`,
        // `es.array.iterator`, and `regenerator-runtime/runtime` stay
        // silent exactly like the reference run.
        let source = "\
require('core-js/modules/es.promise');
require('core-js/modules/es.promise.finally');
require('core-js/modules/es.object.assign');
require('core-js/modules/es.object.keys');
require('core-js/modules/es.object.values');
require('core-js/modules/es.symbol');
require('core-js/modules/es.symbol.async-iterator');
require('core-js/modules/es.array.iterator');
require('core-js/modules/es.array.includes');
require('core-js/modules/es.array.find-index');
require('core-js/modules/es.array.find');
require('core-js/modules/es.string.from-code-point');
require('core-js/modules/es.string.includes');
require('core-js/modules/es.number.is-nan');
require('regenerator-runtime/runtime');
";
        let findings = js_keys(source);
        assert_eq!(count_key(&findings, "javascript:S7742"), 10);
        let issue = js(source)
            .issues
            .into_iter()
            .find(|issue| issue.rule_key == "javascript:S7742")
            .expect("pinned exceljs polyfill must be reported");
        assert_eq!(issue.message, "Use built-in instead.");
        assert_eq!(issue.range.start.line, 3);
    }

    #[test]
    fn s7742_flags_import_and_core_js_pure_forms() {
        let source = "\
import 'core-js/modules/es.object.assign';
import 'core-js-pure/modules/es.array.find';
const x = import('core-js/modules/es.string.includes');
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7742"), 3);
    }

    #[test]
    fn s7742_unavailable_features_and_other_paths_stay_silent() {
        // Features not built-in at the conservative floor, non-`modules`
        // entry paths, the bare bundle, and non-core-js polyfills.
        let source = "\
require('core-js/modules/es.promise');
require('core-js/modules/es.array.flat');
require('core-js/modules/es.string.match-all');
require('core-js/modules/es.object.from-entries');
require('core-js/modules/esnext.array.group-by');
require('core-js/stable/object/assign');
require('core-js/actual/array/find');
require('core-js/features/string/includes');
require('core-js');
require('core-js-pure');
require('regenerator-runtime/runtime');
require('es6-promise');
require('polyfill-array-find');
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7742"), 0);
    }

    #[test]
    fn s7742_relative_and_non_literal_specifiers_stay_silent() {
        let source = "\
require('./core-js/modules/es.object.assign');
require(name);
import './polyfill';
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7742"), 0);
    }

    #[test]
    fn s7742_reports_in_both_languages() {
        let source = "import 'core-js/modules/es.object.values';\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7742"), 1);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7742"), 1);
    }

    #[test]
    fn s7742_stays_silent_in_test_files_like_reference_main_scope() {
        let source = "require('core-js/modules/es.object.assign');\n";
        let test_report = crate::analyze(
            PathBuf::from("spec/utils/verquire.spec.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&test_report), "javascript:S7742"), 0);
        let main_report = crate::analyze(
            PathBuf::from("spec/utils/verquire.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&main_report), "javascript:S7742"), 1);
    }
}
