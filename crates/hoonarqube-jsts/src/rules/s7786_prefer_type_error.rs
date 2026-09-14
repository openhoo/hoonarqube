// Rule module s7786_prefer_type_error (generated).
//
// `javascript:S7786` + `typescript:S7786` — Generic `Error` should be
// `TypeError` when thrown after type checking. Reference semantics:
// eslint-plugin-unicorn `prefer-type-error` at the version pinned by
// SonarJS 13.x (v65.0.1, wrapped by SonarJS S7786).
//
// A `throw new Error(...)` is reported when it is the only statement of
// its block, the block directly belongs to an `if`, and the `if` test
// proves a type/operation failure: global `isNaN(...)`/`isFinite(...)`
// calls, member type-check calls (`_.isFunction`, `util.isArray`, ...),
// `typeof` checks (also under `!`), `instanceof` against anything that is
// not an error-constructor-shaped name, and `&&`/`||` combinations of
// those. `instanceof Error`-style checks, plain truthiness/comparison
// tests, multi-statement bodies, and throws outside `if` blocks stay
// silent, preserving custom error intent, subclassing, messages, and
// control flow. The report anchors on the `Error` constructor with the
// reference message "`new Error()` is too unspecific for a type check.
// Use `new TypeError()` instead." No auto-fix is offered.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope};
use hoonarqube_ir::Issue;

/// Entry point: `javascript:S7786` + `typescript:S7786`
/// prefer-type-error check over the parsed program.
pub(crate) fn check(_ctx: &AnalysisContext) -> Vec<Issue> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    const MESSAGE: &str = concat!(
        "`new Error()` is too unspecific for a type check. ",
        "Use `new TypeError()` instead."
    );

    #[test]
    fn s7786_flags_pinned_express_anchors() {
        // Pinned anchors: expressjs/express@53d4a0d
        // lib/application.js:296 and lib/view.js:84 - lone throws behind
        // `typeof fn !== 'function'`.
        let source = "\
app.engine = function engine(ext, fn) {
  if (typeof fn !== 'function') {
    throw new Error('callback function required');
  }
};

View.prototype.lookup = function lookup(name) {
  var resolved = require(name).__express;

  if (typeof resolved !== 'function') {
    throw new Error('Module \"' + name + '\" does not provide a view engine.');
  }
};
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7786"), 2);
        for (line, prefix) in [
            (3u32, "    throw new "),
            (11, "    throw new "),
        ] {
            let issue = report
                .issues
                .iter()
                .find(|issue| {
                    issue.rule_key == "javascript:S7786"
                        && issue.range.start.line == line
                })
                .expect("each pinned express throw must be reported");
            assert_eq!(issue.message, MESSAGE);
            assert_eq!(
                issue.range.start.column,
                u32::try_from(prefix.len()).unwrap()
            );
            assert_eq!(
                issue.range.end.column,
                u32::try_from(prefix.len()).unwrap() + "Error".len() as u32
            );
        }
    }

    #[test]
    fn s7786_flags_pinned_zod_anchors() {
        // Pinned anchors: colinhacks/zod@46da957
        // packages/zod/src/v3/types.ts:3470/4380/4421.
        let source = "\
class ZodTuple {
  static create(schemas: unknown) {
    if (!Array.isArray(schemas)) {
      throw new Error('You must pass an array of schemas to z.tuple([ ... ])');
    }
    const refined = effect.refinement(acc, checkCtx);
    if (refined instanceof Promise) {
      throw new Error('Async refinement encountered during synchronous parse operation.');
    }
    const result = effect.transform(base.value, checkCtx);
    if (result instanceof Promise) {
      throw new Error(
        `Asynchronous transform encountered during synchronous parse operation.`
      );
    }
  }
}
";
        let keys = ts_keys(source);
        let flagged: Vec<u32> = keys
            .iter()
            .filter(|(key, _)| key == "typescript:S7786")
            .map(|(_, line)| *line)
            .collect();
        assert_eq!(flagged, vec![4, 8, 12]);
    }

    #[test]
    fn s7786_flags_reference_type_check_families() {
        let source = "\
function check(fn, value) {
  if (!isNaN(value)) {
    throw new Error('unexpected NaN');
  }
  if (typeof value === 'string' || typeof value === 'number') {
    throw new Error('primitive not allowed');
  }
  if (_.isPlainObject(value)) {
    throw new Error('plain object not allowed');
  }
  if (util.isArrayLike(value) && !isFinite(value)) {
    throw new Error('unexpected array-like');
  }
  return fn;
}
";
        let keys = js_keys(source);
        let flagged: Vec<u32> = keys
            .iter()
            .filter(|(key, _)| key == "javascript:S7786")
            .map(|(_, line)| *line)
            .collect();
        assert_eq!(flagged, vec![3, 6, 9, 12]);
    }

    #[test]
    fn s7786_controls_stay_silent() {
        let source = "\
function controls(fn, value, Box) {
  if (value instanceof Error) {
    throw new TypeError('already an error');
  }
  if (value instanceof Box) {
    log();
    throw new Error('not a lone throw');
  }
  if (value) {
    throw new Error('no type check');
  }
  if (value !== null) {
    throw new Error('plain comparison');
  }
  if (typeof fn !== 'function') {
    log(fn);
    throw new Error('two statements');
  }
  throw new Error('bare throw');
  function inner() {
    throw new Error('function body');
  }
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7786"), 0);
    }

    #[test]
    fn s7786_reports_in_both_languages() {
        let js_source = "\
function keep(value) {
  if (typeof value !== 'string') {
    throw new Error('string required');
  }
}
";
        let ts_source = "\
function keep(value: unknown) {
  if (typeof value !== 'string') {
    throw new Error('string required');
  }
}
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7786"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7786"), 1);
    }
}
