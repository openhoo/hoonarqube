// Rule module s7722_error_message (generated).
//
// `typescript:S7722` — Built-in error objects should have meaningful
// messages. Reference semantics: eslint-plugin-unicorn `error-message`
// wrapped by SonarJS S7722 (which suppresses stack-trace-capture patterns):
// constructing or calling a built-in error constructor (`Error`,
// `EvalError`, `RangeError`, `ReferenceError`, `SyntaxError`, `TypeError`,
// `URIError`, `AggregateError`, `SuppressedError`) without a message
// argument is reported on the expression; a message argument that is
// statically known to be a non-string or the empty string is reported on
// the argument; statically unknown arguments stay silent. `AggregateError`
// carries its message at index 1 and `SuppressedError` at index 2; spread
// arguments at or before the message index stay silent; shadowed
// constructors stay silent. Direct `.stack` reads of a fresh error and
// variables used exclusively for such reads are deliberate stack-capture
// code and stay silent.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7722_flags_pinned_zod_assert_never_anchor() {
        // Pinned anchor: colinhacks/zod@46da957
        // packages/zod/src/v3/helpers/util.ts:8 `throw new Error();`
        let source = "export function assertNever(_x: never): never {\n\
                      throw new Error();\n\
                      }\n";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7722"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7722")
            .expect("pinned zod assertNever empty error must be reported");
        assert_eq!(issue.message, "Pass a message to the `Error` constructor.");
        assert_eq!(issue.range.start.line, 2);
        assert_eq!(issue.range.start.column, "throw ".len() as u32);
        assert_eq!(issue.range.end.line, 2);
        assert_eq!(issue.range.end.column, "throw new Error();".len() as u32);
    }

    #[test]
    fn s7722_flags_every_builtin_error_constructor_and_call_form() {
        let source = "\
new EvalError();
new RangeError();
new ReferenceError();
new SyntaxError();
new TypeError();
new URIError();
new AggregateError();
new SuppressedError();
Error();
TypeError('meaningful');
";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7722"), 9);
    }

    #[test]
    fn s7722_aggregate_and_suppressed_message_indices_match_reference() {
        let source = "\
new AggregateError();
new AggregateError(entries);
new AggregateError(entries, 'many failures');
new SuppressedError();
new SuppressedError(cause);
new SuppressedError(cause, 'after');
";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7722"), 3);
    }

    #[test]
    fn s7722_reports_non_string_and_empty_message_arguments() {
        let source = "\
new Error(42);
new Error(true);
new Error(null);
new Error(undefined);
new Error([]);
new Error({});
new Error('');
new Error('boom');
new Error(someVariable);
new Error(`ok`);
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7722"), 7);
        let not_strings = filtered(&report, "typescript:S7722");
        assert_eq!(
            not_strings
                .iter()
                .filter(|message| *message == "Error message should be a string.")
                .count(),
            6
        );
        assert_eq!(
            not_strings
                .iter()
                .filter(|message| *message == "Error message should not be an empty string.")
                .count(),
            1
        );
        let numeric = report
            .issues
            .iter()
            .find(|issue| issue.range.start.line == 1)
            .expect("the numeric message argument must be reported");
        assert_eq!(numeric.message, "Error message should be a string.");
        assert_eq!(numeric.range.start.column, "new Error(".len() as u32);
    }

    #[test]
    fn s7722_suppresses_reference_stack_capture_patterns() {
        let silent = "\
const stack = new Error().stack;
new Error().stack;
const computed = new Error()['stack'];
let err = new Error();
console.log(err.stack);
const recorded = new Error().stack;
log(recorded);
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7722"), 0);
    }

    #[test]
    fn s7722_still_reports_when_variable_escapes_stack_reads() {
        let reported = "\
let err = new Error();
console.log(err.message);
let reassigned = new Error();
reassigned = new Error('later');
console.log(reassigned.stack);
let thrown = new Error();
throw thrown;
";
        assert_eq!(count_key(&ts_keys(reported), "typescript:S7722"), 3);
    }

    #[test]
    fn s7722_shadowed_constructors_and_spread_arguments_stay_silent() {
        let silent = "\
function wrap(Error) {
  return new Error();
}
const spread = new Error(...parts);
const aggregated = new AggregateError(...list);
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7722"), 0);
    }

    #[test]
    fn s7722_stays_silent_in_javascript_files() {
        let source = "throw new Error();\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7722"), 0);
    }
}
