// Rule module s7746_useless_promise_resolve_reject (generated).
//
// `javascript:S7746` + `typescript:S7746` — Promise.resolve() and
// Promise.reject() should not be used in async functions or promise
// callbacks. Reference semantics: eslint-plugin-unicorn
// `no-useless-promise-resolve-reject` at the version pinned by SonarJS 13.x
// (v65.0.1, wrapped by SonarJS S7746): a `Promise.resolve(...)` or
// `Promise.reject(...)` call (non-optional member on the `Promise`
// identifier) whose result is returned, yielded, or is an arrow-function
// body is reported on the callee when the nearest enclosing function is
// `async` or a `.then()`/`.catch()`/`.finally()` callback. The wording
// distinguishes `return` from `yield`. Plain functions, awaited results,
// standalone statements, aliases, `new`, optional chains, and unrelated
// callbacks (`.map`) stay silent. No auto-fix is offered: rejection-order
// and microtask semantics must be qualified before any rewrite.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7746_flags_pinned_axios_on_adapter_rejection_anchor() {
        // Pinned anchor: axios/axios@18e7dfed lib/core/dispatchRequest.js:92
        // `return Promise.reject(reason);` inside `onAdapterRejection`, the
        // second `.then(onAdapterResolution, onAdapterRejection)` callback.
        let source = "\
function dispatch(config) {
  return adapter(config).then(
    function onAdapterResolution(response) {
      return transform(response);
    },
    function onAdapterRejection(reason) {
      if (reason && reason.response) {
        reason.response.headers = parse(reason.response.headers);
      }
      return Promise.reject(reason);
    }
  );
}
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7746"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S7746")
            .expect("pinned axios onAdapterRejection must be reported");
        assert_eq!(
            issue.message,
            "Prefer `throw error` over `return Promise.reject(error)`."
        );
        assert_eq!(issue.range.start.line, 9);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("      return ".len()).unwrap()
        );
        assert_eq!(issue.range.end.line, 9);
        assert_eq!(
            issue.range.end.column,
            u32::try_from("      return Promise.reject".len()).unwrap()
        );
    }

    #[test]
    fn s7746_flags_async_and_callback_forms() {
        let source = "\
async function load(check) {
  if (check) {
    return Promise.resolve(fallback());
  }
  return Promise.reject(new Error(\"no\"));
}
function viaThen() {
  return fetchIt().then((result) => Promise.resolve(result));
}
function viaThenRejection() {
  return fetchIt().then((result) => result, (error) => Promise.reject(error));
}
function viaCatch() {
  return fetchIt().catch((error) => Promise.reject(error));
}
async function* viaYield() {
  yield Promise.resolve(1);
}
function viaFinally() {
  return fetchIt().finally(() => Promise.resolve());
}
";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7746"), 7);
    }

    #[test]
    fn s7746_messages_match_reference_wording() {
        let source = "\
async function resolveValue() {
  return Promise.resolve(1);
}
async function* yieldValue() {
  yield Promise.resolve(2);
}
function rejectError() {
  return fetchIt().then(function () {}, function (error) {
    return Promise.reject(error);
  });
}
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7746"), 3);
        let messages: Vec<&str> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "typescript:S7746")
            .map(|issue| issue.message.as_str())
            .collect();
        assert!(messages.contains(&"Prefer `return value` over `return Promise.resolve(value)`."));
        assert!(messages.contains(&"Prefer `yield value` over `yield Promise.resolve(value)`."));
        assert!(messages.contains(&"Prefer `throw error` over `return Promise.reject(error)`."));
    }

    #[test]
    fn s7746_plain_functions_awaits_and_other_contexts_stay_silent() {
        let silent = "\
function plain() {
  return Promise.resolve(1);
}
async function awaited() {
  return await Promise.resolve(1);
}
function mapped(list) {
  return list.map((x) => Promise.resolve(x));
}
function aliased() {
  const P = Promise;
  return P.resolve(1);
}
function standalone() {
  Promise.resolve(1);
}
function constructed() {
  return new Promise.resolve(1);
}
function chained(lib) {
  return lib.Promise.resolve(1);
}
function optionalized() {
  return Promise?.resolve(1);
}
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7746"), 0);
    }

    #[test]
    fn s7746_reports_in_both_languages() {
        let source = "\
async function both(value) {
  return Promise.resolve(value);
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7746"), 1);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7746"), 1);
    }
}
