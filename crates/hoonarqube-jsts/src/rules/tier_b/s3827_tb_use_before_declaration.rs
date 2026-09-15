use super::s3827_globals::PREDEFINED_GLOBALS;
use crate::engine::scope_model::TbModel;
use crate::support::{IssueSink, RuleScope};
use std::collections::HashSet;

/// `S3827` (JS only) — reads of identifiers that resolve to no declaration at
/// all. Function declarations are hoisted, so using one before its textual
/// declaration is defined behavior and never a finding; a genuinely
/// undeclared name is what throws `ReferenceError`.
///
/// Writes to undeclared names, `typeof x` guards, and `with`-statement
/// references exclude the name (exclusions apply to occurrences from that
/// point on, mirroring the reference-order handling of the scope-based
/// original). Predefined execution-environment globals (`require`, `console`,
/// `describe`, ...) always resolve upstream and are never reported.
pub(crate) fn check_tb_use_before_declaration(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    let mut reported: HashSet<&str> = HashSet::new();
    for (name, span) in &model.unresolved_reads {
        if PREDEFINED_GLOBALS.binary_search(name).is_ok() {
            continue;
        }
        if !reported.insert(name) {
            continue;
        }
        sink.emit_span(
            RuleScope::JsOnly,
            "S3827",
            &format!(
                "\"{name}\" does not exist. Change its name or declare it so that its usage doesn't result in a \"ReferenceError\"."
            ),
            *span,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn undeclared_reads_are_reported_once_at_first_use() {
        let source = "function f() {\n  return missingHelper(1);\n}\nf();\nmissingHelper();\n";
        assert_eq!(filtered(&js(source), "S3827").len(), 1);
    }

    #[test]
    fn hoisted_function_and_var_usage_stay_clean() {
        let calls = js("later();\nfunction later() {}\n");
        assert_eq!(filtered(&calls, "S3827").len(), 0);
        let hoisted_export = js(
            "var app = module.exports = createApplication();\nfunction createApplication() {}\n",
        );
        assert_eq!(filtered(&hoisted_export, "S3827").len(), 0);
    }

    #[test]
    fn writes_typeof_and_with_exclude_the_name() {
        // Assignment targets never throw; the later read is excluded too.
        let written = js("count = 1;\nconsole.log(count);\n");
        assert_eq!(filtered(&written, "S3827").len(), 0);
        let typeof_guard =
            js("if (typeof legacyGlobal === 'undefined') {}\nconsole.log(legacyGlobal);\n");
        assert_eq!(filtered(&typeof_guard, "S3827").len(), 0);
        let with_statement = js("with (Math) { free(); }\n");
        assert_eq!(filtered(&with_statement, "S3827").len(), 0);
        // A read that happens before the name is ever written still throws.
        let read_first = js("console.log(counter);\ncounter = 1;\n");
        assert_eq!(filtered(&read_first, "S3827").len(), 1);
    }

    #[test]
    fn execution_environment_globals_never_fire() {
        let source =
            "const root = require('express');\nconsole.log(process.platform, Buffer.alloc(1));\n";
        assert_eq!(filtered(&js(source), "S3827").len(), 0);
    }
}
