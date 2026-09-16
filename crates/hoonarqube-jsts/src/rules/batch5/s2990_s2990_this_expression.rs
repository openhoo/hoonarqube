use super::collectors_hotspots::MiscCollector;
use crate::support::RuleScope;
use oxc_ast::ast::ThisExpression;
use oxc_span::GetSpan;

// `S2990` (upstream `S2990/rule.ts`) flags `this` used as the object of a
// member expression in the module/global scope. `this` inside a class
// (field initializers, computed keys, static blocks) is receiver-bound, and
// `this` at the top level of a CommonJS module is `module.exports` — neither
// refers to the global object.
impl MiscCollector<'_> {
    /// `S2990` logic for `this.<member>` at module level.
    pub(crate) fn check_s2990_this_expression(&mut self, it: &ThisExpression) {
        if self.function_depth == 0
            && self.class_depth == 0
            && self.ts_module_depth == 0
            && !self.commonjs_module
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S2990",
                "Remove this 'this'; it refers to the global object at module level.",
                it.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn module_level_member_this_is_flagged() {
        let script = js_keys("console.log(this.value);\n");
        assert_eq!(count_key(&script, "javascript:S2990"), 1);

        let esm = ts_keys("export const x = 1;\nconsole.log(this.value);\n");
        assert_eq!(count_key(&esm, "typescript:S2990"), 1);
    }

    #[test]
    fn class_field_initializer_this_stays_silent() {
        // Issue #513: `this` in a field initializer is the instance.
        let field = ts_keys(
            "class Emitter<T> {\n    event!: T;\n}\nclass Tracker {\n    private readonly _onDidChange = new Emitter<string>();\n    public readonly onDidChange = this._onDidChange.event;\n}\nexport { Tracker };\n",
        );
        assert_eq!(count_key(&field, "typescript:S2990"), 0);

        let static_block =
            ts_keys("class C {\n  static { this.setup(); }\n  static setup(): void {}\n}\n");
        assert_eq!(count_key(&static_block, "typescript:S2990"), 0);
    }

    #[test]
    fn commonjs_module_this_stays_silent() {
        // Issue #556: top-level `this` in a CommonJS file is `module.exports`.
        let cjs = js_keys(
            "\"use strict\";\nvar __createBinding = (this && this.__createBinding) || (Object.create ? function(){} : function(){});\nvar __exportStar = (this && this.__exportStar) || function(m, exports) {};\n",
        );
        assert_eq!(count_key(&cjs, "javascript:S2990"), 0);

        let exports_ref = js_keys("exports.handler = this.handler;\n");
        assert_eq!(count_key(&exports_ref, "javascript:S2990"), 0);

        let require_ref = js_keys("var fs = require('fs');\nthis.fs = fs;\n");
        assert_eq!(count_key(&require_ref, "javascript:S2990"), 0);
    }

    #[test]
    fn function_scoped_this_stays_silent() {
        let method = js_keys("function context() {\n  return this.value;\n}\n");
        assert_eq!(count_key(&method, "javascript:S2990"), 0);
    }
}
