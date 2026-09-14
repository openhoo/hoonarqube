// Rule module s7737_object_default_param (generated).
//
// `javascript:S7737` + `typescript:S7737` — Objects should not be used as
// default parameters. Reference semantics: eslint-plugin-unicorn
// `no-object-as-default-parameter` at the version pinned by SonarJS 13.x
// (v65.0.1, wrapped by SonarJS S7737): a function parameter whose default
// value is a non-empty object literal is reported. Identifier parameters
// are anchored on the identifier and name the parameter in the message;
// destructuring parameters are anchored on the object literal. Defaults of
// nested binding patterns (not direct function parameters) and empty or
// non-object defaults stay silent. No auto-fix is offered: a shared
// constant would change the fresh mutable-allocation semantics that the
// zod v4 `ProcessParams` defaults rely on.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{BindingPattern, Expression, FormalParameter};
use oxc_span::GetSpan;

/// Entry point: `javascript:S7737` + `typescript:S7737` object default
/// parameter check over the parsed program. Requires the semantic model,
/// so recoverable-parse files stay silent.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    let Some(semantic) = ctx.semantic else {
        return sink.issues;
    };
    for node in semantic.nodes().iter() {
        if let AstKind::FormalParameter(parameter) = node.kind() {
            check_parameter(&mut sink, parameter);
        }
    }
    sink.issues
}

/// Reports one function parameter whose default value is a non-empty object
/// literal. Identifier parameters are anchored on the identifier; every
/// other pattern is anchored on the object literal. Defaults nested inside
/// binding patterns are not direct parameter defaults and stay silent.
fn check_parameter(sink: &mut IssueSink<'_>, parameter: &FormalParameter<'_>) {
    let Some(initializer) = parameter.initializer.as_deref() else {
        return;
    };
    let Expression::ObjectExpression(object) = unparenthesized(initializer) else {
        return;
    };
    if object.properties.is_empty() {
        return;
    }
    if let BindingPattern::BindingIdentifier(identifier) = &parameter.pattern {
        sink.emit_span(
            RuleScope::Both,
            "S7737",
            &format!(
                "Do not use an object literal as default for parameter `{}`.",
                identifier.name
            ),
            identifier.span,
        );
    } else {
        sink.emit_span(
            RuleScope::Both,
            "S7737",
            "Do not use an object literal as default.",
            object.span(),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7737_flags_pinned_zod_custom_params_anchor() {
        // Pinned anchor: colinhacks/zod@46da957 packages/zod/src/v3/types.ts:5041
        // `params: string | CustomParams | ... = { message: \`Input not instance
        // of ${cls.name}\` }` — reported on the identifier with the parameter
        // name in the message.
        let source = "\
export function custom<T>(
  check?: (data: any) => any,
  params: { message?: string } = { message: \"Input not instance\" },
): T {
  return check as never;
}
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7737"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7737")
            .expect("pinned zod custom params default must be reported");
        assert_eq!(
            issue.message,
            "Do not use an object literal as default for parameter `params`."
        );
        assert_eq!(issue.range.start.line, 3);
        assert_eq!(issue.range.start.column, 2);
        assert_eq!(issue.range.end.line, 3);
        assert_eq!(
            issue.range.end.column,
            u32::try_from("  params".len()).unwrap()
        );
    }

    #[test]
    fn s7737_flags_pinned_zod_process_params_controls_without_fix() {
        // Pinned controls: colinhacks/zod@46da957
        // packages/zod/src/v4/core/to-json-schema.ts:216 and
        // packages/zod/src/v4/core/json-schema-generator.ts:104
        // `_params: ProcessParams = { path: [], schemaPath: [] }` — reported
        // like the reference, but a shared constant must never replace the
        // fresh mutable arrays, so no fix is offered.
        let source = "\
interface ProcessParams {
  path: (string | number)[];
  schemaPath: string[];
}

declare function process(
  schema: unknown,
  _params: ProcessParams = { path: [], schemaPath: [] },
): unknown;
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7737"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7737")
            .expect("pinned ProcessParams default must be reported");
        assert_eq!(
            issue.message,
            "Do not use an object literal as default for parameter `_params`."
        );
        assert_eq!(issue.range.start.line, 8);
        assert!(
            report.issues.iter().all(|issue| issue.fix.is_none()),
            "S7737 must not offer an automatic fix"
        );
    }

    #[test]
    fn s7737_flags_destructured_parameter_defaults_on_the_object() {
        // Non-identifier parameter patterns are anchored on the object
        // literal with the plain wording.
        let source = "\
function withPatternDefaults({ option } = { option: 1, fallback: 2 }) {
  return option;
}
const arrow = ([first] = { 0: true }) => first;
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7737"), 2);
        assert!(
            report
                .issues
                .iter()
                .all(|issue| issue.message == "Do not use an object literal as default.")
        );
    }

    #[test]
    fn s7737_empty_and_non_object_defaults_stay_silent() {
        let silent = "\
function emptyDefault(params = {}) {
  return params;
}
function arrayDefault(list = []) {
  return list;
}
function stringDefault(name = \"x\") {
  return name;
}
const assigned: Record<string, unknown> = {};
assigned.later = { nested: 1 };
function nestedDestructure({ inner = { kept: 1 } } = {}) {
  return inner;
}
function plainWithoutDefault(value: unknown) {
  return value;
}
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7737"), 0);
    }

    #[test]
    fn s7737_reports_in_both_languages() {
        let source = "\
function jsForm(params = { from: \"js\" }) {
  return params;
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7737"), 1);
        assert_eq!(count_key(&js_keys(source), "typescript:S7737"), 0);
    }
}
