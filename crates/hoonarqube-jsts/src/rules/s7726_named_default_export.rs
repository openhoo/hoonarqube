// Rule module s7726_named_default_export (generated).
//
// `javascript:S7726` / `typescript:S7726` — Default exports should be
// named. Reference semantics: eslint-plugin-unicorn
// `no-anonymous-default-export`: an anonymous function, async function,
// generator function, async generator function, or class in a default
// export is reported with "The <description> should be named.", including
// parenthesized function and class expressions, and the CommonJS forms
// `module.exports = <anonymous>` and `exports = <anonymous>`. Named
// declarations, aliases of existing bindings, and non-function defaults
// (literals, object and array literals) stay silent. Findings span the
// anonymous declaration.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    AssignmentTarget, Class, ExportDefaultDeclaration, ExportDefaultDeclarationKind, Expression,
    Function,
};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;

/// Entry point: `S7726` anonymous default export check over the parsed
/// program; active for both JavaScript and TypeScript files.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut collector = DefaultExportCollector {
        sink: IssueSink {
            index: ctx.index,
            language: ctx.language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(ctx.program);
    collector.sink.issues
}

struct DefaultExportCollector<'index> {
    sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for DefaultExportCollector<'_> {
    fn visit_export_default_declaration(&mut self, it: &ExportDefaultDeclaration<'a>) {
        match &it.declaration {
            ExportDefaultDeclarationKind::FunctionDeclaration(function)
            | ExportDefaultDeclarationKind::FunctionExpression(function) => {
                self.report_anonymous_function(function);
            }
            ExportDefaultDeclarationKind::ClassDeclaration(class)
            | ExportDefaultDeclarationKind::ClassExpression(class) => {
                self.report_anonymous_class(class);
            }
            ExportDefaultDeclarationKind::ArrowFunctionExpression(arrow) => {
                self.report(arrow.span(), "arrow function");
            }
            // Parenthesized function and class expressions keep the
            // reference behavior, which ignores redundant parentheses.
            ExportDefaultDeclarationKind::ParenthesizedExpression(parenthesized) => {
                self.report_anonymous_expression(&parenthesized.expression);
            }
            _ => {}
        }
        walk::walk_export_default_declaration(self, it);
    }

    fn visit_expression_statement(&mut self, it: &oxc_ast::ast::ExpressionStatement<'a>) {
        if let Expression::AssignmentExpression(assignment) = &it.expression
            && targets_common_js_exports(&assignment.left)
        {
            match &assignment.right {
                Expression::SequenceExpression(sequence) => {
                    if let Some(last) = sequence.expressions.last() {
                        self.report_anonymous_expression(last);
                    }
                }
                expression => self.report_anonymous_expression(expression),
            }
        }
        walk::walk_expression_statement(self, it);
    }
}

impl DefaultExportCollector<'_> {
    fn report(&mut self, span: oxc_span::Span, description: &str) {
        self.sink.emit_span(
            RuleScope::Both,
            "S7726",
            &format!("The {description} should be named."),
            span,
        );
    }

    fn report_anonymous_function(&mut self, function: &Function<'_>) {
        if function.id.is_none() {
            self.report(function.span(), function_description(function));
        }
    }

    fn report_anonymous_class(&mut self, class: &Class<'_>) {
        if class.id.is_none() {
            self.report(class.span(), "class");
        }
    }

    fn report_anonymous_expression(&mut self, expression: &Expression<'_>) {
        match unparenthesized(expression) {
            Expression::FunctionExpression(function) => {
                self.report_anonymous_function(function);
            }
            Expression::ClassExpression(class) => self.report_anonymous_class(class),
            Expression::ArrowFunctionExpression(arrow) => {
                self.report(arrow.span(), "arrow function");
            }
            _ => {}
        }
    }
}

/// The reference `getFunctionNameWithKind` description of an anonymous
/// function.
fn function_description(function: &Function<'_>) -> &'static str {
    match (function.r#async, function.generator) {
        (true, true) => "async generator function",
        (true, false) => "async function",
        (false, true) => "generator function",
        (false, false) => "function",
    }
}

/// Whether the assignment target is `module.exports` or the bare `exports`
/// identifier, the `CommonJS` default-export surfaces of the reference rule.
fn targets_common_js_exports(target: &AssignmentTarget<'_>) -> bool {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(identifier) => identifier.name == "exports",
        AssignmentTarget::StaticMemberExpression(member) => {
            !member.optional
                && member.property.name == "exports"
                && matches!(
                    &member.object,
                    Expression::Identifier(module) if module.name == "module"
                )
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7726_flags_pinned_anonymous_arrow_anchor_in_axios() {
        // Pinned anchor: axios@18e7dfed lib/helpers/parseHeaders.js:41
        // `export default (rawHeaders) => {`
        let source = "export default (rawHeaders) => {\n\
                      const parsed = {};\n\
                      return parsed;\n\
                      };\n";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7726"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S7726")
            .expect("the pinned axios anonymous default arrow must be reported");
        assert_eq!(issue.message, "The arrow function should be named.");
        assert_eq!(issue.range.start.line, 1);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("export default ".len()).unwrap()
        );
    }

    #[test]
    fn s7726_flags_pinned_zod_locale_anchor_in_typescript() {
        // Pinned anchor: colinhacks/zod@46da957
        // packages/zod/src/v4/locales/ar.ts:115, representative of all 63
        // locale modules exporting an anonymous default function.
        let source = "export default function (): { localeError: string } {\n\
                      return { localeError: '' };\n\
                      }\n";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7726"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7726")
            .expect("the pinned zod locale default function must be reported");
        assert_eq!(issue.message, "The function should be named.");
        assert_eq!(issue.range.start.line, 1);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("export default ".len()).unwrap()
        );
    }

    #[test]
    fn s7726_flags_anonymous_function_class_and_commonjs_forms() {
        let source = "\
export default function () {}
export default async function () {}
export default function* () {}
export default async function* () {}
export default class {}
export default (function () {});
module.exports = function () {};
exports = () => ({});
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7726"), 8);
        let messages: Vec<String> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7726")
            .map(|issue| issue.message.clone())
            .collect();
        assert!(messages.contains(&"The async function should be named.".to_string()));
        assert!(messages.contains(&"The generator function should be named.".to_string()));
        assert!(messages.contains(&"The async generator function should be named.".to_string()));
        assert!(messages.contains(&"The class should be named.".to_string()));
    }

    #[test]
    fn s7726_named_exports_and_non_function_defaults_stay_silent() {
        let silent = "\
export default function parseHeaders(rawHeaders) {}
export default class HeaderParser {}
export default 42;
export default { parse };
export default [];
const impl = () => ({});
export default impl;
export default (function named() {});
module.exports = { parse: parseHeaders };
";
        assert_eq!(count_key(&js_keys(silent), "javascript:S7726"), 0);
    }

    #[test]
    fn s7726_flags_both_javascript_and_typescript_files() {
        let source = "export default () => ({});\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7726"), 1);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7726"), 1);
    }
}
