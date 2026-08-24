use super::walker::ReactCollector;
use crate::rules::expression::walker::call_property;
use crate::support::RuleScope;
use crate::support::member_root_name;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_ast::ast::ImportDeclaration;
use oxc_ast::ast::ImportDeclarationSpecifier;
use oxc_ast::ast::ModuleExportName;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6750`, `S6788`, `S6789`, and the call half of `S6957`: deprecated
    /// `ReactDOM` entry points and `this.isMounted` probes.
    pub(crate) fn check_react_dom_calls(&mut self, call: &CallExpression<'_>) {
        if let Some((property, member)) = call_property(call) {
            let root = member_root_name(member);
            let is_render = root == Some("ReactDOM") && property == "render";
            let is_find_dom_node = root == Some("ReactDOM") && property == "findDOMNode";
            let is_create_class =
                (root == Some("React") || root == Some("ReactDOM")) && property == "createClass";
            if is_render && self.expression_statement_depth == 0 {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6750",
                    "'ReactDOM.render' should be called as a statement; do not consume its return value.",
                    call.span(),
                );
            }
            if is_find_dom_node {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6788",
                    "'ReactDOM.findDOMNode' is deprecated; use refs instead.",
                    call.span(),
                );
            }
            if is_render || is_find_dom_node || is_create_class {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6957",
                    "Remove this deprecated React API usage.",
                    call.span(),
                );
            }
        }
        if callee_this_property(call) == Some("isMounted") {
            self.sink.emit_span(
                RuleScope::Both,
                "S6789",
                "'this.isMounted' is deprecated and unreliable; track mounted state explicitly.",
                call.callee.span(),
            );
        }
    }

    /// `S6957` import half: `prop-types` sources and `PropTypes` names.
    pub(crate) fn check_deprecated_import(&mut self, declaration: &ImportDeclaration<'_>) {
        let prop_types_import = declaration.source.value == "prop-types"
            || declaration
                .specifiers
                .iter()
                .flatten()
                .any(|specifier| match specifier {
                    ImportDeclarationSpecifier::ImportSpecifier(imported) => {
                        module_export_name_is(&imported.imported, "PropTypes")
                    }
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(defaulted) => {
                        defaulted.local.name == "PropTypes"
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(_) => false,
                });
        if prop_types_import {
            self.sink.emit_span(
                RuleScope::Both,
                "S6957",
                "Remove this deprecated React API usage; PropTypes checks vanish in production builds.",
                declaration.span(),
            );
        }
    }
}

/// Property name of a `this.<property>` callee, if the call target is
/// exactly that shape.
pub(crate) fn callee_this_property<'a>(call: &'a CallExpression<'a>) -> Option<&'a str> {
    match &call.callee {
        Expression::StaticMemberExpression(member)
            if matches!(&member.object, Expression::ThisExpression(_)) =>
        {
            Some(&member.property.name)
        }
        _ => None,
    }
}

/// Whether a module export name spells `expected` (`import {a as b}` keeps
/// the imported spelling).
pub(crate) fn module_export_name_is(name: &ModuleExportName<'_>, expected: &str) -> bool {
    match name {
        ModuleExportName::IdentifierName(identifier) => identifier.name == expected,
        ModuleExportName::IdentifierReference(reference) => reference.name == expected,
        ModuleExportName::StringLiteral(literal) => literal.value == expected,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6750_flags_consumed_render_return_value() {
        let findings = jsx_keys("const el = ReactDOM.render(<span></span>, node);\n");
        assert_eq!(count_key(&findings, "javascript:S6750"), 1);
    }

    #[test]
    fn s6750_allows_statement_render_but_still_reports_s6957() {
        let findings = jsx_keys("ReactDOM.render(<span></span>, node);\n");
        assert_eq!(count_key(&findings, "javascript:S6750"), 0);
        assert_eq!(count_key(&findings, "javascript:S6957"), 1);
    }

    #[test]
    fn s6788_flags_find_dom_node_call() {
        let findings = js_keys("ReactDOM.findDOMNode(this).focus();\n");
        assert_eq!(count_key(&findings, "javascript:S6788"), 1);
    }

    #[test]
    fn s6789_flags_this_is_mounted_probe() {
        let findings = js_keys("if (this.isMounted()) {\n  done();\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6789"), 1);
    }

    #[test]
    fn s6789_allows_is_mounted_on_other_object() {
        let findings = js_keys("if (widget.isMounted()) {\n  done();\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6789"), 0);
    }

    #[test]
    fn s6957_flags_prop_types_import() {
        let findings = js_keys("import PropTypes from 'prop-types';\n");
        assert_eq!(count_key(&findings, "javascript:S6957"), 1);
    }

    #[test]
    fn s6957_allows_current_react_api() {
        let findings =
            js_keys("import React from 'react';\nconst x = React.createElement('div');\n");
        assert_eq!(count_key(&findings, "javascript:S6957"), 0);
    }
}
