use crate::support::{
    IssueSink, RuleScope, binding_identifier_name, identifier_name, member_object,
    property_key_name, source_slice, static_property_name, unparenthesized,
};
use oxc_ast::ast::{
    ArrowFunctionBody, ArrowFunctionExpression, AssignmentExpression, AssignmentOperator,
    AssignmentTarget, AssignmentTargetPropertyIdentifier, AssignmentTargetWithDefault,
    BinaryExpression, BinaryOperator, BindingIdentifier, BindingPattern, BlockStatement,
    BreakStatement, CallExpression, CatchClause, Class, ClassElement, ConditionalExpression,
    ContinueStatement, Declaration, DoWhileStatement, ExportDefaultDeclarationKind,
    ExportSpecifier, Expression, ForInStatement, ForOfStatement, ForStatement, FormalParameters,
    Function, IfStatement, ImportDeclaration, ImportDeclarationSpecifier, LogicalExpression,
    MemberExpression, MethodDefinition, MethodDefinitionKind, ModuleExportName, NewExpression,
    ReturnStatement, SimpleAssignmentTarget, Statement, StaticBlock, SwitchStatement,
    ThrowStatement, TryStatement, UnaryExpression, UnaryOperator, UpdateExpression,
    VariableDeclaration, VariableDeclarationKind, VariableDeclarator, WhileStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_binary_expression, walk_block_statement,
    walk_call_expression, walk_catch_clause, walk_class, walk_declaration,
    walk_export_default_declaration, walk_expression, walk_for_in_statement, walk_for_of_statement,
    walk_for_statement, walk_function, walk_member_expression, walk_method_definition,
    walk_new_expression, walk_program, walk_return_statement, walk_static_block,
    walk_switch_statement, walk_unary_expression, walk_variable_declaration,
    walk_variable_declarator,
};
use oxc_span::{GetSpan, Span};
use oxc_syntax::scope::ScopeFlags;
use std::collections::{BTreeMap, BTreeSet, HashMap};

mod bindings;
mod builder;
mod census;
mod flow;
mod helpers;

pub(crate) use bindings::*;
pub(crate) use builder::*;
pub(crate) use census::*;
pub(crate) use flow::*;
pub(crate) use helpers::*;

#[cfg(test)]
mod tests {
    use super::*;
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;

    fn binding<'m>(model: &'m TbModel<'_>, name: &str, global: bool) -> &'m TbBinding<'m> {
        model
            .bindings
            .iter()
            .find(|binding| binding.name == name && binding.global == global)
            .unwrap_or_else(|| panic!("no `{name}` binding with global={global}"))
    }
    fn with_model(source: &str, check: impl FnOnce(&TbModel<'_>)) {
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
        let model = build_tb_model(&parsed.program);
        check(&model);
    }
    /// The per-iteration write of a `for (let v of …)` / `for (let v in …)`
    /// head must resolve onto the loop binding itself: its event is recorded
    #[test]
    fn loop_head_let_write_lands_on_the_binding() {
        for source in [
            "let xs = [1];\nfor (let v of xs) {\n}\n",
            "let xs = [1];\nfor (let v in xs) {\n}\n",
        ] {
            with_model(source, |model| {
                let binding = binding(model, "v", false);
                assert_eq!(binding.kind, TbKind::Let);
                assert_eq!(
                    binding.writes.len(),
                    1,
                    "per-iteration write must resolve in the loop scope",
                );
                assert!(
                    !model.implicit_globals.iter().any(|(name, _)| *name == "v"),
                    "`v` is declared; its write must not look implicit",
                );
            });
        }
    }

    #[test]
    fn loop_head_var_write_still_lands_on_the_hoisted_binding() {
        with_model("let xs = [1];\nfor (var w of xs) {\n}\n", |model| {
            let binding = binding(model, "w", true);
            assert_eq!(binding.kind, TbKind::Var);
            assert_eq!(binding.writes.len(), 1);
            assert!(!model.implicit_globals.iter().any(|(name, _)| *name == "w"));
        });
    }

    /// `const x = 1; for (const x of [x]) {}` — the iterable's `x` refers
    /// to the outer binding: the loop-head binding is not yet initialized
    /// where the iterable evaluates (TDZ), so it must not shadow there.
    #[test]
    fn iterable_resolves_outside_the_loop_head_scope() {
        with_model("const x = 1;\nfor (const x of [x]) {\n}\n", |model| {
            let outer = binding(model, "x", true);
            let head = binding(model, "x", false);
            assert_eq!(outer.reads.len(), 1, "iterable must read the outer `x`");
            assert!(
                head.reads.is_empty(),
                "iterable must not see the head binding"
            );
        });
    }

    #[test]
    fn body_and_closures_still_see_the_loop_head_binding() {
        let source = "const fns = [];\nfor (const x of [1]) {\n    fns.push(() => x);\n}\n";
        with_model(source, |model| {
            let head = binding(model, "x", false);
            assert_eq!(head.reads.len(), 1, "the arrow body reads the head binding");
        });
    }

    #[test]
    fn rest_parameters_are_declared_and_signature_minimum_uses_last_required_position() {
        with_model(
            "function f(...args) { args = []; return args; }\n",
            |model| {
                let args = binding(model, "args", false);
                assert_eq!(args.kind, TbKind::Param);
                assert_eq!(args.writes.len(), 1);
                assert!(model.implicit_globals.is_empty());
            },
        );

        let allocator = Allocator::default();
        let parsed =
            Parser::new(&allocator, "function f(a = 0, b) {}\n", SourceType::mjs()).parse();
        let model = build_tb_model(&parsed.program);
        let signature = binding(&model, "f", true)
            .arity
            .as_ref()
            .expect("signature");
        assert_eq!(signature.minimum, 2);
    }
}
