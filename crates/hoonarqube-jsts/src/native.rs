//! Independently implemented non-Sonar JavaScript/TypeScript rules.

use std::collections::{HashMap, HashSet};

use hoonarqube_ir::Issue;
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BinaryOperator, BindingPattern, CallExpression, Expression, ForStatement, ForStatementInit,
    ImportDeclaration, ImportDeclarationSpecifier, ModuleExportName, UpdateOperator,
    VariableDeclarator,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_call_expression, walk_for_statement, walk_import_declaration, walk_variable_declarator,
};
use oxc_parser::Parser;
use oxc_span::{SourceType, Span};
use oxc_syntax::scope::ScopeFlags;

use crate::JstsLanguage;
use crate::engine::scope_model::{TbModel, build_tb_model};
use crate::rules::shared::{argument_expression, call_property};
use crate::support::{
    LineIndex, binding_identifier_name, identifier_name, member_object, sort_issues,
    static_property_name, unparenthesized, update_target_name,
};

pub(crate) fn analyze(source: &str, language: JstsLanguage) -> Vec<Issue> {
    let allocator = Allocator::default();
    let source_type = match language {
        JstsLanguage::JavaScript => SourceType::mjs(),
        JstsLanguage::TypeScript => SourceType::ts(),
    };
    let parsed = Parser::new(&allocator, source, source_type).parse();
    if parsed.diagnostics.errors().next().is_some() {
        return Vec::new();
    }
    let index = LineIndex::new(source);

    let mut syntax_facts = StreamSyntaxFacts::new();
    syntax_facts.visit_program(&parsed.program);
    let model = build_tb_model(&parsed.program);
    let facts = syntax_facts.resolve(&model);

    let mut collector = NativeCollector {
        index: &index,
        language,
        binding_by_read: facts.binding_by_read,
        stream_origins: facts.stream_origins,
        writes: facts.writes,
        error_handlers: facts.error_handlers,
        issues: Vec::new(),
    };
    collector.visit_program(&parsed.program);
    sort_issues(&mut collector.issues);
    collector.issues.dedup();
    collector.issues
}

struct StreamSyntaxFacts {
    fs_declarations: Vec<Span>,
    direct_factory_declarations: Vec<Span>,
    stream_candidates: Vec<(Span, StreamFactorySite)>,
    handler_sites: Vec<(Span, u32)>,
}

#[derive(Clone, Copy)]
enum StreamFactorySite {
    Module(Span),
    Direct(Span),
}

struct ResolvedStreamFacts {
    binding_by_read: HashMap<(u32, u32), usize>,
    stream_origins: HashMap<usize, u32>,
    writes: HashMap<usize, Vec<u32>>,
    error_handlers: HashMap<usize, Vec<u32>>,
}

impl StreamSyntaxFacts {
    fn new() -> Self {
        Self {
            fs_declarations: Vec::new(),
            direct_factory_declarations: Vec::new(),
            stream_candidates: Vec::new(),
            handler_sites: Vec::new(),
        }
    }

    fn resolve(self, model: &TbModel<'_>) -> ResolvedStreamFacts {
        let binding_by_decl: HashMap<_, _> = model
            .bindings
            .iter()
            .enumerate()
            .map(|(id, binding)| (span_key(binding.decl), id))
            .collect();
        let binding_by_read: HashMap<_, _> = model
            .bindings
            .iter()
            .enumerate()
            .flat_map(|(id, binding)| binding.reads.iter().map(move |span| (span_key(*span), id)))
            .collect();
        let fs_bindings = declaration_bindings(&self.fs_declarations, &binding_by_decl);
        let direct_factories =
            declaration_bindings(&self.direct_factory_declarations, &binding_by_decl);
        let mut stream_origins = HashMap::new();
        for (declaration, factory) in self.stream_candidates {
            let factory_binding = match factory {
                StreamFactorySite::Module(site) => binding_by_read
                    .get(&span_key(site))
                    .filter(|id| fs_bindings.contains(id)),
                StreamFactorySite::Direct(site) => binding_by_read
                    .get(&span_key(site))
                    .filter(|id| direct_factories.contains(id)),
            };
            if factory_binding.is_some()
                && let Some(binding) = binding_by_decl.get(&span_key(declaration))
            {
                stream_origins.insert(*binding, declaration.start);
            }
        }
        let mut error_handlers = HashMap::<usize, Vec<u32>>::new();
        for (site, offset) in self.handler_sites {
            if let Some(binding) = binding_by_read.get(&span_key(site))
                && stream_origins.contains_key(binding)
            {
                error_handlers.entry(*binding).or_default().push(offset);
            }
        }
        let writes = model
            .bindings
            .iter()
            .enumerate()
            .filter(|(_, binding)| !binding.writes.is_empty())
            .map(|(id, binding)| (id, binding.writes.iter().map(|span| span.start).collect()))
            .collect();
        ResolvedStreamFacts {
            binding_by_read,
            stream_origins,
            writes,
            error_handlers,
        }
    }
}

fn span_key(span: Span) -> (u32, u32) {
    (span.start, span.end)
}

fn declaration_bindings(
    declarations: &[Span],
    binding_by_decl: &HashMap<(u32, u32), usize>,
) -> HashSet<usize> {
    declarations
        .iter()
        .filter_map(|span| binding_by_decl.get(&span_key(*span)).copied())
        .collect()
}

impl<'a> Visit<'a> for StreamSyntaxFacts {
    fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'a>) {
        if is_fs_module(declaration.source.value.as_str()) {
            for specifier in declaration.specifiers.as_deref().into_iter().flatten() {
                match specifier {
                    ImportDeclarationSpecifier::ImportSpecifier(specifier)
                        if is_create_read_stream_import(&specifier.imported) =>
                    {
                        self.direct_factory_declarations.push(specifier.local.span);
                    }
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => {
                        self.fs_declarations.push(specifier.local.span);
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => {
                        self.fs_declarations.push(specifier.local.span);
                    }
                    ImportDeclarationSpecifier::ImportSpecifier(_) => {}
                }
            }
        }
        walk_import_declaration(self, declaration);
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if let (BindingPattern::BindingIdentifier(binding), Some(init)) =
            (&declarator.id, declarator.init.as_ref())
        {
            if is_fs_require(init) {
                self.fs_declarations.push(binding.span);
            }
            if let Some(factory) = create_read_stream_factory_site(init) {
                self.stream_candidates.push((binding.span, factory));
            }
        }
        walk_variable_declarator(self, declarator);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some((property, member)) = call_property(call)
            && matches!(property, "on" | "once" | "addListener")
            && call
                .arguments
                .first()
                .and_then(argument_expression)
                .is_some_and(|argument| {
                    matches!(argument, Expression::StringLiteral(literal) if literal.value == "error")
                })
            && let Expression::Identifier(receiver) = unparenthesized(member_object(member))
        {
            self.handler_sites.push((receiver.span, call.span.start));
        }
        walk_call_expression(self, call);
    }
}

struct NativeCollector<'index> {
    index: &'index LineIndex<'index>,
    language: JstsLanguage,
    binding_by_read: HashMap<(u32, u32), usize>,
    stream_origins: HashMap<usize, u32>,
    writes: HashMap<usize, Vec<u32>>,
    error_handlers: HashMap<usize, Vec<u32>>,
    issues: Vec<Issue>,
}

impl NativeCollector<'_> {
    fn emit(&mut self, suffix: &str, message: &str, span: Span) {
        self.issues.push(Issue::new(
            format!("hoonarqube-{}:{suffix}", self.language.prefix()),
            message,
            self.index.range(span),
        ));
    }

    fn check_stream_pipe(&mut self, call: &CallExpression<'_>) {
        let Some(("pipe", member)) = call_property(call) else {
            return;
        };
        let Expression::Identifier(receiver) = unparenthesized(member_object(member)) else {
            return;
        };
        let Some(binding) = self.binding_by_read.get(&span_key(receiver.span)) else {
            return;
        };
        let Some(origin) = self.stream_origins.get(binding) else {
            return;
        };
        if self.writes.get(binding).is_some_and(|writes| {
            writes
                .iter()
                .any(|offset| *origin < *offset && *offset < call.span.start)
        }) {
            return;
        }
        let handled = self
            .error_handlers
            .get(binding)
            .is_some_and(|offsets| offsets.iter().any(|offset| *offset < call.span.start));
        if !handled {
            self.emit(
                "unhandled-error-in-stream-pipeline",
                "Handle errors on this source stream or use stream.pipeline.",
                call.span,
            );
        }
    }

    fn check_shifting_loop(&mut self, loop_: &ForStatement<'_>) {
        let Some(counter) = loop_counter(loop_) else {
            return;
        };
        let Some(array) = loop_array(loop_.test.as_ref(), &counter) else {
            return;
        };
        if !loop_increments_counter(loop_, &counter) {
            return;
        }
        let mut body = ShiftingBody::new(&array, &counter);
        body.visit_statement(&loop_.body);
        if body.adjusts_counter || body.breaks {
            return;
        }
        for span in body.splice_calls {
            self.emit(
                "loop-iteration-skipped-due-to-shifting",
                "Adjust the loop counter after splice or stop iterating after this removal.",
                span,
            );
        }
    }
}

impl<'a> Visit<'a> for NativeCollector<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        self.check_stream_pipe(call);
        walk_call_expression(self, call);
    }

    fn visit_for_statement(&mut self, loop_: &ForStatement<'a>) {
        self.check_shifting_loop(loop_);
        walk_for_statement(self, loop_);
    }
}

struct ShiftingBody<'a> {
    array: &'a str,
    counter: &'a str,
    splice_calls: Vec<Span>,
    adjusts_counter: bool,
    breaks: bool,
}

impl<'a> ShiftingBody<'a> {
    fn new(array: &'a str, counter: &'a str) -> Self {
        Self {
            array,
            counter,
            splice_calls: Vec::new(),
            adjusts_counter: false,
            breaks: false,
        }
    }
}

impl<'a> Visit<'a> for ShiftingBody<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(("splice", member)) = call_property(call)
            && identifier_name(member_object(member)) == Some(self.array)
            && call
                .arguments
                .first()
                .and_then(argument_expression)
                .and_then(identifier_name)
                == Some(self.counter)
        {
            self.splice_calls.push(call.span);
        }
        walk_call_expression(self, call);
    }

    fn visit_update_expression(&mut self, update: &oxc_ast::ast::UpdateExpression<'a>) {
        if update_target_name(update) == Some(self.counter)
            && update.operator == UpdateOperator::Decrement
        {
            self.adjusts_counter = true;
        }
    }

    fn visit_break_statement(&mut self, _statement: &oxc_ast::ast::BreakStatement) {
        self.breaks = true;
    }

    fn visit_function(&mut self, _function: &oxc_ast::ast::Function<'a>, _flags: ScopeFlags) {
        // Nested functions do not execute as part of the current iteration.
    }

    fn visit_arrow_function_expression(
        &mut self,
        _function: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
        // Nested functions do not execute as part of the current iteration.
    }
}

fn create_read_stream_factory_site(expression: &Expression<'_>) -> Option<StreamFactorySite> {
    let Expression::CallExpression(call) = unparenthesized(expression) else {
        return None;
    };
    if let Expression::Identifier(callee) = unparenthesized(&call.callee) {
        return Some(StreamFactorySite::Direct(callee.span));
    }
    let member = call.callee.as_member_expression()?;
    if static_property_name(member) != Some("createReadStream") {
        return None;
    }
    let Expression::Identifier(module) = unparenthesized(member_object(member)) else {
        return None;
    };
    Some(StreamFactorySite::Module(module.span))
}

fn is_fs_require(expression: &Expression<'_>) -> bool {
    let Expression::CallExpression(call) = unparenthesized(expression) else {
        return false;
    };
    let Expression::Identifier(callee) = unparenthesized(&call.callee) else {
        return false;
    };
    if callee.name.as_str() != "require" || call.arguments.len() != 1 {
        return false;
    }
    let Some(argument) = call.arguments[0].as_expression() else {
        return false;
    };
    match unparenthesized(argument) {
        Expression::StringLiteral(literal) => is_fs_module(literal.value.as_str()),
        _ => false,
    }
}

fn is_create_read_stream_import(name: &ModuleExportName<'_>) -> bool {
    matches!(
        name,
        ModuleExportName::IdentifierName(identifier)
            if identifier.name.as_str() == "createReadStream"
    ) || matches!(
        name,
        ModuleExportName::IdentifierReference(identifier)
            if identifier.name.as_str() == "createReadStream"
    )
}

fn is_fs_module(module: &str) -> bool {
    matches!(module, "fs" | "node:fs")
}

fn loop_counter(loop_: &ForStatement<'_>) -> Option<String> {
    let ForStatementInit::VariableDeclaration(declaration) = loop_.init.as_ref()? else {
        return None;
    };
    let declarator = declaration.declarations.first()?;
    binding_identifier_name(&declarator.id).map(str::to_string)
}

fn loop_array(test: Option<&Expression<'_>>, counter: &str) -> Option<String> {
    let Expression::BinaryExpression(binary) = unparenthesized(test?) else {
        return None;
    };
    let (counter_side, length_side) = match binary.operator {
        BinaryOperator::LessThan | BinaryOperator::LessEqualThan => (&binary.left, &binary.right),
        BinaryOperator::GreaterThan | BinaryOperator::GreaterEqualThan => {
            (&binary.right, &binary.left)
        }
        _ => return None,
    };
    if identifier_name(counter_side) != Some(counter) {
        return None;
    }
    let member = length_side.as_member_expression()?;
    (static_property_name(member) == Some("length"))
        .then(|| identifier_name(member_object(member)).map(str::to_string))
        .flatten()
}

fn loop_increments_counter(loop_: &ForStatement<'_>, counter: &str) -> bool {
    matches!(
        loop_.update.as_ref().map(unparenthesized),
        Some(Expression::UpdateExpression(update))
            if update.operator == UpdateOperator::Increment
                && update_target_name(update) == Some(counter)
    )
}

#[cfg(test)]
mod tests {
    use super::analyze;
    use crate::JstsLanguage;

    fn keys(source: &str) -> Vec<String> {
        analyze(source, JstsLanguage::JavaScript)
            .into_iter()
            .map(|issue| issue.rule_key)
            .collect()
    }

    #[test]
    fn shifting_loop_rule_requires_same_array_index_and_unadjusted_counter() {
        let bad = keys(concat!(
            "const parts = path.split('/');\n",
            "for (let i = 0; i < parts.length; ++i) {\n",
            "  if (parts[i] === '..') parts.splice(i, 1);\n",
            "}\n",
        ));
        assert!(
            bad.iter()
                .any(|key| key.ends_with("loop-iteration-skipped-due-to-shifting"))
        );

        for clean in [
            "for (let i = 0; i < parts.length; ++i) { parts.splice(i, 1); --i; }",
            "for (let i = 0; i < parts.length; ++i) { parts.splice(i, 1); break; }",
            "for (let i = 0; i < parts.length; ++i) { other.splice(i, 1); }",
        ] {
            assert!(keys(clean).is_empty(), "{clean}");
        }
    }

    #[test]
    fn stream_rule_requires_node_read_stream_and_prior_source_handler() {
        let bad = keys(concat!(
            "const fs = require('fs');\n",
            "const source = fs.createReadStream('in');\n",
            "const destination = fs.createWriteStream('out');\n",
            "source.pipe(destination).on('error', report);\n",
        ));
        assert!(
            bad.iter()
                .any(|key| key.ends_with("unhandled-error-in-stream-pipeline"))
        );

        let scoped = keys(concat!(
            "const fs = require('fs');\n",
            "function handled() { const source = fs.createReadStream('a'); source.on('error', report); source.pipe(out); }\n",
            "function custom(source) { source.pipe(out); }\n",
        ));
        assert!(
            scoped.is_empty(),
            "bindings must resolve by scope: {scoped:?}"
        );

        let reassigned = keys(concat!(
            "const fs = require('fs');\n",
            "let source = fs.createReadStream('a');\n",
            "source = customSource;\n",
            "source.pipe(out);\n",
        ));
        assert!(
            reassigned.is_empty(),
            "reassigned non-stream binding must stay clean: {reassigned:?}",
        );

        let clean = keys(concat!(
            "const fs = require('fs');\n",
            "const source = fs.createReadStream('in');\n",
            "source.on('error', report);\n",
            "source.pipe(destination);\n",
        ));
        assert!(clean.is_empty(), "unexpected native findings: {clean:?}");

        for unrelated in [
            "// require('fs')\nconst source = custom.createReadStream('in'); source.pipe(out);",
            "const custom = { createReadStream() { return source; } }; const source = custom.createReadStream(); source.pipe(out);",
        ] {
            assert!(keys(unrelated).is_empty(), "{unrelated}");
        }

        let imported = keys(concat!(
            "import { createReadStream as read } from 'node:fs';\n",
            "const source = read('in');\n",
            "source.pipe(destination);\n",
        ));
        assert!(
            imported
                .iter()
                .any(|key| key.ends_with("unhandled-error-in-stream-pipeline"))
        );
    }

    #[test]
    fn native_keys_follow_javascript_and_typescript_namespaces() {
        let source = "for (let i = 0; i < xs.length; ++i) xs.splice(i, 1);";
        assert!(
            analyze(source, JstsLanguage::JavaScript)[0]
                .rule_key
                .starts_with("hoonarqube-javascript:")
        );
        assert!(
            analyze(source, JstsLanguage::TypeScript)[0]
                .rule_key
                .starts_with("hoonarqube-typescript:")
        );
    }

    #[test]
    fn shifting_loop_rule_requires_forward_length_condition() {
        for clean in [
            "for (let i = 0; i > parts.length; ++i) parts.splice(i, 1);",
            "for (let i = 0; parts.length < i; ++i) parts.splice(i, 1);",
        ] {
            assert!(keys(clean).is_empty(), "{clean}");
        }
    }
}
