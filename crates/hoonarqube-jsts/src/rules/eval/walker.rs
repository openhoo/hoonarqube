// Family walker for 'eval' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::rules::shared::{argument_expression, is_literal_expression};
use crate::support::LineIndex;
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    CallExpression, Expression, IdentifierReference, NewExpression, VariableDeclaration,
    VariableDeclarationKind, VariableDeclarator,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{walk_call_expression, walk_new_expression};
use oxc_semantic::{Semantic, SymbolId};
use oxc_span::{GetSpan, Span};
use oxc_syntax::reference::ReferenceId;
use std::collections::HashSet;

fn check_eval_usage(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
    semantic: Option<&Semantic<'_>>,
) -> Vec<Issue> {
    let provenance = FunctionProvenance::collect(program, semantic);
    let mut collector = EvalUsageCollector {
        index,
        language,
        semantic,
        provenance: &provenance,
        issues: Vec::new(),
    };
    collector.visit_program(program);
    collector.issues
}

/// Const-bound provenance of the global `Function` constructor.
///
/// `const F = Function` preserves the constructor's identity, and the
/// result of a dynamic `new Function(...)`/`new <alias>(...)` is compiled
/// code; constructing or calling either is dynamic code execution
/// (`S1523`). Rebindable bindings, arbitrary dynamic values, and member
/// expressions stay untracked, so the hotspot never guesses.
#[derive(Default)]
struct FunctionProvenance {
    function_aliases: HashSet<SymbolId>,
    dynamic_factories: HashSet<SymbolId>,
}

/// Where a const-declared factory candidate comes from; alias references
/// resolve to symbols after the whole walk, so declaration order is
/// irrelevant.
enum FactorySource {
    GlobalFunction,
    Alias(ReferenceId),
}

#[derive(Default)]
struct ProvenanceCollector<'s, 'a> {
    semantic: Option<&'s Semantic<'a>>,
    function_aliases: HashSet<SymbolId>,
    factory_candidates: Vec<(SymbolId, FactorySource)>,
}

impl<'a> Visit<'a> for ProvenanceCollector<'_, 'a> {
    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        // Only `const` bindings keep their initializer's identity; a
        // rebindable `let`/`var` alias would be a guess.
        if it.kind == VariableDeclarationKind::Const {
            for declarator in &it.declarations {
                self.collect_declarator(declarator);
            }
        }
    }
}

impl<'a> ProvenanceCollector<'_, 'a> {
    fn collect_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        let Some(init) = declarator.init.as_ref() else {
            return;
        };
        let Some(symbol) = declarator
            .id
            .get_binding_identifier()
            .map(oxc_ast::ast::BindingIdentifier::symbol_id)
        else {
            return;
        };
        match init {
            Expression::Identifier(identifier) => {
                if identifier.name == "Function" && self.is_global(identifier) {
                    self.function_aliases.insert(symbol);
                }
            }
            Expression::NewExpression(new) => {
                if let Expression::Identifier(callee) = &new.callee
                    && has_dynamic_argument(&new.arguments)
                {
                    let source = if callee.name == "Function" && self.is_global(callee) {
                        FactorySource::GlobalFunction
                    } else {
                        FactorySource::Alias(callee.reference_id())
                    };
                    self.factory_candidates.push((symbol, source));
                }
            }
            _ => {}
        }
    }

    fn is_global(&self, identifier: &IdentifierReference<'a>) -> bool {
        self.semantic
            .is_some_and(|semantic| semantic.is_reference_to_global_variable(identifier))
    }
}

impl<'a> FunctionProvenance {
    fn collect(program: &oxc_ast::ast::Program<'a>, semantic: Option<&Semantic<'a>>) -> Self {
        let Some(semantic) = semantic else {
            return Self::default();
        };
        let mut collector = ProvenanceCollector {
            semantic: Some(semantic),
            ..ProvenanceCollector::default()
        };
        collector.visit_program(program);
        let mut provenance = Self {
            function_aliases: collector.function_aliases,
            dynamic_factories: HashSet::new(),
        };
        let scoping = semantic.scoping();
        for (symbol, source) in collector.factory_candidates {
            let tracked = match source {
                FactorySource::GlobalFunction => true,
                FactorySource::Alias(reference_id) => scoping
                    .get_reference(reference_id)
                    .symbol_id()
                    .is_some_and(|callee| provenance.function_aliases.contains(&callee)),
            };
            if tracked {
                provenance.dynamic_factories.insert(symbol);
            }
        }
        provenance
    }
}

/// Collects global `eval(...)` calls and `new Function(...)` expressions
/// anywhere in the tree, anchored at the callee span.
///
/// A direct identifier is only the built-in surface when its semantic
/// reference is global. This keeps local parameters/declarations named
/// `eval` or `Function` out of the hotspot; without semantic provenance the
/// collector remains silent rather than guessing from a name alone.
struct EvalUsageCollector<'a> {
    index: &'a LineIndex<'a>,
    language: JstsLanguage,
    semantic: Option<&'a Semantic<'a>>,
    provenance: &'a FunctionProvenance,
    issues: Vec<Issue>,
}

impl<'a> Visit<'a> for EvalUsageCollector<'_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Expression::Identifier(callee) = &it.callee {
            if matches!(callee.name.as_str(), "eval" | "Function")
                && self.is_global(callee)
                && has_dynamic_argument(&it.arguments)
            {
                let message = if callee.name == "eval" {
                    "Remove this usage of 'eval'."
                } else {
                    "Remove this usage of 'Function'."
                };
                self.push(message, callee.span());
            } else if self.is_dynamic_factory(callee) {
                // Calling a compiled factory runs its dynamic body; the
                // call arguments are values, not code.
                self.push("Remove this usage of 'Function'.", callee.span());
            } else if self.is_function_alias(callee) && has_dynamic_argument(&it.arguments) {
                self.push("Remove this usage of 'Function'.", callee.span());
            }
        }
        walk_call_expression(self, it);
    }
    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        if let Expression::Identifier(callee) = &it.callee
            && has_dynamic_argument(&it.arguments)
            && (callee.name == "Function" && self.is_global(callee)
                || self.is_function_alias(callee))
        {
            self.push("Remove this usage of 'Function'.", callee.span());
        }
        walk_new_expression(self, it);
    }
}

fn has_dynamic_argument(arguments: &[oxc_ast::ast::Argument<'_>]) -> bool {
    arguments.iter().any(|argument| {
        argument_expression(argument).is_none_or(|expression| !is_constant_code(expression))
    })
}

fn is_constant_code(expression: &Expression<'_>) -> bool {
    is_literal_expression(expression)
        || matches!(
            expression,
            Expression::TemplateLiteral(template) if template.expressions.is_empty()
        )
}

impl EvalUsageCollector<'_> {
    fn is_global(&self, identifier: &IdentifierReference<'_>) -> bool {
        self.semantic
            .is_some_and(|semantic| semantic.is_reference_to_global_variable(identifier))
    }

    /// Whether the callee resolves to a dynamically compiled factory
    /// result; calling it runs its dynamic body regardless of the call
    /// arguments.
    fn is_dynamic_factory(&self, callee: &IdentifierReference<'_>) -> bool {
        self.resolved_symbol(callee)
            .is_some_and(|symbol| self.provenance.dynamic_factories.contains(&symbol))
    }

    /// Whether the callee resolves to a const binding of the global
    /// `Function` constructor.
    fn is_function_alias(&self, callee: &IdentifierReference<'_>) -> bool {
        self.resolved_symbol(callee)
            .is_some_and(|symbol| self.provenance.function_aliases.contains(&symbol))
    }

    fn resolved_symbol(&self, callee: &IdentifierReference<'_>) -> Option<SymbolId> {
        self.semantic.and_then(|semantic| {
            semantic
                .scoping()
                .get_reference(callee.reference_id())
                .symbol_id()
        })
    }
}

impl EvalUsageCollector<'_> {
    fn push(&mut self, message: &str, span: Span) {
        self.issues.push(Issue {
            rule_key: format!("{}:S1523", self.language.prefix()),
            message: message.to_string(),
            range: self.index.range(span),
            fix: None,
            flows: Vec::new(),
            alternatives: Vec::new(),
        });
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_eval_usage(ctx.program, ctx.index, ctx.language, ctx.semantic)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn rule_keys_follow_file_language_prefix() {
        let javascript = js("eval(source);");
        assert_eq!(javascript.issues[0].rule_key, "javascript:S1523");

        let typescript = ts("eval(source);");
        assert_eq!(typescript.issues[0].rule_key, "typescript:S1523");
        assert_eq!(typescript.language, "typescript");
    }

    #[test]
    fn s1523_flags_dynamic_function_constructor_and_clean_code_passes() {
        let function_ctor = js_keys("new Function(source);\n");
        assert_eq!(count_key(&function_ctor, "javascript:S1523"), 1);

        let function_call = js_keys("Function(source);\n");
        assert_eq!(count_key(&function_call, "javascript:S1523"), 1);

        let literal_ctor = js_keys("new Function('return 1');\n");
        assert_eq!(count_key(&literal_ctor, "javascript:S1523"), 0);

        let literal_call = js_keys("Function('return 1');\n");
        assert_eq!(count_key(&literal_call, "javascript:S1523"), 0);

        let clean = js_keys("compute('x');\nconst made = new Maker();\n");
        assert_eq!(count_key(&clean, "javascript:S1523"), 0);
    }
    #[test]
    fn s1523_exempts_constant_eval_code_but_keeps_dynamic_code_in_js_and_ts() {
        let javascript = js_keys("eval('work()');\neval(`handle_${role}()`);\n");
        assert_eq!(count_key(&javascript, "javascript:S1523"), 1);

        let typescript = ts_keys("eval('handle_user()');\neval(`handle_${role}()`);\n");
        assert_eq!(count_key(&typescript, "typescript:S1523"), 1);
    }

    #[test]
    fn s1523_uses_global_eval_and_function_provenance() {
        let global = js_keys("eval(source);\nnew Function(source);\nFunction(source);\n");
        assert_eq!(count_key(&global, "javascript:S1523"), 3);

        let shadowed = js_keys(
            "function run(eval, Function) {\n\
             eval(source);\n\
             new Function(source);\n\
             Function(source);\n\
             }\n",
        );
        assert_eq!(count_key(&shadowed, "javascript:S1523"), 0);
    }

    #[test]
    fn s1523_member_callee_is_not_flagged_but_nested_direct_eval_is() {
        let member = js_keys("window.eval('x');\nnew window.Function('return 1');\n");
        assert_eq!(count_key(&member, "javascript:S1523"), 0);
        let nested_direct = js_keys("setTimeout(() => eval(value), 0);\n");
        assert_eq!(count_key(&nested_direct, "javascript:S1523"), 1);
    }
    #[test]
    fn s1523_flags_const_alias_of_global_function_with_provenance_controls() {
        // Issue #195: a const binding to the global `Function` keeps the
        // constructor's provenance, so constructor and call uses remain
        // dynamic-code execution hotspots.
        let aliased = ts("declare const userCode: string;\n\
             const F = Function;\n\
             new F(userCode);\n\
             F(userCode);\n\
             new Function(userCode);\n");
        assert_eq!(count_key(&report_keys(&aliased), "typescript:S1523"), 3);
        let alias_constructor = aliased
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S1523" && issue.range.start.line == 3)
            .expect("alias constructor finding");
        assert_eq!(
            alias_constructor.range,
            hoonarqube_ir::Range {
                start: pos(3, 4),
                end: pos(3, 5),
            }
        );

        // The Zod factory shape: the compiled result is still dynamic code.
        let factory = ts_keys(
            "declare const userCode: string;\n\
             const F = Function;\n\
             const factory = new F(userCode);\n\
             factory(1);\n",
        );
        assert_eq!(count_key(&factory, "typescript:S1523"), 2);

        // Direct `Function` detection is unchanged.
        let direct = ts_keys(
            "declare const userCode: string;\nnew Function(userCode);\nFunction(userCode);\n",
        );
        assert_eq!(count_key(&direct, "typescript:S1523"), 2);

        // Rebindable declarations and arbitrary dynamic values stay
        // untracked.
        let untracked = ts_keys(
            "declare const userCode: string;\n\
             let G = Function;\n\
             new G(userCode);\n\
             const H = libraryFactory();\n\
             H(userCode);\n",
        );
        assert_eq!(count_key(&untracked, "typescript:S1523"), 0);

        // Constant constructor arguments remain exempt through an alias.
        let constant = ts_keys("const F = Function;\nnew F('return 1');\nF('return 1');\n");
        assert_eq!(count_key(&constant, "typescript:S1523"), 0);

        // A shadowed `Function` breaks global provenance for aliases too.
        let shadowed = ts_keys(
            "function run(Function) {\n\
             const F = Function;\n\
             new F(userCode);\n\
             }\n",
        );
        assert_eq!(count_key(&shadowed, "typescript:S1523"), 0);
    }
}
