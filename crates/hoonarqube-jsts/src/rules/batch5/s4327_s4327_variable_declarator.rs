use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::AstKind;
use oxc_ast::ast::{BindingPattern, Expression, VariableDeclarator};
use oxc_semantic::SymbolId;
use oxc_span::GetSpan;

// `S4327` is decorated `typescript-eslint/no-this-alias`: destructuring
// (`const { a } = this`) is allowed, and an alias referenced inside a
// generator function is exempt because `this` rebinding breaks `yield*`.
impl TsTypeCollector<'_, '_> {
    /// `S4327` logic extracted from `visit_variable_declarator`.
    pub(crate) fn check_s4327_variable_declarator(&mut self, it: &VariableDeclarator<'_>) {
        let BindingPattern::BindingIdentifier(binding) = &it.id else {
            return;
        };
        if let Some(init) = &it.init
            && matches!(unparenthesized(init), Expression::ThisExpression(_))
            && !self.referenced_inside_generator(binding.symbol_id.get())
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4327",
                "Unexpected aliasing of 'this' to local variable.",
                it.id.span(),
            );
        }
    }

    /// Whether any reference to `symbol` sits inside a generator function
    /// scope between the reference and the alias's declaring scope.
    fn referenced_inside_generator(&self, symbol: Option<SymbolId>) -> bool {
        let (Some(semantic), Some(symbol)) = (self.semantic, symbol) else {
            return false;
        };
        let scoping = semantic.scoping();
        let declaring_scope = scoping.symbol_scope_id(symbol);
        scoping.get_resolved_references(symbol).any(|reference| {
            let mut scope = reference.scope_id();
            while scope != declaring_scope {
                if let AstKind::Function(function) =
                    semantic.nodes().kind(scoping.get_node_id(scope))
                    && function.generator
                {
                    return true;
                }
                match scoping.scope_parent_id(scope) {
                    Some(parent) => scope = parent,
                    None => break,
                }
            }
            false
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn plain_this_aliases_are_flagged() {
        let alias =
            ts_keys("class C {\n  m() {\n    const self = this;\n    return self;\n  }\n}\n");
        assert_eq!(count_key(&alias, "typescript:S4327"), 1);

        // References inside ordinary functions still flag.
        let closure = ts_keys(
            "class C {\n  initialized = false;\n  get ensure(): () => void {\n    const owner = this;\n    return function (): void {\n      if (owner.initialized) return;\n      owner.initialized = true;\n    };\n  }\n}\n",
        );
        assert_eq!(count_key(&closure, "typescript:S4327"), 1);
    }

    #[test]
    fn generator_referenced_aliases_are_exempt() {
        // Issue #489: an alias referenced inside a `function*` stays silent.
        let generator = ts_keys(
            "class C {\n  items(): void {\n    const owner = this;\n    run(function () { owner.touch(); }, function* () { yield* owner.more(); });\n  }\n}\n",
        );
        assert_eq!(count_key(&generator, "typescript:S4327"), 0);
    }
    #[test]
    fn destructuring_this_stays_silent() {
        let destructured =
            ts_keys("class C {\n  m() {\n    const { a } = this;\n    return a;\n  }\n}\n");
        assert_eq!(count_key(&destructured, "typescript:S4327"), 0);
    }
}
