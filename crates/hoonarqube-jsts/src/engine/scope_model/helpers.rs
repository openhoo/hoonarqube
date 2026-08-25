use super::{
    BTreeMap, BTreeSet, Declaration, Expression, GetSpan, Span, VariableDeclarator, Visit,
    binding_identifier_name, unparenthesized, walk_declaration,
};

/// Parameter names of named function declarations, for the `S2234` name
/// heuristic.
#[derive(Default)]
pub(crate) struct FunctionParamMapCollector {
    pub(crate) params_by_name: BTreeMap<String, Vec<String>>,
}

impl<'a> Visit<'a> for FunctionParamMapCollector {
    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it
            && let Some(id) = &function.id
        {
            let names: Vec<String> = function
                .params
                .items
                .iter()
                .filter_map(|item| binding_identifier_name(&item.pattern))
                .map(str::to_string)
                .collect();
            self.params_by_name.insert(id.name.to_string(), names);
        }
        walk_declaration(self, it);
    }
}

/// Names bound directly to an array literal anywhere in the file, for the
/// `S4619` heuristic (`const xs = []; ... x in xs`).
pub(crate) fn collect_array_binding_names(program: &oxc_ast::ast::Program<'_>) -> BTreeSet<String> {
    #[derive(Default)]
    struct Collector {
        names: BTreeSet<String>,
    }
    impl<'a> Visit<'a> for Collector {
        fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
            if matches!(&it.init, Some(Expression::ArrayExpression(_)))
                && let Some(name) = binding_identifier_name(&it.id)
            {
                self.names.insert(name.to_string());
            }
        }
    }
    let mut collector = Collector::default();
    collector.visit_program(program);
    collector.names
}

/// Names of a parameter list's simple identifiers.
pub(crate) fn parameter_names<'a>(params: &'a oxc_ast::ast::FormalParameters<'a>) -> Vec<&'a str> {
    params
        .items
        .iter()
        .filter_map(|item| binding_identifier_name(&item.pattern))
        .collect()
}

/// Body span of a function-valued expression, if it has one.
pub(crate) fn function_body_span(expression: &Expression<'_>) -> Option<Span> {
    match unparenthesized(expression) {
        Expression::FunctionExpression(function) => {
            function.body.as_deref().map(oxc_span::GetSpan::span)
        }
        Expression::ArrowFunctionExpression(arrow) => Some(arrow.body.span()),
        _ => None,
    }
}

/// Parameter list of a function-valued expression, if it has one.
pub(crate) fn function_parameters<'a>(
    expression: &'a Expression<'a>,
) -> Option<&'a oxc_ast::ast::FormalParameters<'a>> {
    match unparenthesized(expression) {
        Expression::FunctionExpression(function) => Some(&function.params),
        Expression::ArrowFunctionExpression(arrow) => Some(&arrow.params),
        _ => None,
    }
}
