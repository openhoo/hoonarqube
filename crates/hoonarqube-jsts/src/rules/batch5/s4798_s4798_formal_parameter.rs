use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::{BindingPattern, FormalParameter, TSType};
use oxc_span::GetSpan;

// `S4798` only inspects parameters of function implementations
// (`FunctionDeclaration`, `FunctionExpression`, `ArrowFunctionExpression`).
// Overload signatures and interface method signatures cannot carry a default
// value, so parameters inside `Signature`-kind parameter lists are exempt, as
// are constructor parameter properties (`private x?: boolean`).
impl TsTypeCollector<'_, '_> {
    /// `S4798` logic extracted from `visit_formal_parameter`.
    pub(crate) fn check_s4798_formal_parameter(&mut self, it: &FormalParameter<'_>) {
        if self.signature_params_depth > 0
            || it.accessibility.is_some()
            || it.readonly
            || it.r#override
        {
            return;
        }
        if let Some(annotation) = &it.type_annotation
            && it.optional
            && it.initializer.is_none()
            && matches!(annotation.type_annotation, TSType::TSBooleanKeyword(_))
            && let BindingPattern::BindingIdentifier(binding) = &it.pattern
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4798",
                &format!(
                    "Provide a default value for '{}' so that the logic of the function is more evident when this parameter is missing. Consider defining another function if providing default value is not possible.",
                    binding.name
                ),
                it.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn optional_booleans_on_implementations_are_flagged() {
        let function = ts_keys("function f(verbose?: boolean) { return verbose; }\n");
        assert_eq!(count_key(&function, "typescript:S4798"), 1);

        let arrow = ts_keys("const f = (verbose?: boolean) => verbose;\n");
        assert_eq!(count_key(&arrow, "typescript:S4798"), 1);

        let expression = ts_keys("const f = function (verbose?: boolean) { return verbose; };\n");
        assert_eq!(count_key(&expression, "typescript:S4798"), 1);

        let with_default = ts_keys("function f(verbose: boolean = false) { return verbose; }\n");
        assert_eq!(count_key(&with_default, "typescript:S4798"), 0);

        let optional_string = ts_keys("function f(label?: string) { return label; }\n");
        assert_eq!(count_key(&optional_string, "typescript:S4798"), 0);
    }

    #[test]
    fn signature_positions_stay_silent() {
        // Issue #491: overload signatures and interface methods cannot carry
        // a default value.
        let overloads = ts_keys(
            "export function clone<T>(node: T, includeTrivia?: boolean): T;\nexport function clone<T>(node: T | undefined, includeTrivia?: boolean): T | undefined;\nexport function clone<T>(node: T | undefined, includeTrivia = true): T | undefined {\n    return node;\n}\ninterface N { getStart(sourceFile?: object, includeJsDocComment?: boolean): number; }\n",
        );
        assert_eq!(count_key(&overloads, "typescript:S4798"), 0);

        let declared = ts_keys("declare function f(flag?: boolean): void;\n");
        assert_eq!(count_key(&declared, "typescript:S4798"), 0);

        let function_type = ts_keys("type F = (flag?: boolean) => void;\n");
        assert_eq!(count_key(&function_type, "typescript:S4798"), 0);

        let parameter_property =
            ts_keys("class C {\n  constructor(private flag?: boolean) {}\n}\n");
        assert_eq!(count_key(&parameter_property, "typescript:S4798"), 0);
    }
}
