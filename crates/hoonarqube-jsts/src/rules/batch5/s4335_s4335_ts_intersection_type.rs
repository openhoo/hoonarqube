use super::collectors::{TsTypeCollector, type_is_primitive_keyword};
use crate::support::RuleScope;
use oxc_ast::ast::TSIntersectionType;
use oxc_ast::ast::TSType;
use oxc_span::GetSpan;

fn type_is_objectish(ts_type: &TSType<'_>) -> bool {
    match ts_type {
        TSType::TSParenthesizedType(inner) => type_is_objectish(&inner.type_annotation),
        TSType::TSTypeLiteral(_)
        | TSType::TSArrayType(_)
        | TSType::TSTupleType(_)
        | TSType::TSFunctionType(_)
        | TSType::TSMappedType(_)
        | TSType::TSIndexedAccessType(_)
        | TSType::TSConstructorType(_)
        | TSType::TSImportType(_)
        | TSType::TSNamedTupleMember(_) => true,
        _ => false,
    }
}

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S4335` logic extracted from `visit_ts_intersection_type`.
    pub(crate) fn check_s4335_ts_intersection_type(&mut self, it: &TSIntersectionType<'_>) {
        self.check_constituent_redundancy(&it.types, "intersection");

        if it.types.iter().any(type_is_primitive_keyword) && it.types.iter().any(type_is_objectish)
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4335",
                "Review this intersection type; combining a primitive type with an object type is meaningless.",
                it.span(),
            );
        }
    }
}
