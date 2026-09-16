use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::AstKind;
use oxc_ast::ast::{TSIntersectionType, TSType, TSTypeName, TSTypeReference};
use oxc_span::GetSpan;

// `S4335` (upstream `S4335/rule.ts`) flags intersections that collapse or
// carry dead members: an `any`/`never` member simplifies the whole
// intersection, and a null-like (`null`/`undefined`/`void`) or empty-interface
// member is a type without members. Branded-type intersections such as
// `string & { __brand: unknown }` are meaningful nominal typing and stay
// silent; so do the literal-union (`'a' | (string & Empty)`) and generic
// (`T & Empty`, `Foo<Bar> & Empty`, mapped-type) patterns.
impl TsTypeCollector<'_, '_> {
    /// `S4335` logic extracted from `visit_ts_intersection_type`.
    pub(crate) fn check_s4335_ts_intersection_type(&mut self, it: &TSIntersectionType<'_>) {
        self.check_constituent_redundancy(&it.types, "intersection");

        if let Some(member) = it
            .types
            .iter()
            .find(|member| matches!(member, TSType::TSAnyKeyword(_) | TSType::TSNeverKeyword(_)))
        {
            let simplified = if matches!(member, TSType::TSAnyKeyword(_)) {
                "any"
            } else {
                "never"
            };
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4335",
                &format!("Simplify this intersection as it always has type \"{simplified}\"."),
                it.span(),
            );
            return;
        }

        if self.s4335_intersection_exempt(it) {
            return;
        }
        for member in &it.types {
            if self.is_type_without_members(member) {
                self.sink.emit_span(
                    RuleScope::TsOnly,
                    "S4335",
                    "Remove this type without members or change this type intersection.",
                    member.span(),
                );
            }
        }
    }

    /// Whether the intersection matches an exempt idiom: a two-member
    /// intersection inside a union next to a primitive/reference sibling
    /// (literal-union autocomplete pattern), or an intersection with a
    /// mapped-type, generic, or type-parameter sibling.
    fn s4335_intersection_exempt(&self, it: &TSIntersectionType<'_>) -> bool {
        if it.types.len() == 2
            && self.s4335_union_member_spans.contains(&it.span)
            && let Some(other) = it.types.iter().find(|member| {
                !matches!(member, TSType::TSTypeLiteral(literal) if literal.members.is_empty())
            })
            && matches!(
                other,
                TSType::TSStringKeyword(_) | TSType::TSNumberKeyword(_) | TSType::TSTypeReference(_)
            )
        {
            return true;
        }
        it.types.iter().any(|sibling| match sibling {
            TSType::TSMappedType(_) => true,
            TSType::TSTypeReference(reference) => {
                reference.type_arguments.is_some() || self.resolves_to_type_parameter(reference)
            }
            _ => false,
        })
    }

    /// Whether `member` is a type without members: `null`, `undefined`,
    /// `void`, or a reference to an interface with no members and no heritage.
    fn is_type_without_members(&self, member: &TSType<'_>) -> bool {
        match member {
            TSType::TSNullKeyword(_) | TSType::TSUndefinedKeyword(_) | TSType::TSVoidKeyword(_) => {
                true
            }
            TSType::TSTypeReference(reference) => self.resolves_to_empty_interface(reference),
            _ => false,
        }
    }

    /// Whether a type reference resolves to a type parameter (`T & Empty`).
    /// Without semantic information the reference is treated as a possible
    /// type parameter so the exemption stays conservative.
    fn resolves_to_type_parameter(&self, reference: &TSTypeReference<'_>) -> bool {
        let TSTypeName::IdentifierReference(identifier) = &reference.type_name else {
            return false;
        };
        let Some(semantic) = self.semantic else {
            return true;
        };
        let Some(symbol) = identifier.reference_id.get() else {
            return false;
        };
        let Some(symbol) = semantic.scoping().get_reference(symbol).symbol_id() else {
            return false;
        };
        semantic
            .scoping()
            .symbol_flags(symbol)
            .contains(oxc_syntax::symbol::SymbolFlags::TypeParameter)
    }

    /// Whether a type reference resolves to a standalone interface with no
    /// members and no `extends` clause.
    fn resolves_to_empty_interface(&self, reference: &TSTypeReference<'_>) -> bool {
        let TSTypeName::IdentifierReference(identifier) = &reference.type_name else {
            return false;
        };
        let Some(semantic) = self.semantic else {
            return false;
        };
        let Some(symbol) = identifier
            .reference_id
            .get()
            .and_then(|id| semantic.scoping().get_reference(id).symbol_id())
        else {
            return false;
        };
        let mut declarations = semantic.scoping().symbol_declarations(symbol);
        declarations.all(|node_id| {
            matches!(
                semantic.nodes().kind(node_id),
                AstKind::TSInterfaceDeclaration(interface)
                    if interface.body.body.is_empty() && interface.extends.is_empty()
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn branded_type_intersections_stay_silent() {
        // Issue #530: `string & { __brand: unknown }` is the nominal-typing
        // brand idiom — the intersection is meaningful.
        let branded = ts_keys(
            "export type Path = string & { __pathBrand: unknown };\nexport type Escaped = (string & { __escapedIdentifier: void }) | number;\n",
        );
        assert_eq!(count_key(&branded, "typescript:S4335"), 0);

        let primitive_pair = ts_keys("type Both = string & number;\n");
        assert_eq!(count_key(&primitive_pair, "typescript:S4335"), 0);
    }

    #[test]
    fn any_and_never_members_are_flagged() {
        let any_member = ts_keys("type T = { id: string } & any;\n");
        assert_eq!(count_key(&any_member, "typescript:S4335"), 1);

        let never_member = ts_keys("type T = string & never;\n");
        assert_eq!(count_key(&never_member, "typescript:S4335"), 1);
    }

    #[test]
    fn null_like_and_empty_interface_members_are_flagged() {
        let null_member = ts_keys("type T = { id: string } & null;\n");
        assert_eq!(count_key(&null_member, "typescript:S4335"), 1);

        let empty_interface = ts_keys("interface Empty {}\ntype T = { id: string } & Empty;\n");
        assert_eq!(count_key(&empty_interface, "typescript:S4335"), 1);

        // An interface with members is not a dead member.
        let nonempty = ts_keys("interface Full { id: number }\ntype T = { tag: string } & Full;\n");
        assert_eq!(count_key(&nonempty, "typescript:S4335"), 0);
    }

    #[test]
    fn literal_union_and_generic_patterns_stay_silent() {
        let literal_union =
            ts_keys("interface Empty {}\ntype Size = 'small' | 'large' | (string & Empty);\n");
        assert_eq!(count_key(&literal_union, "typescript:S4335"), 0);

        let type_parameter =
            ts_keys("interface Empty {}\nfunction f<T>(x: T & Empty): T & Empty { return x; }\n");
        assert_eq!(count_key(&type_parameter, "typescript:S4335"), 0);

        let generic = ts_keys(
            "interface Empty {}\ntype T = Box<number> & Empty;\ninterface Box<T> { v: T }\n",
        );
        assert_eq!(count_key(&generic, "typescript:S4335"), 0);
    }
}
