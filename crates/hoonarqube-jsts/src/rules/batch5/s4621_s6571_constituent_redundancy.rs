use super::collectors::TsTypeCollector;
use crate::support::source_slice;
use crate::support::{IssueSink, RuleScope};
use oxc_ast::ast::{TSLiteral, TSType, TSTypeAliasDeclaration, TSTypeName};
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;
use std::collections::{HashMap, HashSet};

/// Classification of one union/intersection constituent for the redundancy
/// checks `S6571` (keyword-level subsumption) and `S4621` (structural
/// equality).
enum Constituent {
    /// A keyword type (`string`, `number`, ...) with its canonical name.
    Keyword(&'static str),
    /// A literal type (`'a'`, `42`, `true`) with the primitive subsuming it.
    Literal(&'static str),
    /// Everything else (type references, object literals, ...).
    Other,
}

fn constituent_kind(ts_type: &TSType<'_>) -> Constituent {
    match ts_type {
        TSType::TSAnyKeyword(_) => Constituent::Keyword("any"),
        TSType::TSBigIntKeyword(_) => Constituent::Keyword("bigint"),
        TSType::TSBooleanKeyword(_) => Constituent::Keyword("boolean"),
        TSType::TSIntrinsicKeyword(_) => Constituent::Keyword("intrinsic"),
        TSType::TSNeverKeyword(_) => Constituent::Keyword("never"),
        TSType::TSNullKeyword(_) => Constituent::Keyword("null"),
        TSType::TSNumberKeyword(_) => Constituent::Keyword("number"),
        TSType::TSObjectKeyword(_) => Constituent::Keyword("object"),
        TSType::TSStringKeyword(_) => Constituent::Keyword("string"),
        TSType::TSSymbolKeyword(_) => Constituent::Keyword("symbol"),
        TSType::TSThisType(_) => Constituent::Keyword("this"),
        TSType::TSUndefinedKeyword(_) => Constituent::Keyword("undefined"),
        TSType::TSUnknownKeyword(_) => Constituent::Keyword("unknown"),
        TSType::TSVoidKeyword(_) => Constituent::Keyword("void"),
        TSType::TSLiteralType(literal) => match &literal.literal {
            TSLiteral::StringLiteral(_) => Constituent::Literal("string"),
            TSLiteral::NumericLiteral(_) | TSLiteral::UnaryExpression(_) => {
                Constituent::Literal("number")
            }
            TSLiteral::BooleanLiteral(_) => Constituent::Literal("boolean"),
            TSLiteral::BigIntLiteral(_) => Constituent::Literal("bigint"),
            TSLiteral::TemplateLiteral(_) => Constituent::Other,
        },
        _ => Constituent::Other,
    }
}

fn keyword_name(ts_type: &TSType<'_>) -> Option<&'static str> {
    match constituent_kind(ts_type) {
        Constituent::Keyword(name) => Some(name),
        _ => None,
    }
}

impl TsTypeCollector<'_, '_> {
    /// `S6571` keyword-level redundancy and `S4621` structural duplicates.
    pub(crate) fn check_constituent_redundancy(&mut self, types: &[TSType<'_>], container: &str) {
        let all_keywords: Vec<&'static str> = types.iter().filter_map(keyword_name).collect();
        // Bounded in-file alias resolution: an alias that flattens entirely
        // to keyword constituents behaves like those keywords, so a literal
        // beside it is as redundant as one beside the keyword itself.
        let alias_keywords: Vec<&'static str> = types
            .iter()
            .filter_map(|ts_type| self.type_aliases.expansion(ts_type))
            .flat_map(|expansion| expansion.keywords.iter().copied())
            .collect();
        let mut subsuming_keywords = all_keywords;
        subsuming_keywords.extend_from_slice(&alias_keywords);
        // `any`/`unknown` override every other constituent, directly or
        // through an alias expansion.
        let top_constituents: Vec<bool> = types
            .iter()
            .map(|ts_type| {
                matches!(keyword_name(ts_type), Some("any" | "unknown"))
                    || self
                        .type_aliases
                        .expansion(ts_type)
                        .is_some_and(|expansion| expansion.top)
            })
            .collect();
        let mut seen_keywords: Vec<&'static str> = Vec::new();
        let mut seen_slices: Vec<&str> = Vec::new();
        let mut previous_keyword = None;
        let source = self.source;
        for (position, ts_type) in types.iter().enumerate() {
            match constituent_kind(ts_type) {
                Constituent::Keyword(name) => self.check_keyword_constituent(
                    name,
                    ts_type,
                    &mut seen_keywords,
                    &mut previous_keyword,
                    container,
                ),
                Constituent::Literal(base) => self.check_literal_constituent(
                    base,
                    ts_type,
                    &subsuming_keywords,
                    &mut previous_keyword,
                    container,
                ),
                Constituent::Other => {
                    if top_constituents[position] {
                        self.emit_redundant_constituent(ts_type, container);
                    }
                    check_other_constituent(
                        &mut self.sink,
                        source,
                        ts_type,
                        &mut seen_slices,
                        &mut previous_keyword,
                    );
                }
            }
        }
        for ts_type in types {
            if matches!(keyword_name(ts_type), Some("any" | "unknown")) {
                self.emit_redundant_constituent(ts_type, container);
            }
        }
    }

    fn check_keyword_constituent(
        &mut self,
        name: &'static str,
        ts_type: &TSType<'_>,
        seen_keywords: &mut Vec<&'static str>,
        previous_keyword: &mut Option<&'static str>,
        container: &str,
    ) {
        if *previous_keyword == Some(name) {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4621",
                "Remove this duplicated type or replace with another one.",
                ts_type.span(),
            );
        } else if seen_keywords.contains(&name) {
            self.emit_redundant_constituent(ts_type, container);
        } else {
            seen_keywords.push(name);
        }
        *previous_keyword = Some(name);
    }

    fn check_literal_constituent(
        &mut self,
        base: &'static str,
        ts_type: &TSType<'_>,
        all_keywords: &[&'static str],
        previous_keyword: &mut Option<&'static str>,
        container: &str,
    ) {
        *previous_keyword = None;
        if all_keywords.contains(&base) {
            self.emit_redundant_constituent(ts_type, container);
        }
    }

    fn emit_redundant_constituent(&mut self, ts_type: &TSType<'_>, container: &str) {
        let message = format!("Remove this redundant member from the {container} type.");
        self.sink
            .emit_span(RuleScope::TsOnly, "S6571", &message, ts_type.span());
    }
}

fn check_other_constituent<'source>(
    sink: &mut IssueSink<'_>,
    source: &'source str,
    ts_type: &TSType<'_>,
    seen_slices: &mut Vec<&'source str>,
    previous_keyword: &mut Option<&'static str>,
) {
    *previous_keyword = None;
    let text = source_slice(source, ts_type.span());
    if seen_slices.contains(&text) {
        sink.emit_span(
            RuleScope::TsOnly,
            "S4621",
            "Remove this duplicated type or replace with another one.",
            ts_type.span(),
        );
    } else {
        seen_slices.push(text);
    }
}

/// The keyword expansion of one in-file `type` alias.
#[derive(Clone, Default)]
pub(crate) struct AliasExpansion {
    /// Flattened keyword constituents the alias resolves to.
    keywords: Vec<&'static str>,
    /// The expansion contains `any` or `unknown`.
    top: bool,
}

/// Bounded in-file resolution of `type` aliases to keyword constituents
/// for `S6571`. Only aliases whose whole expansion flattens to keywords
/// and literals resolve; opaque shapes, generic aliases, duplicated
/// names, and cycles stay unresolved, so the redundancy checks never
/// guess from names alone.
#[derive(Default)]
pub(crate) struct TypeAliasTable {
    expansions: HashMap<String, AliasExpansion>,
}

impl TypeAliasTable {
    pub(crate) fn collect(program: &oxc_ast::ast::Program<'_>) -> Self {
        let mut declarations = AliasDeclarations::default();
        declarations.visit_program(program);
        let mut table = Self::default();
        for (name, ts_type) in &declarations.declarations {
            if declarations.duplicated.contains(name) {
                continue;
            }
            let mut expansion = AliasExpansion::default();
            let mut visiting: Vec<String> = Vec::new();
            if expand_type(ts_type, &declarations, &mut visiting, &mut expansion) {
                table.expansions.insert(name.clone(), expansion);
            }
        }
        table
    }

    /// The keyword expansion of a constituent that is an unqualified
    /// reference to a resolvable in-file alias.
    pub(crate) fn expansion(&self, ts_type: &TSType<'_>) -> Option<&AliasExpansion> {
        let TSType::TSTypeReference(reference) = ts_type else {
            return None;
        };
        if reference.type_arguments.is_some() {
            return None;
        }
        let TSTypeName::IdentifierReference(identifier) = &reference.type_name else {
            return None;
        };
        self.expansions.get(identifier.name.as_str())
    }
}

#[derive(Default)]
struct AliasDeclarations<'a> {
    declarations: Vec<(String, &'a TSType<'a>)>,
    duplicated: HashSet<String>,
}

impl<'a> Visit<'a> for AliasDeclarations<'a> {
    fn visit_ts_type_alias_declaration(&mut self, it: &TSTypeAliasDeclaration<'a>) {
        // Generic aliases depend on their type arguments and never resolve.
        if it.type_parameters.is_none() {
            let name = it.id.name.as_str().to_owned();
            if self
                .declarations
                .iter()
                .any(|(existing, _)| *existing == name)
            {
                self.duplicated.insert(name);
            } else {
                self.declarations
                    .push((name, self.alloc(&it.type_annotation)));
            }
        }
    }
}

/// Flattens one type into keyword constituents; `false` means the shape is
/// opaque and the alias stays unresolved.
fn expand_type(
    ts_type: &TSType<'_>,
    declarations: &AliasDeclarations<'_>,
    visiting: &mut Vec<String>,
    expansion: &mut AliasExpansion,
) -> bool {
    if let Some(name) = keyword_name(ts_type) {
        expansion.top |= matches!(name, "any" | "unknown");
        expansion.keywords.push(name);
        return true;
    }
    match ts_type {
        // A literal resolves but contributes no keyword claim.
        TSType::TSLiteralType(_) => true,
        TSType::TSParenthesizedType(parenthesized) => expand_type(
            &parenthesized.type_annotation,
            declarations,
            visiting,
            expansion,
        ),
        TSType::TSUnionType(union) => union
            .types
            .iter()
            .all(|part| expand_type(part, declarations, visiting, expansion)),
        TSType::TSTypeReference(reference)
            if reference.type_arguments.is_none()
                && matches!(&reference.type_name, TSTypeName::IdentifierReference(_)) =>
        {
            let TSTypeName::IdentifierReference(identifier) = &reference.type_name else {
                return false;
            };
            let name = identifier.name.as_str().to_owned();
            if visiting.contains(&name) || declarations.duplicated.contains(&name) {
                return false;
            }
            let Some((_, target)) = declarations
                .declarations
                .iter()
                .find(|(existing, _)| *existing == name)
            else {
                return false;
            };
            visiting.push(name);
            let resolved = expand_type(target, declarations, visiting, expansion);
            visiting.pop();
            resolved
        }
        _ => false,
    }
}
