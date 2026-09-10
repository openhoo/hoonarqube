use super::collectors::TsTypeCollector;
use crate::support::source_slice;
use crate::support::{IssueSink, RuleScope};
use oxc_ast::ast::TSLiteral;
use oxc_ast::ast::TSType;
use oxc_span::GetSpan;

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
        let mut seen_keywords: Vec<&'static str> = Vec::new();
        let mut seen_slices: Vec<&str> = Vec::new();
        let mut previous_keyword = None;
        let source = self.source;
        for ts_type in types {
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
                    &all_keywords,
                    &mut previous_keyword,
                    container,
                ),
                Constituent::Other => check_other_constituent(
                    &mut self.sink,
                    source,
                    ts_type,
                    &mut seen_slices,
                    &mut previous_keyword,
                ),
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
