use super::{Expression, GetSpan, RegExpFlags, RegExpLiteral, Span, to_u32};

// ----- Regex-site plumbing -----

/// One constant regex found in the AST: a regex literal or a `RegExp`
/// constructor call whose arguments are all literals. Pattern rules run the
/// shared mini walker over the pattern text; nothing is executed.
pub(crate) struct RegexSite {
    /// Fallback span for findings whose exact pattern offset is unknown
    /// (constructor-form offsets hide behind string escapes).
    pub(crate) span: Span,
    /// Source byte offset of `pattern[0]`; reliable only when
    /// [`RegexSite::exact`] holds.
    pub(crate) pattern_base: u32,
    /// Whether `pattern_base` maps pattern byte offsets exactly onto source.
    pub(crate) exact: bool,
    pub(crate) pattern: String,
    pub(crate) flags: String,
}

impl RegexSite {
    pub(crate) fn sub_span(&self, start: usize, end: usize) -> Span {
        if self.exact {
            Span::new(
                self.pattern_base.saturating_add(to_u32(start)),
                self.pattern_base.saturating_add(to_u32(end)),
            )
        } else {
            self.span
        }
    }

    pub(crate) fn whole_pattern_span(&self) -> Span {
        self.sub_span(0, self.pattern.len())
    }

    pub(crate) fn has_flag(&self, flag: char) -> bool {
        self.flags.contains(flag)
    }
}

/// Builds a site from a regex literal; its pattern text sits verbatim
/// between the slashes, so sub-spans are exact.
pub(crate) fn regex_site_from_literal(literal: &RegExpLiteral<'_>) -> RegexSite {
    RegexSite {
        span: literal.span,
        pattern_base: literal.span.start.saturating_add(1),
        exact: true,
        pattern: literal.regex.pattern.text.as_str().to_string(),
        flags: regex_flags_text(literal.regex.flags),
    }
}

/// Literal-form flags in canonical order; the constructor form keeps its
/// raw flags string instead.
pub(crate) fn regex_flags_text(flags: RegExpFlags) -> String {
    const ORDERED: [(RegExpFlags, char); 8] = [
        (RegExpFlags::G, 'g'),
        (RegExpFlags::I, 'i'),
        (RegExpFlags::M, 'm'),
        (RegExpFlags::S, 's'),
        (RegExpFlags::U, 'u'),
        (RegExpFlags::Y, 'y'),
        (RegExpFlags::D, 'd'),
        (RegExpFlags::V, 'v'),
    ];
    ORDERED
        .iter()
        .filter(|&(flag, _)| flags.contains(*flag))
        .map(|&(_, ch)| ch)
        .collect()
}

/// String value of a constant literal argument: a string literal or a
/// substitution-free template literal.
pub(crate) fn literal_string_value(argument: &oxc_ast::ast::Argument<'_>) -> Option<String> {
    match argument.as_expression()? {
        Expression::StringLiteral(string) => Some(string.value.as_str().to_string()),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => template
            .quasis
            .first()
            .and_then(|element| element.value.cooked.as_ref())
            .map(|atom| atom.as_str().to_string()),
        _ => None,
    }
}

/// Builds a site from `new RegExp(pattern, flags?)` / `RegExp(pattern,
/// flags?)` when every argument is a constant literal. Offsets inside
/// escaped strings are unreliable, so findings anchor at the argument span.
pub(crate) fn constructor_regex_site(
    arguments: &[oxc_ast::ast::Argument<'_>],
) -> Option<RegexSite> {
    let pattern = literal_string_value(arguments.first()?)?;
    let flags = match arguments.get(1) {
        Some(argument) => literal_string_value(argument)?,
        None => String::new(),
    };
    Some(RegexSite {
        span: arguments.first()?.span(),
        pattern_base: 0,
        exact: false,
        pattern,
        flags,
    })
}

/// The regex literal behind an optional call argument, if it is one.
pub(crate) fn regex_literal_argument<'a>(
    argument: Option<&'a oxc_ast::ast::Argument<'a>>,
) -> Option<&'a oxc_ast::ast::RegExpLiteral<'a>> {
    match argument?.as_expression()? {
        Expression::RegExpLiteral(literal) => Some(literal),
        _ => None,
    }
}

/// Grapheme components that silently truncate inside a character class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GraphemeComponentKind {
    CombiningMark,
    JoinSequence,
    ModifiedEmoji,
    RegionalIndicator,
}

pub(crate) fn grapheme_component_kind(ch: char) -> Option<GraphemeComponentKind> {
    let kind = match ch {
        '\u{0300}'..='\u{036F}'
        | '\u{1AB0}'..='\u{1AFF}'
        | '\u{1DC0}'..='\u{1DFF}'
        | '\u{20D0}'..='\u{20F0}'
        | '\u{FE20}'..='\u{FE2F}' => GraphemeComponentKind::CombiningMark,
        '\u{200D}' => GraphemeComponentKind::JoinSequence,
        '\u{FE00}'..='\u{FE0F}' | '\u{1F3FB}'..='\u{1F3FF}' => GraphemeComponentKind::ModifiedEmoji,
        '\u{1F1E6}'..='\u{1F1FF}' => GraphemeComponentKind::RegionalIndicator,
        _ => return None,
    };
    Some(kind)
}
// ----- Context-sensitive family members -----

/// One `$n` / `$<name>` reference found in a replacement string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GroupReference {
    Index(u32),
    Name(String),
}
