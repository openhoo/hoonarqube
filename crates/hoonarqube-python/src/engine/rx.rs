use crate::support::REGEX_FUNCTIONS;
use crate::support::decode_escape;
use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::has_verbose_flag;
use crate::support::keyword_value;
use crate::support::member_in_ranges;
use crate::support::ranges_overlap;
use crate::support::string_part_body;
use crate::support::to_u32;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// regex: shared mini regex-pattern engine (python:S4784 … python:S6537).
//
// One private decoder + parser over string-literal contents powers every
// regex rule. The decoder preserves source offsets (and flags string-level
// octal escapes), the parser models Python `re` syntax conservatively, and
// malformed patterns never panic: structural rules simply skip them while
// python:S5856 reports the syntax error.
// ---------------------------------------------------------------------------

/// One decoded pattern character with its absolute source offset. `octal`
/// marks characters produced by a string-level octal escape such as `\101`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RxUnit {
    pub(crate) ch: char,
    pub(crate) at: TextSize,
    pub(crate) octal: bool,
}

/// Decodes one string-literal part into offset-preserving units. Raw parts
/// map characters 1:1; cooked parts resolve the escapes that Python string
/// literals resolve and keep every other backslash sequence verbatim, which
/// is exactly what the `re` engine then observes.
pub(crate) fn decode_string_part(raw: &str, base: TextSize) -> Vec<RxUnit> {
    let (body, body_start, is_raw) = string_part_body(raw);
    let inner_base = base + TextSize::from(to_u32(body_start));
    if is_raw {
        return body
            .char_indices()
            .map(|(offset, ch)| RxUnit {
                at: inner_base + TextSize::from(to_u32(offset)),
                ch,
                octal: false,
            })
            .collect();
    }
    let bytes = body.as_bytes();
    let mut units = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let ch = body[i..].chars().next().unwrap_or('\\');
        let ch_len = ch.len_utf8();
        if ch != '\\' {
            units.push(RxUnit {
                at: inner_base + TextSize::from(to_u32(i)),
                ch,
                octal: false,
            });
            i += ch_len;
            continue;
        }
        i += decode_escape(body, i, inner_base, &mut units);
    }
    units
}

/// Parsed regular-expression node; spans are absolute source ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RxNode {
    Alternation(Vec<RxSeq>),
    Seq(RxSeq),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RxSeq {
    pub(crate) items: Vec<RxItem>,
    pub(crate) span: TextRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RxItem {
    pub(crate) atom: RxAtom,
    pub(crate) quant: Option<RxQuant>,
    pub(crate) span: TextRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RxQuant {
    pub(crate) min: u32,
    pub(crate) max: Option<u32>,
    pub(crate) lazy: bool,
    pub(crate) possessive: bool,
    /// Written in `{n}`/`{n,m}` form (as opposed to `*`, `+`, `?`).
    pub(crate) curly: bool,
    pub(crate) span: TextRange,
}

#[derive(Debug, Clone, Eq)]
pub(crate) enum RxAtom {
    Literal(char),
    Dot,
    Class(RxClass),
    Group(RxGroup),
    Anchor(RxAnchor),
    EscClass(RxEscClass),
    Backref(u32),
    NamedRef(String),
    GlobalFlags,
    Comment,
}

// Spans are excluded from atom equality: structural comparisons (duplicate
// alternatives, contradictory lookarounds) must ignore positions.
impl PartialEq for RxAtom {
    fn eq(&self, other: &Self) -> bool {
        use RxAtom as A;
        match (self, other) {
            (A::Literal(a), A::Literal(b)) => a == b,
            (A::Dot, A::Dot) | (A::GlobalFlags, A::GlobalFlags) | (A::Comment, A::Comment) => true,
            (A::Class(a), A::Class(b)) => a == b,
            (A::Group(a), A::Group(b)) => a.kind == b.kind && rx_equivalent(&a.body, &b.body),
            (A::Anchor(a), A::Anchor(b)) => a == b,
            (A::EscClass(a), A::EscClass(b)) => a == b,
            (A::Backref(a), A::Backref(b)) => a == b,
            (A::NamedRef(a), A::NamedRef(b)) => a == b,
            _ => false,
        }
    }
}

/// Structural equality of parsed nodes, ignoring all source spans.
pub(crate) fn rx_equivalent(left: &RxNode, right: &RxNode) -> bool {
    match (left, right) {
        (RxNode::Seq(a), RxNode::Seq(b)) => rx_seq_equivalent(a, b),
        (RxNode::Alternation(a), RxNode::Alternation(b)) => {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| rx_seq_equivalent(x, y))
        }
        _ => false,
    }
}

pub(crate) fn rx_seq_equivalent(left: &RxSeq, right: &RxSeq) -> bool {
    left.items.len() == right.items.len()
        && left
            .items
            .iter()
            .zip(right.items.iter())
            .all(|(a, b)| rx_item_equivalent(a, b))
}

pub(crate) fn rx_item_equivalent(left: &RxItem, right: &RxItem) -> bool {
    left.atom == right.atom
        && match (&left.quant, &right.quant) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                a.min == b.min && a.max == b.max && a.lazy == b.lazy && a.possessive == b.possessive
            }
            _ => false,
        }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RxClass {
    pub(crate) negated: bool,
    pub(crate) items: Vec<RxClassItem>,
    pub(crate) span: TextRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RxClassItem {
    Char(char),
    Range(char, char),
    Esc(RxEscClass),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RxEscClass {
    Digit,
    NotDigit,
    Word,
    NotWord,
    Space,
    NotSpace,
    UnicodeOpaque,
}

impl RxEscClass {
    fn complement(self) -> Option<Self> {
        Some(match self {
            Self::Digit => Self::NotDigit,
            Self::NotDigit => Self::Digit,
            Self::Word => Self::NotWord,
            Self::NotWord => Self::Word,
            Self::Space => Self::NotSpace,
            Self::NotSpace => Self::Space,
            Self::UnicodeOpaque => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RxAnchor {
    Caret,
    Dollar,
    StringStart,
    StringEnd,
    StringEndNl,
    WordBoundary,
    NotWordBoundary,
}

impl RxAnchor {
    pub(crate) fn is_start(self) -> bool {
        matches!(self, Self::Caret | Self::StringStart)
    }

    pub(crate) fn is_end(self) -> bool {
        matches!(self, Self::Dollar | Self::StringEnd | Self::StringEndNl)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RxGroupKind {
    Capture,
    NonCapture,
    FlagScope,
    Atomic,
    Lookahead,
    NegativeLookahead,
    Lookbehind,
    NegativeLookbehind,
    Conditional,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RxGroup {
    pub(crate) kind: RxGroupKind,
    pub(crate) body: RxNode,
    pub(crate) span: TextRange,
}

/// Syntax error with the absolute span of the offending token.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RxError {
    pub(crate) span: TextRange,
}

pub(crate) type RxResult<T> = Result<T, RxError>;

/// Back reference recorded during parsing for python:S6001.
#[derive(Debug, Clone)]
pub(crate) struct RxBackrefRecord {
    pub(crate) name: Option<String>,
    pub(crate) number: Option<u32>,
    pub(crate) span: TextRange,
    pub(crate) visible_numbers: Vec<u32>,
    pub(crate) visible_names: Vec<String>,
}

/// Pattern-level octal escape recorded during parsing for python:S6537.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RxOctalRecord {
    pub(crate) span: TextRange,
}

pub(crate) struct RxParser<'a> {
    pub(crate) units: &'a [RxUnit],
    pub(crate) pos: usize,
    pub(crate) depth: u32,
    pub(crate) capture_count: u32,
    pub(crate) visible_numbers: Vec<u32>,
    pub(crate) visible_names: Vec<String>,
    pub(crate) all_names: Vec<String>,
    pub(crate) backrefs: Vec<RxBackrefRecord>,
    pub(crate) octals: Vec<RxOctalRecord>,
}

pub(crate) const RX_MAX_DEPTH: u32 = 48;

impl<'a> RxParser<'a> {
    fn new(units: &'a [RxUnit]) -> Self {
        Self {
            units,
            pos: 0,
            depth: 0,
            capture_count: 0,
            visible_numbers: Vec::new(),
            visible_names: Vec::new(),
            all_names: Vec::new(),
            backrefs: Vec::new(),
            octals: Vec::new(),
        }
    }

    fn peek(&self) -> Option<RxUnit> {
        self.units.get(self.pos).copied()
    }

    fn peek_second(&self) -> Option<RxUnit> {
        self.units.get(self.pos + 1).copied()
    }

    fn bump(&mut self) -> Option<RxUnit> {
        let unit = self.peek();
        if unit.is_some() {
            self.pos += 1;
        }
        unit
    }

    fn err_at(&self, unit: Option<RxUnit>) -> RxError {
        let span = match unit {
            Some(unit) => TextRange::at(unit.at, TextSize::from(to_u32(unit.ch.len_utf8()))),
            None => self.tail_span(),
        };
        RxError { span }
    }

    fn tail_span(&self) -> TextRange {
        match self.units.last() {
            Some(last) => {
                let end = last.at + TextSize::from(to_u32(last.ch.len_utf8()));
                TextRange::new(end, end)
            }
            None => TextRange::empty(TextSize::new(0)),
        }
    }

    fn enter(&mut self, unit: RxUnit) -> RxResult<()> {
        self.depth += 1;
        if self.depth > RX_MAX_DEPTH {
            return Err(self.err_at(Some(unit)));
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    /// Parses the whole pattern; every unit must be consumed.
    fn parse_root(mut self) -> RxResult<RxParsed> {
        let root = self.parse_alternation(None)?;
        Ok(RxParsed {
            root,
            capture_count: self.capture_count,
            names: self.all_names,
            backrefs: self.backrefs,
            octals: self.octals,
        })
    }

    /// `sequence (| sequence)*`. Captures opened inside one branch are
    /// rolled back before the next branch parses: a back reference may only
    /// rely on groups matched earlier on the same path (python:S6001).
    fn parse_alternation(&mut self, closer: Option<char>) -> RxResult<RxNode> {
        let saved_numbers = self.visible_numbers.len();
        let saved_names = self.visible_names.len();
        let first = self.parse_sequence(closer)?;
        let mut branches = vec![first];
        while self.peek().is_some_and(|unit| unit.ch == '|') {
            self.visible_numbers.truncate(saved_numbers);
            self.visible_names.truncate(saved_names);
            self.bump();
            branches.push(self.parse_sequence(closer)?);
        }
        self.visible_numbers.truncate(saved_numbers);
        self.visible_names.truncate(saved_names);
        Ok(if branches.len() == 1 {
            RxNode::Seq(branches.remove(0))
        } else {
            RxNode::Alternation(branches)
        })
    }

    fn parse_sequence(&mut self, closer: Option<char>) -> RxResult<RxSeq> {
        let start = self
            .peek()
            .map_or_else(|| self.tail_span().start(), |u| u.at);
        let mut items = Vec::new();
        while let Some(unit) = self.peek() {
            if unit.ch == '|' || closer.is_some_and(|c| unit.ch == c) {
                break;
            }
            items.push(self.parse_item()?);
        }
        let end = self.peek().map_or_else(|| self.tail_span().end(), |u| u.at);
        Ok(RxSeq {
            items,
            span: TextRange::new(start, end),
        })
    }

    fn parse_item(&mut self) -> RxResult<RxItem> {
        let (atom, start) = self.parse_atom()?;
        let quant = self.parse_quantifier()?;
        let end = quant
            .as_ref()
            .map_or_else(|| atom_span_end(&atom, start), |q| q.span.end());
        Ok(RxItem {
            atom,
            quant,
            span: TextRange::new(start, end),
        })
    }

    /// Postfix quantifier with optional lazy (`?`) or possessive (`+`)
    /// modifier; a `{` that does not scan as a repeat stays a literal brace.
    fn parse_quantifier(&mut self) -> RxResult<Option<RxQuant>> {
        let Some(unit) = self.peek() else {
            return Ok(None);
        };
        let mut curly = false;
        let (min, max) = match unit.ch {
            '*' => {
                self.bump();
                (0, None)
            }
            '+' => {
                self.bump();
                (1, None)
            }
            '?' => {
                self.bump();
                (0, Some(1))
            }
            '{' => match self.scan_curly_repeat()? {
                Some(bounds) => {
                    curly = true;
                    bounds
                }
                None => return Ok(None),
            },
            _ => return Ok(None),
        };
        self.finish_quantifier(min, max, curly, unit)
    }

    /// Applies lazy/possessive modifiers and the multiple-repeat guard.
    fn finish_quantifier(
        &mut self,
        min: u32,
        max: Option<u32>,
        curly: bool,
        unit: RxUnit,
    ) -> RxResult<Option<RxQuant>> {
        let mut lazy = false;
        let mut possessive = false;
        match self.peek().map(|u| u.ch) {
            Some('?') => {
                self.bump();
                lazy = true;
            }
            Some('+') => {
                self.bump();
                possessive = true;
            }
            _ => {}
        }
        if let Some(next) = self.peek()
            && (matches!(next.ch, '*' | '+' | '?') || (next.ch == '{' && self.curly_repeat_ahead()))
        {
            return Err(self.err_at(Some(next)));
        }
        let span_end = self.consumed_end(unit.at);
        Ok(Some(RxQuant {
            min,
            max,
            lazy,
            possessive,
            curly,
            span: TextRange::new(unit.at, span_end),
        }))
    }

    /// End offset of the most recently consumed unit (`fallback` at EOI).
    fn consumed_end(&self, fallback: TextSize) -> TextSize {
        self.units.get(self.pos - 1).map_or(fallback, |last| {
            last.at + TextSize::from(to_u32(last.ch.len_utf8()))
        })
    }

    /// Scans `{n}`, `{n,}`, `{n,m}`, `{,m}`; returns `None` without
    /// consuming when the braces do not form a repeat (Python then treats
    /// the brace literally).
    fn scan_curly_repeat(&mut self) -> RxResult<Option<(u32, Option<u32>)>> {
        if !self.curly_repeat_ahead() {
            return Ok(None);
        }
        self.bump(); // '{'
        let min = if self.peek().is_some_and(|u| u.ch == ',') {
            0
        } else {
            self.scan_digits().ok_or_else(|| self.err_at(self.peek()))?
        };
        let max = if self.peek().is_some_and(|u| u.ch == ',') {
            self.bump();
            if self.peek().is_some_and(|u| u.ch == '}') {
                None
            } else {
                Some(self.scan_digits().ok_or_else(|| self.err_at(self.peek()))?)
            }
        } else {
            Some(min)
        };
        let close = self.bump();
        match close {
            Some(unit) if unit.ch == '}' => {
                if max.is_some_and(|m| m < min) {
                    return Err(self.err_at(Some(unit)));
                }
                Ok(Some((min, max)))
            }
            _ => Err(self.err_at(close)),
        }
    }

    /// Whether a curly repeat starts at the cursor, without consuming.
    fn curly_repeat_ahead(&self) -> bool {
        let mut i = self.pos + 1; // past '{'
        let mut leading = 0;
        while self.units.get(i).is_some_and(|u| u.ch.is_ascii_digit()) {
            i += 1;
            leading += 1;
        }
        if self.units.get(i).is_some_and(|u| u.ch == ',') {
            i += 1;
            let mut trailing = 0;
            while self.units.get(i).is_some_and(|u| u.ch.is_ascii_digit()) {
                i += 1;
                trailing += 1;
            }
            if trailing == 0 && self.units.get(i).is_none_or(|u| u.ch != '}') {
                return false;
            }
            if leading == 0 && trailing == 0 {
                // A bare `{,}` is a literal brace in Python.
                return false;
            }
        } else if leading == 0 {
            return false;
        }
        self.units.get(i).is_some_and(|u| u.ch == '}')
    }

    fn scan_digits(&mut self) -> Option<u32> {
        let mut value: u32 = 0;
        let mut any = false;
        while let Some(unit) = self.peek() {
            if !unit.ch.is_ascii_digit() {
                break;
            }
            value = value
                .checked_mul(10)?
                .checked_add(u32::from(unit.ch as u8 - b'0'))?;
            self.bump();
            any = true;
        }
        any.then_some(value)
    }

    fn parse_atom(&mut self) -> RxResult<(RxAtom, TextSize)> {
        let Some(unit) = self.bump() else {
            return Err(self.err_at(None));
        };
        let start = unit.at;
        let atom = match unit.ch {
            ')' | '*' | '+' | '?' => return Err(self.err_at(Some(unit))),
            '(' => return self.parse_group(start),
            '[' => RxAtom::Class(self.parse_class(start)?),
            '.' => RxAtom::Dot,
            '^' => RxAtom::Anchor(RxAnchor::Caret),
            '$' => RxAtom::Anchor(RxAnchor::Dollar),
            '\\' => return self.parse_escape(start),
            other => RxAtom::Literal(other),
        };
        Ok((atom, start))
    }

    /// Group dispatch: plain captures, `(?:…)`, flags groups, lookarounds,
    /// atomic groups, `(?#…)` comments, `(?P=name)` references and
    /// `(?(cond)…)` conditionals.
    fn parse_group(&mut self, start: TextSize) -> RxResult<(RxAtom, TextSize)> {
        let open = self
            .units
            .get(self.pos - 1)
            .copied()
            .ok_or_else(|| self.err_at(None))?;
        self.enter(open)?;
        let head = if self.peek().is_some_and(|u| u.ch == '?') {
            self.bump();
            self.parse_group_head()?
        } else {
            GroupHead::Capture(None)
        };
        let atom = match head {
            GroupHead::Complete(atom) => atom,
            GroupHead::NamedBackref(name) => RxAtom::NamedRef(name),
            GroupHead::Kind(kind) => {
                let body = self.parse_alternation(Some(')'))?;
                let close = self.expect_close()?;
                RxAtom::Group(RxGroup {
                    kind,
                    body,
                    span: TextRange::new(start, close),
                })
            }
            GroupHead::Capture(name) => {
                let span_start = start;
                self.capture_count += 1;
                self.visible_numbers.push(self.capture_count);
                if let Some(name) = name.as_ref() {
                    if self.all_names.iter().any(|seen| seen == name) {
                        return Err(self.err_at(Some(open)));
                    }
                    self.all_names.push(name.clone());
                    self.visible_names.push(name.clone());
                }
                let body = self.parse_alternation(Some(')'))?;
                let close = self.expect_close()?;
                RxAtom::Group(RxGroup {
                    kind: RxGroupKind::Capture,
                    body,
                    span: TextRange::new(span_start, close),
                })
            }
        };
        self.leave();
        Ok((atom, start))
    }

    /// Consumes the `(?` extension marker and classifies the group.
    fn parse_group_head(&mut self) -> RxResult<GroupHead> {
        let marker = self.bump().ok_or_else(|| self.err_at(None))?;
        match marker.ch {
            ':' => Ok(GroupHead::Kind(RxGroupKind::NonCapture)),
            '#' => {
                while let Some(unit) = self.bump() {
                    if unit.ch == ')' {
                        break;
                    }
                }
                Ok(GroupHead::Complete(RxAtom::Comment))
            }
            '=' => Ok(GroupHead::Kind(RxGroupKind::Lookahead)),
            '!' => Ok(GroupHead::Kind(RxGroupKind::NegativeLookahead)),
            '>' => Ok(GroupHead::Kind(RxGroupKind::Atomic)),
            '<' => match self.peek().map(|u| u.ch) {
                Some('=') => {
                    self.bump();
                    Ok(GroupHead::Kind(RxGroupKind::Lookbehind))
                }
                Some('!') => {
                    self.bump();
                    Ok(GroupHead::Kind(RxGroupKind::NegativeLookbehind))
                }
                _ => Err(self.err_at(Some(marker))),
            },
            'P' => self.parse_p_extension(marker),
            '(' => self.parse_conditional_head(marker),
            'a' | 'i' | 'L' | 'm' | 's' | 'u' | 'x' => self.parse_flag_group(marker),
            _ => Err(self.err_at(Some(marker))),
        }
    }

    /// `(?P<name>…)` named capture or `(?P=name)` named reference.
    fn parse_p_extension(&mut self, marker: RxUnit) -> RxResult<GroupHead> {
        let next = self.peek().ok_or_else(|| self.err_at(Some(marker)))?;
        if next.ch != '<' && next.ch != '=' {
            return Err(self.err_at(Some(next)));
        }
        self.bump();
        let named_reference = next.ch == '=';
        let terminator = if named_reference { ')' } else { '>' };
        let mut name = String::new();
        while let Some(unit) = self.peek() {
            if unit.ch == terminator {
                break;
            }
            if !unit.ch.is_alphanumeric() && unit.ch != '_' {
                return Err(self.err_at(Some(unit)));
            }
            name.push(unit.ch);
            self.bump();
        }
        if name.is_empty()
            || !name
                .chars()
                .next()
                .is_some_and(|first| first.is_alphabetic() || first == '_')
        {
            return Err(self.err_at(self.peek()));
        }
        if named_reference {
            // `(?P=name)` is a complete atom including its closing paren.
            let close = self.bump();
            match close {
                Some(unit) if unit.ch == ')' => {}
                other => return Err(self.err_at(other)),
            }
            let span = TextRange::new(marker.at, self.consumed_end(marker.at));
            self.record_backref(Some(name.clone()), None, span);
            return Ok(GroupHead::NamedBackref(name));
        }
        let close = self.bump();
        match close {
            Some(unit) if unit.ch == '>' => {}
            other => return Err(self.err_at(other)),
        }
        Ok(GroupHead::Capture(Some(name)))
    }

    /// `(?(1)yes|no)` conditional: consume the condition up to its `)`.
    fn parse_conditional_head(&mut self, marker: RxUnit) -> RxResult<GroupHead> {
        let mut saw_token = false;
        while let Some(unit) = self.peek() {
            if unit.ch == ')' {
                break;
            }
            if !unit.ch.is_alphanumeric() && unit.ch != '_' {
                return Err(self.err_at(Some(unit)));
            }
            saw_token = true;
            self.bump();
        }
        if !saw_token {
            return Err(self.err_at(Some(marker)));
        }
        let close = self.bump();
        match close {
            Some(unit) if unit.ch == ')' => Ok(GroupHead::Kind(RxGroupKind::Conditional)),
            other => Err(self.err_at(other)),
        }
    }

    /// `(?flags)` global settings or `(?flags:body)` scoped groups.
    fn parse_flag_group(&mut self, marker: RxUnit) -> RxResult<GroupHead> {
        // The dispatcher already consumed the first flag letter.
        while self
            .peek()
            .is_some_and(|u| matches!(u.ch, 'a' | 'i' | 'L' | 'm' | 's' | 'u' | 'x'))
        {
            self.bump();
        }
        match self.peek().map(|u| u.ch) {
            Some(':') => {
                self.bump();
                Ok(GroupHead::Kind(RxGroupKind::FlagScope))
            }
            Some(')') => {
                self.bump();
                Ok(GroupHead::Complete(RxAtom::GlobalFlags))
            }
            _ => Err(self.err_at(Some(marker))),
        }
    }

    fn expect_close(&mut self) -> RxResult<TextSize> {
        let close = self.bump();
        match close {
            Some(unit) if unit.ch == ')' => Ok(unit.at + TextSize::from(to_u32(')'.len_utf8()))),
            other => Err(self.err_at(other)),
        }
    }

    fn record_backref(&mut self, name: Option<String>, number: Option<u32>, span: TextRange) {
        self.backrefs.push(RxBackrefRecord {
            name,
            number,
            span,
            visible_numbers: self.visible_numbers.clone(),
            visible_names: self.visible_names.clone(),
        });
    }

    /// Pattern-level escape dispatch (`\d`, anchors, `\xHH`, octal escapes,
    /// back references, opaque `\p{...}`); unknown ASCII-letter escapes are
    /// syntax errors exactly like Python 3.7+.
    fn parse_escape(&mut self, start: TextSize) -> RxResult<(RxAtom, TextSize)> {
        let Some(next) = self.peek() else {
            return Err(self.err_at(None));
        };
        let done = |atom: RxAtom| Ok((atom, start));
        match next.ch {
            'd' => Ok(self.bump_simple(RxEscClass::Digit, start)),
            'D' => Ok(self.bump_simple(RxEscClass::NotDigit, start)),
            'w' => Ok(self.bump_simple(RxEscClass::Word, start)),
            'W' => Ok(self.bump_simple(RxEscClass::NotWord, start)),
            's' => Ok(self.bump_simple(RxEscClass::Space, start)),
            'S' => Ok(self.bump_simple(RxEscClass::NotSpace, start)),
            'b' => {
                self.bump();
                done(RxAtom::Anchor(RxAnchor::WordBoundary))
            }
            'B' => {
                self.bump();
                done(RxAtom::Anchor(RxAnchor::NotWordBoundary))
            }
            'A' => {
                self.bump();
                done(RxAtom::Anchor(RxAnchor::StringStart))
            }
            'Z' => {
                self.bump();
                done(RxAtom::Anchor(RxAnchor::StringEnd))
            }
            'z' => {
                self.bump();
                done(RxAtom::Anchor(RxAnchor::StringEndNl))
            }
            'x' => self.parse_hex_escape(start, 2),
            'u' => self.parse_hex_escape(start, 4),
            'U' => self.parse_hex_escape(start, 8),
            'N' => self.parse_named_char(start),
            'p' | 'P' => self.parse_unicode_property(start),
            'g' => Err(self.err_at(Some(next))),
            '0'..='9' => self.parse_number_escape(start),
            ch if ch.is_ascii_alphabetic() => Err(self.err_at(Some(next))),
            _ => {
                self.bump();
                done(RxAtom::Literal(next.ch))
            }
        }
    }

    fn bump_simple(&mut self, class: RxEscClass, start: TextSize) -> (RxAtom, TextSize) {
        self.bump();
        (RxAtom::EscClass(class), start)
    }

    /// `\p{Name}` / `\P{Name}`: opaque Unicode property class.
    fn parse_unicode_property(&mut self, start: TextSize) -> RxResult<(RxAtom, TextSize)> {
        self.bump(); // 'p'/'P'
        if self.peek().is_none_or(|u| u.ch != '{') {
            return Err(self.err_at(self.peek()));
        }
        self.bump();
        while let Some(unit) = self.peek() {
            if unit.ch == '}' {
                self.bump();
                return Ok((RxAtom::EscClass(RxEscClass::UnicodeOpaque), start));
            }
            self.bump();
        }
        Err(self.err_at(self.peek()))
    }

    /// `\xHH` / `\uHHHH` / `\UHHHHHHHH`; incomplete forms are errors.
    fn parse_hex_escape(&mut self, start: TextSize, width: usize) -> RxResult<(RxAtom, TextSize)> {
        self.bump(); // 'x'/'u'/'U'
        let mut text = String::new();
        for _ in 0..width {
            let Some(unit) = self.peek().filter(|u| u.ch.is_ascii_hexdigit()) else {
                return Err(self.err_at(self.peek()));
            };
            text.push(unit.ch);
            self.bump();
        }
        let value = u32::from_str_radix(&text, 16).unwrap_or(0xfffd);
        Ok((
            RxAtom::Literal(char::from_u32(value).unwrap_or('\u{fffd}')),
            start,
        ))
    }

    /// `\N{NAME}`: opaque named character.
    fn parse_named_char(&mut self, start: TextSize) -> RxResult<(RxAtom, TextSize)> {
        self.bump(); // 'N'
        if self.peek().is_none_or(|u| u.ch != '{') {
            return Err(self.err_at(self.peek()));
        }
        while let Some(unit) = self.peek() {
            self.bump();
            if unit.ch == '}' {
                return Ok((RxAtom::Literal('\u{fffd}'), start));
            }
        }
        Err(self.err_at(self.peek()))
    }

    /// Numeric escape: `\0…`/three-octal-digit octal escapes (recorded for
    /// python:S6537) or decimal back references (python:S6001).
    fn parse_number_escape(&mut self, start: TextSize) -> RxResult<(RxAtom, TextSize)> {
        let mut digits: Vec<u8> = Vec::new();
        while let Some(unit) = self.peek().filter(|u| u.ch.is_ascii_digit())
            && digits.len() < 3
        {
            digits.push(unit.ch as u8 - b'0');
            self.bump();
        }
        let octal = digits[0] == 0 || (digits.len() == 3 && digits.iter().all(|d| *d <= 7));
        let span = TextRange::new(start, self.consumed_end(start));
        if octal {
            let value = digits.iter().fold(0u32, |acc, d| acc * 8 + u32::from(*d));
            if value > 0o377 {
                return Err(self.err_at(self.peek()));
            }
            self.octals.push(RxOctalRecord { span });
            Ok((
                RxAtom::Literal(char::from_u32(value).unwrap_or('\u{fffd}')),
                start,
            ))
        } else {
            digits.truncate(2);
            let number = digits.iter().fold(0u32, |acc, d| acc * 10 + u32::from(*d));
            self.record_backref(None, Some(number), span);
            Ok((RxAtom::Backref(number), start))
        }
    }

    /// Character class contents: ranges, class shorthands, escapes; the `]`
    /// right after `[`/`[^` is a literal, and `\b` means backspace inside.
    fn parse_class(&mut self, start: TextSize) -> RxResult<RxClass> {
        let negated = if self.peek().is_some_and(|u| u.ch == '^') {
            self.bump();
            true
        } else {
            false
        };
        let mut items = Vec::new();
        let mut first = true;
        loop {
            let Some(unit) = self.peek() else {
                return Err(self.err_at(self.peek()));
            };
            if unit.ch == ']' && !first {
                self.bump();
                break;
            }
            first = false;
            self.parse_class_item(&mut items)?;
        }
        let end = self.consumed_end(start);
        Ok(RxClass {
            negated,
            items,
            span: TextRange::new(start, end),
        })
    }

    /// One class member, including `-range-` composition.
    fn parse_class_item(&mut self, items: &mut Vec<RxClassItem>) -> RxResult<()> {
        let element = self.parse_class_element()?;
        let RxClassItem::Char(low) = element else {
            items.push(element);
            return Ok(());
        };
        let dashes = self.peek().is_some_and(|u| u.ch == '-')
            && self.peek_second().is_some_and(|u| u.ch != ']');
        if dashes {
            self.bump(); // '-'
            match self.parse_class_element()? {
                RxClassItem::Char(high) if high >= low => {
                    items.push(RxClassItem::Range(low, high));
                }
                _ => {
                    return Err(self.err_at(self.peek()));
                }
            }
        } else {
            items.push(RxClassItem::Char(low));
            if self.peek().is_some_and(|u| u.ch == '-')
                && self.peek_second().is_some_and(|u| u.ch == ']')
            {
                self.bump();
                items.push(RxClassItem::Char('-'));
            }
        }
        Ok(())
    }

    /// One undecorated class element: character, shorthand, or escape.
    fn parse_class_element(&mut self) -> RxResult<RxClassItem> {
        let Some(unit) = self.bump() else {
            return Err(self.err_at(None));
        };
        if unit.ch != '\\' {
            return Ok(RxClassItem::Char(unit.ch));
        }
        let Some(next) = self.peek() else {
            return Err(self.err_at(None));
        };
        match next.ch {
            'd' => Ok(self.class_shorthand(RxEscClass::Digit)),
            'D' => Ok(self.class_shorthand(RxEscClass::NotDigit)),
            'w' => Ok(self.class_shorthand(RxEscClass::Word)),
            'W' => Ok(self.class_shorthand(RxEscClass::NotWord)),
            's' => Ok(self.class_shorthand(RxEscClass::Space)),
            'S' => Ok(self.class_shorthand(RxEscClass::NotSpace)),
            'b' => {
                self.bump();
                Ok(RxClassItem::Char('\u{08}'))
            }
            'x' => self.class_hex(2),
            'u' => self.class_hex(4),
            'U' => self.class_hex(8),
            'N' => {
                self.bump();
                if self.peek().is_none_or(|u| u.ch != '{') {
                    return Err(self.err_at(self.peek()));
                }
                while let Some(inner) = self.peek() {
                    self.bump();
                    if inner.ch == '}' {
                        return Ok(RxClassItem::Char('\u{fffd}'));
                    }
                }
                Err(self.err_at(self.peek()))
            }
            '0'..='7' => self.class_octal(),
            ch if ch.is_ascii_alphabetic() => Err(self.err_at(Some(next))),
            _ => {
                self.bump();
                Ok(RxClassItem::Char(next.ch))
            }
        }
    }

    fn class_shorthand(&mut self, class: RxEscClass) -> RxClassItem {
        self.bump();
        RxClassItem::Esc(class)
    }

    fn class_hex(&mut self, width: usize) -> RxResult<RxClassItem> {
        self.bump(); // 'x'/'u'/'U'
        let mut text = String::new();
        for _ in 0..width {
            let Some(unit) = self.peek().filter(|u| u.ch.is_ascii_hexdigit()) else {
                return Err(self.err_at(self.peek()));
            };
            text.push(unit.ch);
            self.bump();
        }
        let value = u32::from_str_radix(&text, 16).unwrap_or(0xfffd);
        Ok(RxClassItem::Char(
            char::from_u32(value).unwrap_or('\u{fffd}'),
        ))
    }

    /// Octal escapes inside classes are never back references.
    fn class_octal(&mut self) -> RxResult<RxClassItem> {
        let start = self.peek().map_or(TextSize::new(0), |u| u.at);
        let mut value: u32 = 0;
        let mut count = 0;
        while let Some(unit) = self.peek().filter(|u| ('0'..='7').contains(&u.ch))
            && count < 3
        {
            value = value * 8 + (u32::from(unit.ch) - u32::from('0'));
            self.bump();
            count += 1;
        }
        if value > 0o377 {
            return Err(self.err_at(self.peek()));
        }
        let span = TextRange::new(start, self.consumed_end(start));
        self.octals.push(RxOctalRecord { span });
        Ok(RxClassItem::Char(
            char::from_u32(value).unwrap_or('\u{fffd}'),
        ))
    }
}

/// Head classification returned by [`RxParser::parse_group_head`].
pub(crate) enum GroupHead {
    /// Body-less atoms whose span is already final (`(?#…)`, `(?flags)`).
    Complete(RxAtom),
    /// `(?P=name)` terminates the atom itself.
    NamedBackref(String),
    /// Body follows; closed by the matching `)`.
    Kind(RxGroupKind),
    /// Plain or named capturing group; bookkeeping happens in the caller.
    Capture(Option<String>),
}

pub(crate) fn atom_span_end(atom: &RxAtom, start: TextSize) -> TextSize {
    match atom {
        RxAtom::Group(group) => group.span.end(),
        RxAtom::Class(class) => class.span.end(),
        _ => start,
    }
}

/// Parsed pattern plus everything the rule checks need from the parse pass.
pub(crate) struct RxParsed {
    pub(crate) root: RxNode,
    pub(crate) capture_count: u32,
    pub(crate) names: Vec<String>,
    pub(crate) backrefs: Vec<RxBackrefRecord>,
    pub(crate) octals: Vec<RxOctalRecord>,
}

pub(crate) fn parse_regex(units: &[RxUnit]) -> RxResult<RxParsed> {
    RxParser::new(units).parse_root()
}

// ---------------------------------------------------------------------------
// regex: rule checks over the parsed pattern engine above.
// ---------------------------------------------------------------------------

/// Decoded string-literal contents of a regex argument.
pub(crate) struct RegexLiteral {
    pub(crate) units: Vec<RxUnit>,
}

/// One `re.<fn>(...)` call site relevant to the regex rules.
pub(crate) struct RegexSite {
    pub(crate) pattern_range: TextRange,
    pub(crate) pattern: Option<Vec<RxUnit>>,
    pub(crate) repl: Option<RegexLiteral>,
    pub(crate) verbose: bool,
}

pub(crate) fn decode_regex_literal(expr: &Expr, source: &str) -> Option<RegexLiteral> {
    let Expr::StringLiteral(literal) = expr else {
        return None;
    };
    let mut units = Vec::new();
    for part in &literal.value {
        units.extend(decode_string_part(
            &source[part.range()],
            part.range().start(),
        ));
    }
    Some(RegexLiteral { units })
}

pub(crate) fn collect_regex_sites(body: &[Stmt], source: &str) -> Vec<RegexSite> {
    let mut sites = Vec::new();
    for_each_call(body, &mut |call| {
        let Some(path) = dotted_name(&call.func) else {
            return;
        };
        if !REGEX_FUNCTIONS.contains(&path.as_str()) {
            return;
        }
        let pattern_expr = call
            .arguments
            .args
            .first()
            .or_else(|| keyword_value(&call.arguments, "pattern"));
        let repl = if matches!(path.as_str(), "re.sub" | "re.subn") {
            call.arguments
                .args
                .get(1)
                .or_else(|| keyword_value(&call.arguments, "repl"))
                .and_then(|expr| decode_regex_literal(expr, source))
        } else {
            None
        };
        sites.push(RegexSite {
            pattern_range: pattern_expr.map_or_else(|| call.range(), Ranged::range),
            pattern: pattern_expr
                .and_then(|expr| decode_regex_literal(expr, source))
                .map(|literal| literal.units),
            repl,
            verbose: has_verbose_flag(&call.arguments),
        });
    });
    sites
}

// --- shared regex-AST walkers and predicates --------------------------------

pub(crate) fn for_each_rx_seq<'a>(node: &'a RxNode, visit: &mut impl FnMut(&'a RxSeq)) {
    match node {
        RxNode::Seq(seq) => visit(seq),
        RxNode::Alternation(branches) => {
            for branch in branches {
                visit(branch);
            }
        }
    }
}

pub(crate) fn for_each_rx_item<'a>(node: &'a RxNode, visit: &mut impl FnMut(&'a RxItem)) {
    for_each_rx_seq(node, &mut |seq| {
        for item in &seq.items {
            visit(item);
            if let RxAtom::Group(group) = &item.atom {
                for_each_rx_item(&group.body, visit);
            }
        }
    });
}

pub(crate) fn rx_atom_nullable(atom: &RxAtom) -> bool {
    match atom {
        RxAtom::Anchor(_)
        | RxAtom::Backref(_)
        | RxAtom::NamedRef(_)
        | RxAtom::GlobalFlags
        | RxAtom::Comment => true,
        RxAtom::Group(group) => {
            if matches!(
                group.kind,
                RxGroupKind::Lookahead
                    | RxGroupKind::NegativeLookahead
                    | RxGroupKind::Lookbehind
                    | RxGroupKind::NegativeLookbehind
            ) {
                true
            } else {
                rx_node_nullable(&group.body)
            }
        }
        _ => false,
    }
}

pub(crate) fn rx_node_nullable(node: &RxNode) -> bool {
    match node {
        RxNode::Alternation(branches) => branches.iter().any(rx_seq_nullable),
        RxNode::Seq(seq) => rx_seq_nullable(seq),
    }
}

pub(crate) fn rx_seq_nullable(seq: &RxSeq) -> bool {
    seq.items.iter().all(|item| match &item.quant {
        Some(quant) => quant.min == 0 || rx_atom_nullable(&item.atom),
        None => rx_atom_nullable(&item.atom),
    })
}

/// Zero-width atoms: assertions, flags, comments, and lookarounds.
pub(crate) fn rx_atom_zero_width(atom: &RxAtom) -> bool {
    matches!(
        atom,
        RxAtom::Anchor(_) | RxAtom::GlobalFlags | RxAtom::Comment
    ) || matches!(
        atom,
        RxAtom::Group(group)
            if matches!(
                group.kind,
                RxGroupKind::Lookahead
                    | RxGroupKind::NegativeLookahead
                    | RxGroupKind::Lookbehind
                    | RxGroupKind::NegativeLookbehind
            )
    )
}

/// Whether `item` requires at least one non-empty-width step.
pub(crate) fn rx_item_consuming(item: &RxItem) -> bool {
    let lookaround = matches!(
        &item.atom,
        RxAtom::Group(group)
            if matches!(
                group.kind,
                RxGroupKind::Lookahead
                    | RxGroupKind::NegativeLookahead
                    | RxGroupKind::Lookbehind
                    | RxGroupKind::NegativeLookbehind
            )
    );
    let zero_width = lookaround
        || matches!(
            &item.atom,
            RxAtom::Anchor(_) | RxAtom::GlobalFlags | RxAtom::Comment
        );
    !zero_width && item.quant.as_ref().is_none_or(|quant| quant.min >= 1)
}

pub(crate) fn rx_is_unbounded_repeat(item: &RxItem) -> bool {
    item.quant
        .as_ref()
        .is_some_and(|quant| quant.max.is_none() && !quant.possessive)
}

// --- character-set approximation --------------------------------------------

/// Approximate first-character set of an atom; conservative intersections.
#[derive(Debug, Clone)]
pub(crate) enum RxSet {
    All,
    Members {
        exact: BTreeSet<char>,
        ranges: Vec<(char, char)>,
    },
    Excluding {
        exact: BTreeSet<char>,
        ranges: Vec<(char, char)>,
    },
}

pub(crate) fn esc_class_members(class: RxEscClass) -> Option<RxSet> {
    let members = |exact: &[char], ranges: &[(char, char)]| RxSet::Members {
        exact: exact.iter().copied().collect(),
        ranges: ranges.to_vec(),
    };
    match class {
        RxEscClass::Digit => Some(members(&[], &[('0', '9')])),
        RxEscClass::Word => Some(members(&['_'], &[('0', '9'), ('A', 'Z'), ('a', 'z')])),
        RxEscClass::Space => Some(members(&[' ', '\t', '\n', '\u{0b}', '\u{0c}', '\r'], &[])),
        RxEscClass::NotDigit => Some(RxSet::Excluding {
            exact: BTreeSet::new(),
            ranges: vec![('0', '9')],
        }),
        RxEscClass::NotWord => Some(RxSet::Excluding {
            exact: ['_'].into_iter().collect(),
            ranges: vec![('0', '9'), ('A', 'Z'), ('a', 'z')],
        }),
        RxEscClass::NotSpace => Some(RxSet::Excluding {
            exact: [' ', '\t', '\n', '\u{0b}', '\u{0c}', '\r']
                .into_iter()
                .collect(),
            ranges: vec![],
        }),
        RxEscClass::UnicodeOpaque => None,
    }
}

pub(crate) fn class_item_member(
    item: &RxClassItem,
    out: &mut (BTreeSet<char>, Vec<(char, char)>),
) -> bool {
    match item {
        RxClassItem::Char(ch) => {
            out.0.insert(*ch);
            true
        }
        RxClassItem::Range(low, high) => {
            out.1.push((*low, *high));
            true
        }
        RxClassItem::Esc(class) => match esc_class_members(*class) {
            Some(RxSet::Members { exact, ranges }) => {
                out.0.extend(exact);
                out.1.extend(ranges);
                true
            }
            _ => false,
        },
    }
}

pub(crate) fn rx_atom_first_set(atom: &RxAtom) -> Option<RxSet> {
    match atom {
        RxAtom::Literal(ch) => Some(RxSet::Members {
            exact: [*ch].into_iter().collect(),
            ranges: vec![],
        }),
        RxAtom::Dot => Some(RxSet::All),
        RxAtom::Class(class) => {
            let mut members = (BTreeSet::new(), Vec::new());
            let concrete = class
                .items
                .iter()
                .all(|item| class_item_member(item, &mut members));
            if !concrete {
                return None;
            }
            if class.negated {
                Some(RxSet::Excluding {
                    exact: members.0,
                    ranges: members.1,
                })
            } else {
                Some(RxSet::Members {
                    exact: members.0,
                    ranges: members.1,
                })
            }
        }
        RxAtom::EscClass(class) => esc_class_members(*class),
        RxAtom::Group(group) => rx_node_first_set(&group.body),
        _ => None,
    }
}

pub(crate) fn rx_node_first_set(node: &RxNode) -> Option<RxSet> {
    match node {
        RxNode::Alternation(branches) => {
            let mut combined = None;
            for branch in branches {
                let set = rx_branch_first_set(branch)?;
                combined = Some(match combined {
                    None => set,
                    Some(previous) => rx_union_sets(previous, set)?,
                });
            }
            combined
        }
        RxNode::Seq(seq) => rx_branch_first_set(seq),
    }
}

/// First mandatory character of a branch: skip leading nullable items.
pub(crate) fn rx_branch_first_set(seq: &RxSeq) -> Option<RxSet> {
    for item in &seq.items {
        let nullable = match &item.quant {
            Some(quant) => quant.min == 0 || rx_atom_nullable(&item.atom),
            None => rx_atom_nullable(&item.atom),
        };
        if nullable {
            continue;
        }
        return rx_atom_first_set(&item.atom);
    }
    None
}

pub(crate) fn rx_union_sets(left: RxSet, right: RxSet) -> Option<RxSet> {
    match (left, right) {
        (RxSet::All, _) | (_, RxSet::All) => Some(RxSet::All),
        (
            RxSet::Members {
                exact: mut e1,
                ranges: mut r1,
            },
            RxSet::Members {
                exact: e2,
                ranges: r2,
            },
        ) => {
            e1.extend(e2);
            r1.extend(r2);
            Some(RxSet::Members {
                exact: e1,
                ranges: r1,
            })
        }
        _ => None,
    }
}

/// Conservative intersection test; undecidable shapes count as intersecting.
pub(crate) fn rx_sets_intersect(a: &RxSet, b: &RxSet) -> bool {
    use RxSet::{All, Excluding, Members};
    fn partly_outside(
        ranges: &[(char, char)],
        excluded_exact: &BTreeSet<char>,
        excluded_ranges: &[(char, char)],
    ) -> bool {
        ranges.iter().any(|(low, high)| {
            [*low, *high]
                .into_iter()
                .any(|ch| !excluded_exact.contains(&ch) && !member_in_ranges(ch, excluded_ranges))
                || !excluded_ranges
                    .iter()
                    .any(|(l2, h2)| l2 <= low && high <= h2)
        })
    }
    if matches!(a, All) || matches!(b, All) {
        return true;
    }
    match (a, b) {
        (
            Members {
                exact: e1,
                ranges: r1,
            },
            Members {
                exact: e2,
                ranges: r2,
            },
        ) => {
            e1.iter()
                .any(|ch| e2.contains(ch) || member_in_ranges(*ch, r2))
                || e2.iter().any(|ch| member_in_ranges(*ch, r1))
                || ranges_overlap(r1, r2)
        }
        (
            Members { exact, ranges },
            Excluding {
                exact: xe,
                ranges: xr,
            },
        )
        | (
            Excluding {
                exact: xe,
                ranges: xr,
            },
            Members { exact, ranges },
        ) => {
            exact
                .iter()
                .any(|ch| !xe.contains(ch) && !member_in_ranges(*ch, xr))
                || partly_outside(ranges, xe, xr)
        }
        _ => true,
    }
}

/// Span of a branch-leading start anchor (`^a|b` mis-shape).
pub(crate) fn rx_leading_anchor_span(branch: &RxSeq) -> Option<TextRange> {
    match branch.items.first() {
        Some(item)
            if item.quant.is_none() && matches!(item.atom, RxAtom::Anchor(a) if a.is_start()) =>
        {
            Some(item.span)
        }
        _ => None,
    }
}

pub(crate) fn rx_trailing_anchor_span(branch: &RxSeq) -> Option<TextRange> {
    match branch.items.last() {
        Some(item)
            if item.quant.is_none() && matches!(item.atom, RxAtom::Anchor(a) if a.is_end()) =>
        {
            Some(item.span)
        }
        _ => None,
    }
}

pub(crate) fn rx_lookahead_body(atom: &RxAtom) -> Option<&RxNode> {
    match atom {
        RxAtom::Group(group)
            if matches!(
                group.kind,
                RxGroupKind::Lookahead | RxGroupKind::NegativeLookahead
            ) =>
        {
            Some(&group.body)
        }
        _ => None,
    }
}

pub(crate) fn rx_positive_lookahead_body(atom: &RxAtom) -> Option<&RxNode> {
    match atom {
        RxAtom::Group(group) if group.kind == RxGroupKind::Lookahead => Some(&group.body),
        _ => None,
    }
}

pub(crate) fn flush_space_run(run: &[&RxItem], push: &mut dyn FnMut(&str, &str, TextRange)) {
    if run.len() >= 2 {
        push(
            "python:S6326",
            "Replace multiple spaces with one space and a quantifier.",
            TextRange::new(run[0].span.start(), run[run.len() - 1].span.end()),
        );
    }
}

/// Whether every input matched by `later` is also matched by `earlier`.
pub(crate) fn rx_branch_covered_by(earlier: &RxSeq, later: &RxSeq) -> bool {
    fn single(branch: &RxSeq) -> Option<&RxItem> {
        (branch.items.len() == 1 && branch.items[0].quant.is_none()).then(|| &branch.items[0])
    }
    if rx_seq_equivalent(earlier, later) {
        return true;
    }
    let Some(later_item) = single(later) else {
        return false;
    };
    if let RxAtom::Literal(ch) = &later_item.atom {
        // `[ab]|a` — a class superset covers the single character.
        if let Some(earlier_item) = single(earlier)
            && let RxAtom::Class(class) = &earlier_item.atom
            && !class.negated
            && class_contains_char(class, *ch)
        {
            return true;
        }
    }
    // `.*|a` — an all-matching wildcard alternative covers everything.
    if earlier.items.len() == 1
        && matches!(earlier.items[0].atom, RxAtom::Dot)
        && earlier.items[0]
            .quant
            .as_ref()
            .is_none_or(|quant| quant.max != Some(0))
    {
        return true;
    }
    false
}

pub(crate) fn class_contains_char(class: &RxClass, ch: char) -> bool {
    class.items.iter().any(|item| match item {
        RxClassItem::Char(member) => member == &ch,
        RxClassItem::Range(low, high) => low <= &ch && &ch <= high,
        RxClassItem::Esc(shorthand) => match shorthand {
            RxEscClass::Digit => ch.is_ascii_digit(),
            RxEscClass::Word => ch.is_ascii_alphanumeric() || ch == '_',
            RxEscClass::Space => matches!(ch, ' ' | '\t' | '\n' | '\u{0b}' | '\u{0c}' | '\r'),
            _ => false,
        },
    })
}

pub(crate) fn is_repetitive(quant: &RxQuant) -> bool {
    quant.max.is_none_or(|max| max >= 2)
}

/// Whether the body can match the same input in structurally different ways.
pub(crate) fn rx_body_ambiguous(node: &RxNode) -> bool {
    match node {
        RxNode::Alternation(_) => true,
        RxNode::Seq(seq) => {
            if seq
                .items
                .iter()
                .any(|item| item.quant.as_ref().is_some_and(|quant| quant.min == 0))
            {
                return true;
            }
            let repetitive: Vec<&RxItem> = seq
                .items
                .iter()
                .filter(|item| item.quant.as_ref().is_some_and(is_repetitive))
                .collect();
            match repetitive.len() {
                0 => false,
                1 => {
                    let rep = repetitive[0];
                    if seq.items.len() == 1 {
                        // `(a+)+`: a lone repetition can split its input in
                        // many ways across outer iterations.
                        return true;
                    }
                    // One repetition plus mandatory neighbors: ambiguous only
                    // when a neighbor's first characters overlap the repeated
                    // atom (e.g. `(a+a)+`) rather than anchoring it (`(ba+)+`).
                    seq.items.iter().any(|item| {
                        item.span != rep.span
                            && match (rx_atom_first_set(&item.atom), rx_atom_first_set(&rep.atom)) {
                                (Some(a), Some(b)) => rx_sets_intersect(&a, &b),
                                _ => true,
                            }
                    })
                }
                _ => true,
            }
        }
    }
}

/// Whether `next` can be satisfied without consuming anything, or is an end
/// anchor. A group with an explicit end-anchor alternative (e.g. `(end|$)`)
/// is the sanctioned way to terminate a lazy quantifier and is exempt.
pub(crate) fn lazy_next_forced_empty(next: &RxItem) -> bool {
    match &next.atom {
        RxAtom::Anchor(anchor) if anchor.is_end() => true,
        RxAtom::Group(group)
            if matches!(&group.body, RxNode::Alternation(branches)
                if branches.iter().any(|branch|
                    branch.items.len() == 1
                        && matches!(branch.items[0].atom, RxAtom::Anchor(a) if a.is_end()))) =>
        {
            false
        }
        _ => rx_item_nullable_pub(next),
    }
}

pub(crate) fn rx_item_nullable_pub(item: &RxItem) -> bool {
    match &item.quant {
        Some(quant) => quant.min == 0 || rx_atom_nullable(&item.atom),
        None => rx_atom_nullable(&item.atom),
    }
}

pub(crate) fn rx_optional_separator_overlaps(
    middle: &RxItem,
    first: &RxItem,
    second: &RxItem,
) -> bool {
    let Some(set_m) = rx_atom_first_set(&middle.atom) else {
        return true;
    };
    [(first, "f"), (second, "s")].iter().any(|(item, _)| {
        rx_atom_first_set(&item.atom).is_some_and(|set| rx_sets_intersect(&set, &set_m))
    })
}

pub(crate) fn for_each_class<'a>(node: &'a RxNode, visit: &mut impl FnMut(&'a RxClass)) {
    for_each_rx_item(node, &mut |item| {
        if let RxAtom::Class(class) = &item.atom {
            visit(class);
        }
    });
}

/// Concise equivalent message for exact known class shapes.
pub(crate) fn concise_class_message(class: &RxClass) -> Option<&'static str> {
    let ranges_of = |items: &[RxClassItem]| -> Option<Vec<(char, char)>> {
        items
            .iter()
            .map(|item| match item {
                RxClassItem::Range(low, high) => Some((*low, *high)),
                RxClassItem::Char('_') => Some(('_', '_')),
                _ => None,
            })
            .collect()
    };
    let digit = [('0', '9')];
    let word = [('0', '9'), ('A', 'Z'), ('_', '_'), ('a', 'z')];
    if let Some(ranges) = ranges_of(&class.items) {
        let same = |shape: &[(char, char)]| {
            ranges.len() == shape.len() && shape.iter().all(|entry| ranges.contains(entry))
        };
        return match (class.negated, same(&digit), same(&word)) {
            (false, true, _) => Some("Use \\d instead of this character class."),
            (true, true, _) => Some("Use \\D instead of this character class."),
            (false, _, true) => Some("Use \\w instead of this character class."),
            (true, _, true) => Some("Use \\W instead of this character class."),
            _ => None,
        };
    }
    // [\w\W]-style complement pairs match everything: use the wildcard.
    let complementary = class.items.len() == 2
        && matches!(class.items[0], RxClassItem::Esc(_))
        && matches!(class.items[1], RxClassItem::Esc(_))
        && match (&class.items[0], &class.items[1]) {
            (RxClassItem::Esc(a), RxClassItem::Esc(b)) => {
                a.complement() == Some(*b) || b.complement() == Some(*a)
            }
            _ => false,
        };
    complementary.then_some("Use the wildcard instead of this all-matching character class.")
}

/// RSPEC-5843 complexity: nesting-sensitive operator counting.
pub(crate) fn rx_complexity(node: &RxNode, level: u32) -> u32 {
    match node {
        RxNode::Alternation(branches) => {
            let bars = u32::try_from(branches.len().saturating_sub(1)).unwrap_or(0);
            let mut cost = level.saturating_add(bars.saturating_sub(1));
            for branch in branches {
                cost += rx_complexity(&RxNode::Seq(branch.clone()), level + 1);
            }
            cost
        }
        RxNode::Seq(seq) => seq
            .items
            .iter()
            .map(|item| rx_item_complexity(item, level))
            .sum(),
    }
}

pub(crate) fn rx_item_complexity(item: &RxItem, level: u32) -> u32 {
    let mut cost = match &item.atom {
        RxAtom::Class(_) | RxAtom::Backref(_) | RxAtom::NamedRef(_) => 1,
        RxAtom::Group(group)
            if !matches!(group.kind, RxGroupKind::Capture | RxGroupKind::NonCapture) =>
        {
            level
        }
        _ => 0,
    };
    if item.quant.is_some() {
        cost += level;
    }
    let inner_level = level + u32::from(item.quant.is_some());
    if let RxAtom::Group(group) = &item.atom {
        cost += rx_complexity(&group.body, inner_level);
    }
    cost
}

pub(crate) fn rx_root_span(node: &RxNode) -> TextRange {
    match node {
        RxNode::Seq(seq) => seq.span,
        RxNode::Alternation(branches) => TextRange::new(
            branches[0].span.start(),
            branches[branches.len() - 1].span.end(),
        ),
    }
}
