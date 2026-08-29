use super::{
    AnchorKind, ClassItem, GroupKind, MAX_GROUP_DEPTH, ParsedRegex, PatternNode, ShorthandClass,
};

/// Parses the literal-syntax subset of ECMAScript regex patterns. Returns
/// `Err` only for definite syntax errors — unbalanced parentheses,
/// unterminated character classes, quantifiers with nothing to repeat,
/// unknown `(?…)` headers, reversed class ranges, malformed `\u`/`\x`
/// forms in unicode mode — and for runaway group nesting beyond
/// [`MAX_GROUP_DEPTH`] (degenerate input; bailing out keeps the scan
/// bounded). Anything merely unfamiliar parses conservatively so the
/// walker never invents findings (tolerant, never panics).
pub(crate) fn parse_regex_pattern(pattern: &str, unicode_mode: bool) -> Result<ParsedRegex, ()> {
    let mut parser = PatternParser {
        source: pattern,
        chars: pattern.char_indices().collect(),
        pos: 0,
        captures: Vec::new(),
        group_depth: 0,
        empty_branch_positions: Vec::new(),
        unicode_mode,
    };
    let alternatives = parser.parse_alternatives(None)?;
    Ok(ParsedRegex {
        capture_count: parser.captures.len(),
        capture_names: parser.captures.iter().flatten().cloned().collect(),
        alternatives,
        empty_branch_positions: parser.empty_branch_positions,
    })
}

struct PatternParser<'p> {
    /// The raw pattern text, for verbatim quantifier slices.
    source: &'p str,
    chars: Vec<(usize, char)>,
    pos: usize,
    captures: Vec<Option<String>>,
    unicode_mode: bool,
    /// Current `(` nesting level; bounded by [`MAX_GROUP_DEPTH`].
    group_depth: u32,
    empty_branch_positions: Vec<usize>,
}

impl PatternParser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).map(|&(_, ch)| ch)
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += 1;
        Some(ch)
    }

    fn current_offset(&self) -> usize {
        self.chars
            .get(self.pos)
            .map_or_else(|| self.end_offset(), |&(off, _)| off)
    }

    fn end_offset(&self) -> usize {
        self.chars
            .last()
            .map_or(0, |&(off, ch)| off + ch.len_utf8())
    }

    /// Alternation body of the whole pattern (`terminator: None`) or of one
    /// group (`terminator: Some(')')`, consumed here).
    fn parse_alternatives(
        &mut self,
        terminator: Option<char>,
    ) -> Result<Vec<Vec<PatternNode>>, ()> {
        let mut alternatives = Vec::new();
        let mut local_empties = Vec::new();
        loop {
            let branch_start = self.current_offset();
            let nodes = self.parse_sequence(terminator)?;
            if nodes.is_empty() {
                local_empties.push(branch_start);
            }
            alternatives.push(nodes);
            if self.peek() == Some('|') {
                self.pos += 1;
            } else {
                break;
            }
        }
        // A single empty branch is either an empty pattern (clean) or a
        // wholly empty group (`S6331`); neither belongs to `S6323`.
        if !(alternatives.len() == 1 && alternatives[0].is_empty()) {
            self.empty_branch_positions.extend(local_empties);
        }
        match terminator {
            None => {
                if self.pos != self.chars.len() {
                    return Err(()); // stray `)`
                }
            }
            Some(expected) => {
                if self.peek() != Some(expected) {
                    return Err(()); // unclosed group
                }
                self.pos += 1;
            }
        }
        Ok(alternatives)
    }

    fn parse_sequence(&mut self, terminator: Option<char>) -> Result<Vec<PatternNode>, ()> {
        let mut nodes: Vec<PatternNode> = Vec::new();
        loop {
            match self.peek() {
                None | Some('|') => break,
                Some(')') => {
                    if terminator == Some(')') {
                        break;
                    }
                    return Err(()); // unbalanced `)`
                }
                // A quantifier here has nothing to repeat: sequence start,
                // after `|`, after `(`, or stacked onto another quantifier.
                Some('*' | '+' | '?') => return Err(()),
                _ => {}
            }
            let atom = self.parse_atom()?;
            let quantifier_pos = self.current_offset();
            if let Some((min, max)) = self.try_parse_quantifier()? {
                let mut greedy = true;
                if self.peek() == Some('?') {
                    self.pos += 1;
                    greedy = false;
                }
                let verbose = self.source[quantifier_pos..self.current_offset()].to_string();
                nodes.push(PatternNode::Quantified {
                    node: Box::new(atom),
                    min,
                    max,
                    greedy,
                    pos: quantifier_pos,
                    verbose,
                });
            } else {
                nodes.push(atom);
            }
        }
        Ok(nodes)
    }

    /// `Ok(None)` when the upcoming text is not a quantifier (malformed
    /// braces stay literal characters, per Annex B); `Err` for a definite
    /// `{m,n}` reversal in unicode mode.
    fn try_parse_quantifier(&mut self) -> Result<Option<(u32, Option<u32>)>, ()> {
        match self.peek() {
            Some('*') => {
                self.pos += 1;
                Ok(Some((0, None)))
            }
            Some('+') => {
                self.pos += 1;
                Ok(Some((1, None)))
            }
            Some('?') => {
                self.pos += 1;
                Ok(Some((0, Some(1))))
            }
            Some('{') => self.try_parse_brace_quantifier(),
            _ => Ok(None),
        }
    }

    fn try_parse_brace_quantifier(&mut self) -> Result<Option<(u32, Option<u32>)>, ()> {
        let save = self.pos;
        self.pos += 1; // `{`
        let Some(min) = self.parse_decimal() else {
            self.pos = save;
            return Ok(None);
        };
        let max = match self.peek() {
            Some('}') => {
                self.pos += 1;
                Some(min)
            }
            Some(',') => {
                self.pos += 1;
                let max = self.parse_decimal();
                if self.peek() != Some('}') {
                    self.pos = save;
                    return Ok(None);
                }
                self.pos += 1;
                max
            }
            _ => {
                self.pos = save;
                return Ok(None);
            }
        };
        if let Some(max) = max
            && max < min
        {
            if self.unicode_mode {
                return Err(());
            }
            self.pos = save;
            return Ok(None);
        }
        Ok(Some((min, max)))
    }

    fn parse_decimal(&mut self) -> Option<u32> {
        let mut value: Option<u32> = None;
        while let Some(digit) = self.peek().and_then(|next| next.to_digit(10)) {
            value = Some(value.unwrap_or(0).saturating_mul(10).saturating_add(digit));
            self.pos += 1;
        }
        value
    }

    fn parse_atom(&mut self) -> Result<PatternNode, ()> {
        let Some(&(pos, ch)) = self.chars.get(self.pos) else {
            return Err(());
        };
        self.pos += 1;
        match ch {
            '.' => Ok(PatternNode::Dot),
            '^' => Ok(PatternNode::Anchor {
                kind: AnchorKind::Start,
                pos,
            }),
            '$' => Ok(PatternNode::Anchor {
                kind: AnchorKind::End,
                pos,
            }),
            '[' => self.parse_class(pos),
            '(' => self.parse_group(pos),
            '\\' => self.parse_escape(pos),
            _ => Ok(PatternNode::Literal { ch, pos }),
        }
    }

    fn parse_group(&mut self, start: usize) -> Result<PatternNode, ()> {
        // Runaway group nesting must not exhaust the stack: bail past the
        // cap (mirroring the Python crate's `RX_MAX_DEPTH` guard) and let
        // the `Err` degrade to "no structural findings".
        if self.group_depth >= MAX_GROUP_DEPTH {
            return Err(());
        }
        self.group_depth += 1;
        let parsed = self.parse_group_inner(start);
        self.group_depth -= 1;
        parsed
    }

    fn parse_group_inner(&mut self, start: usize) -> Result<PatternNode, ()> {
        let kind = if self.peek() == Some('?') {
            self.pos += 1;
            match self.peek() {
                Some(':') => {
                    self.pos += 1;
                    GroupKind::NonCapturing
                }
                Some('=') => {
                    self.pos += 1;
                    GroupKind::Lookahead { negated: false }
                }
                Some('!') => {
                    self.pos += 1;
                    GroupKind::Lookahead { negated: true }
                }
                Some('<') => {
                    self.pos += 1;
                    match self.peek() {
                        Some('=') => {
                            self.pos += 1;
                            GroupKind::Lookbehind { negated: false }
                        }
                        Some('!') => {
                            self.pos += 1;
                            GroupKind::Lookbehind { negated: true }
                        }
                        _ => {
                            let name = self.parse_group_name()?;
                            self.captures.push(Some(name.clone()));
                            GroupKind::Named(name)
                        }
                    }
                }
                _ => return Err(()), // unknown `(?…)` header
            }
        } else {
            self.captures.push(None);
            GroupKind::Capturing
        };
        let alternatives = self.parse_alternatives(Some(')'))?;
        Ok(PatternNode::Group {
            kind,
            alternatives,
            start,
            end: self.current_offset(),
        })
    }

    fn parse_group_name(&mut self) -> Result<String, ()> {
        let mut name = String::new();
        loop {
            match self.bump() {
                None | Some('(' | '|') => return Err(()),
                Some('>') => break,
                Some(ch) => name.push(ch),
            }
        }
        if name.is_empty() {
            return Err(());
        }
        Ok(name)
    }

    fn parse_escape(&mut self, backslash_pos: usize) -> Result<PatternNode, ()> {
        let Some(&(char_pos, ch)) = self.chars.get(self.pos) else {
            return Err(()); // trailing backslash
        };
        self.pos += 1;
        match ch {
            'd' | 'D' | 'w' | 'W' | 's' | 'S' => {
                let (negated, kind) = Self::shorthand_negated_and_kind(ch);
                Ok(PatternNode::ClassEscape {
                    negated,
                    kind,
                    pos: backslash_pos,
                })
            }
            'p' | 'P' => self.property_escape_node(backslash_pos, char_pos, ch),
            'b' => Ok(PatternNode::Anchor {
                kind: AnchorKind::WordBoundary,
                pos: backslash_pos,
            }),
            'B' => Ok(PatternNode::Anchor {
                kind: AnchorKind::NotWordBoundary,
                pos: backslash_pos,
            }),
            '1'..='9' => {
                while self.peek().is_some_and(|next| next.is_ascii_digit()) {
                    self.pos += 1;
                }
                Ok(PatternNode::BackReference { pos: backslash_pos })
            }
            'k' if self.peek() == Some('<') => {
                self.pos += 1;
                self.parse_group_name()?;
                Ok(PatternNode::BackReference { pos: backslash_pos })
            }
            _ => self.simple_escape_node(char_pos, ch),
        }
    }

    /// Negation flag and class kind for the `\d`/`\w`/`\s` family.
    fn shorthand_negated_and_kind(ch: char) -> (bool, ShorthandClass) {
        match ch {
            'D' => (true, ShorthandClass::Digit),
            'W' => (true, ShorthandClass::Word),
            'S' => (true, ShorthandClass::Space),
            'd' => (false, ShorthandClass::Digit),
            'w' => (false, ShorthandClass::Word),
            _ => (false, ShorthandClass::Space),
        }
    }

    /// Character produced by a plain control escape (`\n`, `\t`, `\0`, …);
    /// `None` for escapes that keep the escaped character itself.
    fn simple_escape_char(esc: char) -> Option<char> {
        match esc {
            'n' => Some('\n'),
            't' => Some('\t'),
            'r' => Some('\r'),
            'f' => Some('\u{000C}'),
            'v' => Some('\u{000B}'),
            '0' => Some('\0'),
            _ => None,
        }
    }

    /// `\p{…}` property escapes; a bare letter stays literal outside
    /// unicode mode.
    fn property_escape_node(
        &mut self,
        backslash_pos: usize,
        char_pos: usize,
        ch: char,
    ) -> Result<PatternNode, ()> {
        match self.peek() {
            Some('{') => {
                self.skip_property_body()?;
                Ok(PatternNode::PropertyEscape {
                    negated: ch == 'P',
                    pos: backslash_pos,
                })
            }
            None => Err(()),
            Some(_) if self.unicode_mode => Err(()),
            Some(_) => Ok(PatternNode::Literal { ch, pos: char_pos }),
        }
    }

    /// Control-character escapes, unicode-mode `\u`/`\x`/`\c`, and the
    /// identity fallback for every other escaped character.
    fn simple_escape_node(&mut self, char_pos: usize, ch: char) -> Result<PatternNode, ()> {
        if let Some(escaped) = Self::simple_escape_char(ch) {
            return Ok(PatternNode::Literal {
                ch: escaped,
                pos: char_pos,
            });
        }
        match ch {
            'u' if self.unicode_mode => Ok(PatternNode::Literal {
                ch: self.parse_unicode_escape()?,
                pos: char_pos,
            }),
            'x' if self.unicode_mode => Ok(PatternNode::Literal {
                ch: self.parse_hex_escape(2)?,
                pos: char_pos,
            }),
            'c' if self.unicode_mode => self.control_escape_node(char_pos),
            _ => Ok(PatternNode::Literal { ch, pos: char_pos }),
        }
    }

    /// `\cLetter` control character in unicode mode.
    fn control_escape_node(&mut self, char_pos: usize) -> Result<PatternNode, ()> {
        match self.peek() {
            Some(letter) if letter.is_ascii_alphabetic() => {
                self.pos += 1;
                Ok(PatternNode::Literal {
                    ch: (letter.to_ascii_uppercase() as u8 ^ 0x40) as char,
                    pos: char_pos,
                })
            }
            _ => Err(()),
        }
    }

    /// `\u{HexDigits}` or `\uHHHH` in unicode mode; `u` already consumed.
    fn parse_unicode_escape(&mut self) -> Result<char, ()> {
        if self.peek() == Some('{') {
            self.pos += 1;
            let mut value: u32 = 0;
            let mut digits = 0;
            while let Some(next) = self.peek()
                && next != '}'
            {
                let Some(nibble) = next.to_digit(16) else {
                    return Err(());
                };
                value = value.saturating_mul(16).saturating_add(nibble);
                digits += 1;
                self.pos += 1;
            }
            if digits == 0 || digits > 6 || self.bump() != Some('}') {
                return Err(());
            }
            char::from_u32(value).ok_or(())
        } else {
            self.parse_hex_escape(4)
        }
    }

    /// Exactly `count` hex digits in unicode mode; `x`/`u` already consumed.
    fn parse_hex_escape(&mut self, count: usize) -> Result<char, ()> {
        let mut value: u32 = 0;
        for _ in 0..count {
            let nibble = self.peek().and_then(|next| next.to_digit(16)).ok_or(())?;
            value = value.saturating_mul(16).saturating_add(nibble);
            self.pos += 1;
        }
        char::from_u32(value).ok_or(())
    }

    fn skip_property_body(&mut self) -> Result<(), ()> {
        self.pos += 1; // `{`
        loop {
            match self.bump() {
                None | Some('(' | '|') => return Err(()),
                Some('}') => return Ok(()),
                Some(_) => {}
            }
        }
    }

    fn parse_class(&mut self, start: usize) -> Result<PatternNode, ()> {
        let negated = if self.peek() == Some('^') {
            self.pos += 1;
            true
        } else {
            false
        };
        let mut items = Vec::new();
        loop {
            let Some(&(item_pos, ch)) = self.chars.get(self.pos) else {
                return Err(()); // unterminated class
            };
            if ch == ']' {
                self.pos += 1;
                break;
            }
            let item = self.parse_class_item(item_pos, ch)?;
            if let ClassItem::Char {
                ch: low,
                pos: low_pos,
            } = item
                && let Some(range) = self.try_parse_class_range(low, low_pos)?
            {
                items.push(range);
            } else {
                items.push(item);
            }
        }
        Ok(PatternNode::Class {
            negated,
            items,
            start,
            end: self.current_offset(),
        })
    }

    /// Extends a lone class char into `low-high` when a dash and a further
    /// single char follow; otherwise rewinds so `-` stays literal.
    fn try_parse_class_range(
        &mut self,
        low: char,
        low_pos: usize,
    ) -> Result<Option<ClassItem>, ()> {
        if self.peek() != Some('-') {
            return Ok(None);
        }
        let save = self.pos;
        self.pos += 1; // `-`
        let Some(&(high_pos, high_ch)) = self.chars.get(self.pos) else {
            self.pos = save;
            return Ok(None);
        };
        if high_ch == ']' {
            self.pos = save;
            return Ok(None);
        }
        let ClassItem::Char { ch: high, .. } = self.parse_class_item(high_pos, high_ch)? else {
            // `a-\d`: Annex B keeps the dash literal; rewind and let the
            // shorthand be parsed as its own item.
            self.pos = save;
            return Ok(None);
        };
        if high < low {
            return Err(()); // reversed range
        }
        Ok(Some(ClassItem::Range {
            low,
            high,
            start: low_pos,
        }))
    }

    fn parse_class_item(&mut self, pos: usize, ch: char) -> Result<ClassItem, ()> {
        if ch != '\\' {
            self.pos += 1;
            return Ok(ClassItem::Char { ch, pos });
        }
        self.pos += 1; // backslash
        let Some(&(char_pos, esc)) = self.chars.get(self.pos) else {
            return Err(()); // trailing backslash
        };
        self.pos += 1;
        match esc {
            'd' | 'D' | 'w' | 'W' | 's' | 'S' => {
                let (negated, kind) = Self::shorthand_negated_and_kind(esc);
                Ok(ClassItem::Shorthand { negated, kind, pos })
            }
            'p' | 'P' => self.class_property_item(pos, char_pos, esc),
            // Outside classes `\b` anchors; inside classes it is backspace.
            'b' => Ok(ClassItem::Char {
                ch: '\u{0008}',
                pos: char_pos,
            }),
            _ => self.class_mapped_item(char_pos, esc),
        }
    }

    /// `\p{…}` inside a class; a bare letter stays literal outside unicode
    /// mode.
    fn class_property_item(
        &mut self,
        pos: usize,
        char_pos: usize,
        esc: char,
    ) -> Result<ClassItem, ()> {
        match self.peek() {
            Some('{') => {
                self.skip_property_body()?;
                Ok(ClassItem::Property {
                    negated: esc == 'P',
                    pos,
                })
            }
            None => Err(()),
            Some(_) if self.unicode_mode => Err(()),
            Some(_) => Ok(ClassItem::Char {
                ch: esc,
                pos: char_pos,
            }),
        }
    }

    /// Control-character escapes and, in unicode mode, `\u`/`\x`; every
    /// other escape keeps the escaped character itself.
    fn class_mapped_item(&mut self, char_pos: usize, esc: char) -> Result<ClassItem, ()> {
        if let Some(mapped) = Self::simple_escape_char(esc) {
            return Ok(ClassItem::Char {
                ch: mapped,
                pos: char_pos,
            });
        }
        let ch = match esc {
            'u' if self.unicode_mode => self.parse_unicode_escape()?,
            'x' if self.unicode_mode => self.parse_hex_escape(2)?,
            _ => esc,
        };
        Ok(ClassItem::Char { ch, pos: char_pos })
    }
}
