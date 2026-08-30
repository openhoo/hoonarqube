use super::MAX_GROUP_DEPTH;

/// Whether a `/` at this point starts a regex literal instead of a division.
pub(crate) fn regex_can_start(prev: Option<char>, word: &str) -> bool {
    match prev {
        None => true,
        Some(c) => {
            matches!(
                c,
                '(' | ','
                    | '='
                    | ':'
                    | '['
                    | '!'
                    | '&'
                    | '|'
                    | '?'
                    | '{'
                    | '}'
                    | ';'
                    | '+'
                    | '-'
                    | '*'
                    | '%'
                    | '~'
                    | '^'
                    | '<'
                    | '>'
            ) || matches!(
                word,
                "return"
                    | "typeof"
                    | "case"
                    | "in"
                    | "of"
                    | "new"
                    | "delete"
                    | "void"
                    | "instanceof"
                    | "do"
                    | "else"
                    | "yield"
                    | "await"
            )
        }
    }
}

/// Skips a regex literal starting at `chars[i - 1] == '/'`; returns the index
/// of the closing `/` (or the line end on unterminated regexes).
pub(crate) fn skip_regex_literal(chars: &[char], mut i: usize) -> usize {
    while i < chars.len() {
        if chars[i] == '\\' {
            i += 2;
            continue;
        }
        if chars[i] == '[' {
            // Character class: `/` inside is literal.
            i += 1;
            while i < chars.len() && chars[i] != ']' {
                i += if chars[i] == '\\' { 2 } else { 1 };
            }
            i += 1;
            continue;
        }
        if chars[i] == '/' || chars[i] == '\n' {
            break;
        }
        i += 1;
    }
    i
}

/// Minimal backtracking regex matcher for catalog string parameters
/// (`S139` `pattern`, `S1451` regular-expression header formats, `S6418`
/// `secretWords`). Supported: literals, `.`, `[…]` classes with ranges and
/// negation, `\d \D \w \W \s \S \t \n \r \\` escapes, `(…)`/`(?:…)` groups,
/// alternation, `* + ? {m} {m,} {m,n}` quantifiers, and `^`/`$` anchors
/// bound to the whole subject. Patterns using anything else fail to compile
/// and match nothing (tolerant, never panics); so do patterns whose group
/// nesting runs past [`MAX_GROUP_DEPTH`].

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RegexNode {
    Char(char),
    /// `.`: any character except `\n`.
    AnyChar,
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
    StartAnchor,
    EndAnchor,
    Group(Vec<Vec<RegexNode>>),
    Repeat {
        node: Box<RegexNode>,
        min: usize,
        max: Option<usize>,
    },
}

pub(crate) const CLASS_DIGIT: [(char, char); 1] = [('0', '9')];

pub(crate) const CLASS_WORD: [(char, char); 4] = [('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')];

const MAX_MATCHER_PATTERN_NODES: usize = 512;
const MAX_REPETITION_STATES: usize = 100_000;

pub(crate) fn regex_search(pattern: &str, subject: &str) -> bool {
    let Some(alternatives) = parse_regex(pattern) else {
        return false;
    };
    regex_search_parsed(&alternatives, subject)
}

/// [`regex_search`] over an already parsed pattern; hot callers matching
/// many subjects against fixed patterns parse once instead of per call.
/// An empty `alternatives` slice matches nothing, mirroring a failed parse.
pub(crate) fn regex_search_parsed(alternatives: &[Vec<RegexNode>], subject: &str) -> bool {
    let chars: Vec<char> = subject.chars().collect();
    (0..=chars.len()).any(|start| match_alternatives(alternatives, &chars, start, &mut |_| true))
}

/// Matches `subject` only where the match starts at offset zero.
pub(crate) fn regex_prefix_match(pattern: &str, subject: &str) -> bool {
    let Some(alternatives) = parse_regex(pattern) else {
        return false;
    };
    let chars: Vec<char> = subject.chars().collect();
    match_alternatives(&alternatives, &chars, 0, &mut |_| true)
}

pub(crate) fn match_alternatives(
    alternatives: &[Vec<RegexNode>],
    text: &[char],
    pos: usize,
    tail: &mut dyn FnMut(usize) -> bool,
) -> bool {
    alternatives
        .iter()
        .any(|sequence| match_sequence(sequence, text, pos, tail))
}

pub(crate) fn match_sequence(
    nodes: &[RegexNode],
    text: &[char],
    pos: usize,
    tail: &mut dyn FnMut(usize) -> bool,
) -> bool {
    let Some((first, rest)) = nodes.split_first() else {
        return tail(pos);
    };
    match_node(first, text, pos, &mut |next| {
        match_sequence(rest, text, next, tail)
    })
}

pub(crate) fn match_node(
    node: &RegexNode,
    text: &[char],
    pos: usize,
    tail: &mut dyn FnMut(usize) -> bool,
) -> bool {
    match node {
        RegexNode::Char(expected) => text.get(pos) == Some(expected) && tail(pos + 1),
        RegexNode::AnyChar => pos < text.len() && text[pos] != '\n' && tail(pos + 1),
        RegexNode::Class { negated, ranges } => {
            let Some(c) = text.get(pos) else {
                return false;
            };
            let hit = ranges.iter().any(|(low, high)| low <= c && c <= high);
            (hit != *negated) && tail(pos + 1)
        }
        RegexNode::StartAnchor => pos == 0 && tail(pos),
        RegexNode::EndAnchor => pos == text.len() && tail(pos),
        RegexNode::Group(alternatives) => match_alternatives(alternatives, text, pos, tail),
        RegexNode::Repeat { node, min, max } => match_repeat(node, *min, *max, 0, text, pos, tail),
    }
}

pub(crate) fn match_repeat(
    node: &RegexNode,
    min: usize,
    max: Option<usize>,
    count: usize,
    text: &[char],
    pos: usize,
    tail: &mut dyn FnMut(usize) -> bool,
) -> bool {
    // Keep repetition over long subjects off the call stack. Each frontier
    // contains the distinct positions reachable after exactly N repeats;
    // trying frontiers in reverse preserves greedy boolean semantics.
    let remaining = text.len().saturating_sub(pos);
    let limit = max.unwrap_or(remaining).min(remaining);
    let mut levels = vec![vec![pos]];
    let mut work = 0_usize;
    while count + levels.len() - 1 < limit {
        let mut next_level = Vec::new();
        let mut exhausted = false;
        let Some(current_level) = levels.last() else {
            return false;
        };
        for &current in current_level {
            match_node(node, text, current, &mut |next| {
                work += 1;
                if work > MAX_REPETITION_STATES {
                    exhausted = true;
                    return true;
                }
                if next != current {
                    next_level.push(next);
                }
                false
            });
            if exhausted {
                return false;
            }
        }
        next_level.sort_unstable();
        next_level.dedup();
        if next_level.is_empty() {
            break;
        }
        levels.push(next_level);
    }
    levels
        .iter()
        .enumerate()
        .rev()
        .any(|(level, positions)| count + level >= min && positions.iter().copied().any(&mut *tail))
}

pub(crate) fn parse_regex(pattern: &str) -> Option<Vec<Vec<RegexNode>>> {
    let mut parser = RegexParser {
        chars: pattern.chars().collect(),
        pos: 0,
        depth: 0,
        nodes: 0,
    };
    let alternatives = parser.parse_group_body()?;
    parser.expect_end()?;
    Some(alternatives)
}

pub(crate) struct RegexParser {
    pub(crate) chars: Vec<char>,
    pub(crate) pos: usize,
    /// Current `(` nesting level; bounded by [`MAX_GROUP_DEPTH`].
    pub(crate) depth: u32,
    pub(crate) nodes: usize,
}

impl RegexParser {
    pub(crate) fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    pub(crate) fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    pub(crate) fn eat(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    pub(crate) fn expect_end(&self) -> Option<()> {
        (self.pos == self.chars.len()).then_some(())
    }

    /// Alternatives up to an unmatched closing parenthesis. Group nesting
    /// beyond [`MAX_GROUP_DEPTH`] compiles to nothing instead of risking
    /// stack exhaustion on runaway input.
    pub(crate) fn parse_group_body(&mut self) -> Option<Vec<Vec<RegexNode>>> {
        if self.depth >= MAX_GROUP_DEPTH {
            return None;
        }
        self.depth += 1;
        let parsed = self.parse_group_body_inner();
        self.depth -= 1;
        parsed
    }

    fn parse_group_body_inner(&mut self) -> Option<Vec<Vec<RegexNode>>> {
        let mut alternatives = vec![self.parse_sequence()?];
        while self.eat('|') {
            alternatives.push(self.parse_sequence()?);
        }
        Some(alternatives)
    }

    pub(crate) fn parse_sequence(&mut self) -> Option<Vec<RegexNode>> {
        let mut nodes = Vec::new();
        while let Some(c) = self.peek()
            && c != '|'
            && c != ')'
        {
            nodes.push(self.parse_atom_quantified()?);
        }
        Some(nodes)
    }

    pub(crate) fn parse_atom_quantified(&mut self) -> Option<RegexNode> {
        let atom = self.parse_atom()?;
        let (min, max) = match self.peek() {
            Some('*') => {
                self.pos += 1;
                (0, None)
            }
            Some('+') => {
                self.pos += 1;
                (1, None)
            }
            Some('?') => {
                self.pos += 1;
                (0, Some(1))
            }
            Some('{') => self.parse_counted_range()?,
            _ => return Some(atom),
        };
        Some(RegexNode::Repeat {
            node: Box::new(atom),
            min,
            max,
        })
    }

    /// `{m}`, `{m,}` or `{m,n}` (the opening brace is unconsumed).
    pub(crate) fn parse_counted_range(&mut self) -> Option<(usize, Option<usize>)> {
        let saved = self.pos;
        self.pos += 1; // consume `{`
        let minimum = self.parse_number()?;
        let maximum = if self.eat(',') {
            if self.peek() == Some('}') {
                None
            } else {
                Some(self.parse_number()?)
            }
        } else {
            Some(minimum)
        };
        if !self.eat('}') || maximum.is_some_and(|max| max < minimum) {
            self.pos = saved;
            return None;
        }
        Some((minimum, maximum))
    }

    pub(crate) fn parse_number(&mut self) -> Option<usize> {
        let digits = self.chars[self.pos..]
            .iter()
            .copied()
            .take_while(char::is_ascii_digit)
            .collect::<String>();
        if digits.is_empty() {
            return None;
        }
        self.pos += digits.len();
        digits.parse().ok()
    }

    pub(crate) fn parse_atom(&mut self) -> Option<RegexNode> {
        self.nodes += 1;
        if self.nodes > MAX_MATCHER_PATTERN_NODES {
            return None;
        }
        match self.bump()? {
            '(' => {
                // A `(?:` head opens a plain non-capturing group; captures are
                // not tracked by this matcher, so it parses exactly like `(`.
                if self.peek() == Some('?') && self.chars.get(self.pos + 1) == Some(&':') {
                    self.pos += 2;
                }
                let alternatives = self.parse_group_body()?;
                if !self.eat(')') {
                    return None;
                }
                Some(RegexNode::Group(alternatives))
            }
            '[' => self.parse_class(),
            '.' => Some(RegexNode::AnyChar),
            '^' => Some(RegexNode::StartAnchor),
            '$' => Some(RegexNode::EndAnchor),
            '\\' => self.parse_escape(),
            '*' | '+' | '?' => None,
            literal => Some(RegexNode::Char(literal)),
        }
    }

    pub(crate) fn parse_class(&mut self) -> Option<RegexNode> {
        let negated = self.eat('^');
        let mut ranges = Vec::new();
        // A `]` directly after the (optional) `^` is a literal.
        if self.peek() == Some(']') {
            ranges.push((']', ']'));
            self.pos += 1;
        }
        loop {
            let first = match self.bump()? {
                ']' => break,
                '\\' => self.escape_ranges()?,
                literal => vec![(literal, literal)],
            };
            if first.len() == 1
                && first[0].0 == first[0].1
                && self.peek() == Some('-')
                && self
                    .chars
                    .get(self.pos + 1)
                    .is_some_and(|&next| next != ']')
            {
                self.pos += 1; // consume `-`
                let upper = match self.bump()? {
                    '\\' => self.escape_ranges()?.pop()?.0,
                    upper => upper,
                };
                let lower = first[0].0;
                if upper < lower {
                    return None;
                }
                ranges.push((lower, upper));
            } else {
                ranges.extend(first);
            }
        }
        Some(RegexNode::Class { negated, ranges })
    }

    /// One escape inside or outside a class as a range list.
    pub(crate) fn escape_ranges(&mut self) -> Option<Vec<(char, char)>> {
        match self.bump()? {
            'd' => Some(CLASS_DIGIT.to_vec()),
            // Negated shorthand inside classes (`[\D]`) is unsupported;
            // such patterns compile to nothing instead.
            'D' | 'W' => None,
            'w' => Some(CLASS_WORD.to_vec()),
            's' => Some(vec![(' ', ' '), ('\t', '\t'), ('\n', '\r')]),
            't' => Some(vec![('\t', '\t')]),
            'n' => Some(vec![('\n', '\n')]),
            'r' => Some(vec![('\r', '\r')]),
            escaped => Some(vec![(escaped, escaped)]),
        }
    }

    pub(crate) fn parse_escape(&mut self) -> Option<RegexNode> {
        match self.bump()? {
            'd' => Some(RegexNode::Class {
                negated: false,
                ranges: CLASS_DIGIT.to_vec(),
            }),
            'D' => Some(RegexNode::Class {
                negated: true,
                ranges: CLASS_DIGIT.to_vec(),
            }),
            'w' => Some(RegexNode::Class {
                negated: false,
                ranges: CLASS_WORD.to_vec(),
            }),
            'W' => Some(RegexNode::Class {
                negated: true,
                ranges: CLASS_WORD.to_vec(),
            }),
            's' => Some(RegexNode::Class {
                negated: false,
                ranges: vec![(' ', ' '), ('\t', '\t'), ('\n', '\r')],
            }),
            'S' => Some(RegexNode::Class {
                negated: true,
                ranges: vec![(' ', ' '), ('\t', '\t'), ('\n', '\r')],
            }),
            't' => Some(RegexNode::Char('\t')),
            'n' => Some(RegexNode::Char('\n')),
            'r' => Some(RegexNode::Char('\r')),
            escaped => Some(RegexNode::Char(escaped)),
        }
    }
}
