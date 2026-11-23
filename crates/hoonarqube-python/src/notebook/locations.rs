use super::{Finding, MAX_FRAGMENTS, MAX_PROJECTED_BYTES, MESSAGE, RULE};
use hoonarqube_ir::{Pos, Range};
use ruff_text_size::{TextRange, TextSize};
use serde_json::value::RawValue;

struct Fragment {
    cell: usize,
    start: usize,
    end: usize,
    raw_start: usize,
}

#[derive(Default)]
pub(super) struct Projection {
    pub text: String,
    pub cells: Vec<TextRange>,
    fragments: Vec<Fragment>,
    source_strings: usize,
}

impl Projection {
    pub fn push(&mut self, raw: &str, cell: usize, source: &RawValue) -> Result<(), String> {
        let start = self.text.len();
        if source.get().starts_with('[') {
            let items: super::bounded::Bounded<&RawValue, MAX_FRAGMENTS> =
                serde_json::from_str(source.get()).map_err(|e| e.to_string())?;
            for item in items.0 {
                self.push_fragment(raw, cell, item)?;
            }
        } else {
            self.push_fragment(raw, cell, source)?;
        }
        // A cell magic can switch languages or consume the entire remaining
        // cell as data. Its body must never be analyzed as ordinary Python.
        if self.text[start..].trim_start().starts_with("%%") {
            return Err(format!("unsupported cell magic at index {cell}"));
        }
        let end = self.text.len();
        if end >= MAX_PROJECTED_BYTES {
            return Err("notebook projection exceeds 1 MiB".into());
        }
        self.cells.push(TextRange::new(
            TextSize::try_from(start).map_err(|e| e.to_string())?,
            TextSize::try_from(end).map_err(|e| e.to_string())?,
        ));
        self.text.push('\n');
        Ok(())
    }

    fn push_fragment(&mut self, raw: &str, cell: usize, token: &RawValue) -> Result<(), String> {
        self.source_strings += 1;
        let literal = token.get();
        let decoded: String = serde_json::from_str(literal).map_err(|e| e.to_string())?;
        let start = self.text.len();
        if start + decoded.len() + 1 > MAX_PROJECTED_BYTES || self.source_strings > MAX_FRAGMENTS {
            return Err("notebook projection exceeds 1 MiB or 65536 source fragments".into());
        }
        if !decoded.is_empty() {
            // RawValue borrows this precise JSON token from the input; identical
            // values in metadata, outputs or another cell cannot redirect it.
            let raw_start = literal.as_ptr() as usize - raw.as_ptr() as usize + 1;
            self.text.push_str(&decoded);
            self.fragments.push(Fragment {
                cell,
                start,
                end: self.text.len(),
                raw_start,
            });
        }
        Ok(())
    }

    pub fn findings(&self, raw: &str, mut ranges: Vec<TextRange>) -> Result<Vec<Finding>, String> {
        // Consume the projected and physical source once, including on compact
        // notebooks with many findings on the same physical JSON line.
        ranges.sort_unstable_by_key(|r| r.start());
        let mut physical = Physical::default();
        let mut current = None;
        let mut decoded = 0;
        let mut encoded = 0;
        let mut findings = Vec::with_capacity(ranges.len());
        for r in ranges {
            let start = r.start().to_usize();
            let end = r.end().to_usize();
            let index = self.fragments.partition_point(|f| f.end <= start);
            let f = self
                .fragments
                .get(index)
                .filter(|f| f.start <= start && end <= f.end)
                .ok_or("primary range spans multiple JSON strings or falls outside a code cell")?;
            if current != Some(index) {
                current = Some(index);
                decoded = f.start;
                encoded = f.raw_start;
            }
            let mut position = |to| -> Result<Pos, String> {
                let part = self
                    .text
                    .get(decoded..to)
                    .ok_or("non-monotonic primary locations")?;
                for c in part.chars() {
                    // serde_json has already validated the string and decoded its
                    // surrogate pairs. Count the original spelling of this scalar.
                    encoded += match raw.as_bytes().get(encoded..encoded + 2) {
                        Some([b'\\', b'u']) => {
                            if c.len_utf16() == 2 {
                                12
                            } else {
                                6
                            }
                        }
                        Some([b'\\', _]) => 2,
                        _ => c.len_utf8(),
                    };
                }
                decoded = to;
                physical.advance(raw, encoded)
            };
            let range = Range {
                start: position(start)?,
                end: position(end)?,
            };
            findings.push(Finding {
                rule_key: RULE,
                message: MESSAGE,
                cell_index: f.cell,
                range,
            });
        }
        Ok(findings)
    }
}

struct Physical {
    offset: usize,
    pos: Pos,
}
impl Default for Physical {
    fn default() -> Self {
        Self {
            offset: 0,
            pos: Pos { line: 1, column: 0 },
        }
    }
}
impl Physical {
    fn advance(&mut self, raw: &str, offset: usize) -> Result<Pos, String> {
        let part = raw
            .get(self.offset..offset)
            .ok_or("invalid physical notebook offset")?;
        let mut chars = part.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\r' || c == '\n' {
                if c == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
                self.pos.line += 1;
                self.pos.column = 0;
            } else {
                self.pos.column += if c.len_utf16() == 2 { 2 } else { 1 };
            }
        }
        self.offset = offset;
        Ok(self.pos)
    }
}
