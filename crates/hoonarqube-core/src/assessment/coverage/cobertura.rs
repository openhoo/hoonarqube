//! Import the Cobertura XML dialect written by Python's coverage.py.
//!
//! Only class-level lines are used. Branch observations are counts from
//! condition-coverage, never synthesized branch identities.

use std::collections::BTreeSet;

use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::{Reader, XmlVersion, escape::resolve_xml_entity};

use super::{
    MAX_MEASUREMENTS, MAX_RECORDS, MAX_XML_TEXT, ParsedCoverage, ParsedFile, ParsedLine,
    is_windows_absolute,
};

mod branch;
mod paths;
#[cfg(test)]
mod tests;

pub(super) use paths::PathIndex;

const MAX_SOURCE_ROOTS: usize = 128;
const MAX_PATH_BYTES: usize = 4096;

pub(super) fn parse(content: &str, diagnostics: &mut Vec<String>) -> ParsedCoverage {
    let mut parser = Parser::default();
    if let Err(error) = parser.read(content) {
        diagnostics.push(format!("invalid Cobertura XML: {error}"));
        parser.coverage.invalid = true;
    } else if parser.coverage.records.is_empty() {
        diagnostics.push("Cobertura contains no class records".to_owned());
        parser.coverage.incomplete = true;
    }
    parser.coverage.saw_record = parser.measured.lines != 0;
    parser.coverage
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Node {
    Coverage,
    Sources,
    Source,
    Packages,
    Package,
    Classes,
    Class,
    Methods,
    Lines,
    Line,
}

impl Node {
    fn child(parent: Option<Self>, name: &str) -> Option<Self> {
        match (parent, name) {
            (None, "coverage") => Some(Self::Coverage),
            (Some(Self::Coverage), "sources") => Some(Self::Sources),
            (Some(Self::Sources), "source") => Some(Self::Source),
            (Some(Self::Coverage), "packages") => Some(Self::Packages),
            (Some(Self::Packages), "package") => Some(Self::Package),
            (Some(Self::Package), "classes") => Some(Self::Classes),
            (Some(Self::Classes), "class") => Some(Self::Class),
            (Some(Self::Class), "methods") => Some(Self::Methods),
            (Some(Self::Class), "lines") => Some(Self::Lines),
            (Some(Self::Lines), "line") => Some(Self::Line),
            _ => None,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Totals {
    lines: u64,
    hits: u64,
    branches: u64,
    taken: u64,
}

#[derive(Default)]
struct Parser {
    coverage: ParsedCoverage,
    stack: Vec<Node>,
    expected: Option<Totals>,
    measured: Totals,
    active: Option<ParsedFile>,
    line_numbers: BTreeSet<u32>,
    source_text: String,
}

impl Parser {
    fn read(&mut self, content: &str) -> Result<(), String> {
        let mut reader = Reader::from_str(content);
        reader.config_mut().expand_empty_elements = true;
        reader.config_mut().check_comments = true;
        let mut saw_declaration = false;
        loop {
            match reader.read_event().map_err(|error| error.to_string())? {
                Event::Start(start) => self.start(&start)?,
                Event::End(_) => self.end()?,
                Event::Text(text) => self.text(text.as_ref())?,
                Event::CData(text) => self.text(text.as_ref())?,
                Event::GeneralRef(reference) => self.reference(&reference)?,
                Event::Decl(_) if self.expected.is_none() && !saw_declaration => {
                    saw_declaration = true;
                }
                Event::Comment(_) => {}
                Event::Eof => break,
                _ => return Err("unexpected declaration, DTD or processing instruction".into()),
            }
        }
        if !self.stack.is_empty() {
            return Err("truncated coverage document".into());
        }
        let expected = self
            .expected
            .as_ref()
            .ok_or("missing coverage document root")?;
        if *expected != self.measured {
            return Err(
                "coverage summary counters contradict the class line or branch records".into(),
            );
        }
        Ok(())
    }

    fn start(&mut self, start: &BytesStart<'_>) -> Result<(), String> {
        let name = start.name();
        let node = Node::child(self.stack.last().copied(), name.as_ref())
            .ok_or_else(|| format!("unexpected <{}> element", name.as_ref()))?;
        let attrs = attributes(start)?;
        match node {
            Node::Coverage if self.expected.is_some() => {
                return Err("multiple document roots".into());
            }
            Node::Coverage => self.expected = Some(totals(&attrs)?),
            Node::Class => {
                if self.coverage.records.len() == MAX_RECORDS {
                    return Err("too many class records".into());
                }
                let path = get(&attrs, "filename")
                    .filter(|path| valid_path(path))
                    .ok_or("class filename is missing or contains an invalid coverage path")?;
                self.active = Some(ParsedFile {
                    path: path.to_owned(),
                    ..ParsedFile::default()
                });
                self.line_numbers.clear();
            }
            Node::Line => self.line(&attrs)?,
            _ => {}
        }
        self.stack.push(node);
        Ok(())
    }

    fn end(&mut self) -> Result<(), String> {
        match self.stack.pop() {
            Some(Node::Source) => {
                let path = self.source_text.trim();
                if (!path.is_empty() && !valid_path(path))
                    || self.coverage.source_roots.len() == MAX_SOURCE_ROOTS
                {
                    return Err("invalid Cobertura source path or too many source roots".into());
                }
                self.coverage.source_roots.push(path.to_owned());
                self.source_text.clear();
            }
            Some(Node::Class) => self
                .coverage
                .records
                .push(self.active.take().ok_or("missing class")?),
            None => return Err("closing element outside coverage document".into()),
            _ => {}
        }
        Ok(())
    }

    fn text(&mut self, text: &str) -> Result<(), String> {
        if self.stack.last() == Some(&Node::Source) {
            if self.source_text.len() + text.len() > MAX_PATH_BYTES {
                return Err("Cobertura source path exceeds the importer limit".into());
            }
            self.source_text.push_str(text);
        } else if !text.trim().is_empty() {
            return Err("unexpected text outside a Cobertura source path".into());
        }
        Ok(())
    }

    fn reference(&mut self, reference: &BytesRef<'_>) -> Result<(), String> {
        if self.stack.last() != Some(&Node::Source) {
            return Err("unexpected entity reference".into());
        }
        if let Some(value) = reference
            .resolve_char_ref()
            .map_err(|error| error.to_string())?
        {
            self.text(value.encode_utf8(&mut [0; 4]))
        } else if let Some(value) = resolve_xml_entity(reference.as_ref()) {
            self.text(value)
        } else {
            Err("custom XML entities are not supported".into())
        }
    }

    fn line(&mut self, attrs: &Attributes<'_>) -> Result<(), String> {
        let line = number(attrs, "number")
            .and_then(|number| u32::try_from(number).ok())
            .filter(|number| *number > 0)
            .ok_or("line number must be a positive integer")?;
        let covered = number(attrs, "hits").ok_or("line hits must be a nonnegative integer")? > 0;
        let class = self.active.as_mut().ok_or("class line without a class")?;
        let counts = branch::counts(
            get(attrs, "branch"),
            get(attrs, "condition-coverage"),
            get(attrs, "missing-branches"),
        )
        .map_err(|error| format!("{error} at line {line} for '{}'", class.path))?;
        if !self.line_numbers.insert(line) {
            return Err(format!("duplicate line {line} for '{}'", class.path));
        }
        self.measured.lines += 1;
        self.measured.hits += u64::from(covered);
        if let Some(counts) = &counts {
            self.measured.branches += counts.eligible;
            self.measured.taken += counts.covered;
        }
        if self.measured.lines + self.measured.branches > MAX_MEASUREMENTS as u64 {
            return Err("too many line and branch measurements".into());
        }
        class.lines.push(ParsedLine {
            line,
            covered,
            checksum: None,
            branch_counts: counts,
        });
        Ok(())
    }
}

type Attributes<'a> = Vec<(&'a str, String)>;

fn attributes<'a>(start: &'a BytesStart<'_>) -> Result<Attributes<'a>, &'static str> {
    start
        .attributes()
        .map(|attribute| {
            let attribute = attribute.map_err(|_| "malformed XML attribute")?;
            if attribute.value.len() > MAX_XML_TEXT {
                return Err("XML attribute exceeds the importer limit");
            }
            let key = attribute.key.into_inner();
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|_| "invalid XML attribute value")?;
            Ok((key, value.into_owned()))
        })
        .collect()
}

fn get<'a>(attrs: &'a Attributes<'_>, key: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find_map(|(name, value)| (*name == key).then_some(value.as_str()))
}

fn number(attrs: &Attributes<'_>, key: &str) -> Option<u64> {
    super::parse_nonnegative_u64(get(attrs, key)?)
}

fn totals(attrs: &Attributes<'_>) -> Result<Totals, &'static str> {
    Ok(Totals {
        lines: number(attrs, "lines-valid").ok_or("missing or invalid lines-valid counter")?,
        hits: number(attrs, "lines-covered").ok_or("missing or invalid lines-covered counter")?,
        branches: number(attrs, "branches-valid")
            .ok_or("missing or invalid branches-valid counter")?,
        taken: number(attrs, "branches-covered")
            .ok_or("missing or invalid branches-covered counter")?,
    })
}

fn valid_path(path: &str) -> bool {
    let text = path.replace('\\', "/");
    !text.trim().is_empty()
        && text.len() <= MAX_PATH_BYTES
        && !text.chars().any(char::is_control)
        && !text.contains("://")
        && (text.as_bytes().get(1) != Some(&b':') || is_windows_absolute(&text))
        && !text.split('/').any(|component| component == "..")
}
