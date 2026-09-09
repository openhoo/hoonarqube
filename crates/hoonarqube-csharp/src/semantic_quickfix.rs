//! Compiler-backed C# quick-fix facts and their safe conversion to the IR.
//!
//! The Roslyn helper owns finding recognition and edit construction.  This
//! module deliberately does not infer a fix from the issue text or from a
//! same-shaped syntax tree: a fact is usable only when the helper supplied an
//! exact byte span and every edit can be represented in the one source passed
//! to the ordinary quick-fix pipeline.

use std::path::PathBuf;

use hoonarqube_ir::{Pos, Range, TextEdit};
use serde::{Deserialize, Serialize};

use crate::quickfix::{SemanticPlan, canonical_action_id};

/// One compiler-proven quick-fix finding.  `start_byte` and `end_byte` are
/// half-open UTF-8 offsets local to `source_path`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerQuickFixFact {
    pub source_path: PathBuf,
    pub rule_key: String,
    pub start_byte: usize,
    pub end_byte: usize,
    #[serde(default)]
    pub actions: Vec<CompilerQuickFixAction>,
}

/// One distinct Roslyn code-fix action for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerQuickFixAction {
    pub id: String,
    pub message: String,
    #[serde(default)]
    pub edits: Vec<CompilerQuickFixEdit>,
}

/// One replacement in the source identified by its enclosing fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerQuickFixEdit {
    pub start_byte: usize,
    pub end_byte: usize,
    pub replacement: String,
}

/// Returns true when the helper emitted a fact for the exact issue span.
///
/// The caller must first validate that the project context is complete and that
/// `source` is the unchanged snapshot loaded by that context.
#[must_use]
pub(crate) fn proves(
    facts: &[CompilerQuickFixFact],
    key: &str,
    start: usize,
    end: usize,
    source: &str,
) -> bool {
    facts.iter().any(|fact| {
        fact.rule_key == key
            && fact.start_byte == start
            && fact.end_byte == end
            && valid_span(source, fact.start_byte, fact.end_byte)
    })
}

/// Converts all actions attached to the exact fact into the existing narrow
/// `quickfix::SemanticPlan` hook.  Unknown IDs, malformed edits, and edits
/// that overlap after conversion are rejected rather than silently guessed.
#[must_use]
pub(crate) fn plans(
    facts: &[CompilerQuickFixFact],
    key: &str,
    start: usize,
    end: usize,
    source: &str,
) -> Vec<SemanticPlan> {
    let Some(fact) = facts.iter().find(|fact| {
        fact.rule_key == key
            && fact.start_byte == start
            && fact.end_byte == end
            && valid_span(source, fact.start_byte, fact.end_byte)
    }) else {
        return Vec::new();
    };

    fact.actions
        .iter()
        .filter_map(|action| convert_action(action, source))
        .collect()
}

fn convert_action(action: &CompilerQuickFixAction, source: &str) -> Option<SemanticPlan> {
    let id = canonical_action_id(&action.id)?;
    if action.edits.is_empty() {
        return None;
    }

    let mut edits = Vec::with_capacity(action.edits.len());
    for edit in &action.edits {
        if !valid_span(source, edit.start_byte, edit.end_byte) {
            return None;
        }
        let start = byte_to_pos(source, edit.start_byte)?;
        let end = byte_to_pos(source, edit.end_byte)?;
        edits.push(TextEdit {
            range: Range { start, end },
            replacement: edit.replacement.clone(),
        });
    }
    edits.sort_by_key(|edit| (edit.range.start, edit.range.end));
    if edits.windows(2).any(|pair| pair[0].overlaps(&pair[1])) {
        return None;
    }

    Some(SemanticPlan {
        id,
        message: action.message.clone(),
        edits,
    })
}

fn valid_span(source: &str, start: usize, end: usize) -> bool {
    start <= end
        && end <= source.len()
        && source.is_char_boundary(start)
        && source.is_char_boundary(end)
}

fn byte_to_pos(source: &str, byte: usize) -> Option<Pos> {
    if !valid_span(source, byte, byte) {
        return None;
    }
    let prefix = &source[..byte];
    let line = prefix.bytes().filter(|&value| value == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current_line)| current_line)
        .chars()
        .count();
    Some(Pos {
        line: u32::try_from(line).ok()?,
        column: u32::try_from(column).ok()?,
    })
}
