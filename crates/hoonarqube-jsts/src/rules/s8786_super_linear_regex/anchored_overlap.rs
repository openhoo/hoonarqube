//! Sibling repetition detection for anchored, end-constrained alternatives.

use super::{CharClass, RegexFlags, atom_class, first_set};
use crate::engine::pattern_parser::{AnchorKind, ClassItem, PatternNode, node_can_match_empty};

/// A start anchor prevents restarting a search but does not prevent two
/// sequential repetitions from consuming different portions of the same run.
pub(super) fn anchored_repeats_overlap(
    alternatives: &[Vec<PatternNode>],
    flags: RegexFlags,
) -> bool {
    let [sequence] = alternatives else {
        return false;
    };
    if !matches!(
        sequence.first(),
        Some(PatternNode::Anchor {
            kind: AnchorKind::Start,
            ..
        })
    ) || !matches!(
        sequence.last(),
        Some(PatternNode::Anchor {
            kind: AnchorKind::End,
            ..
        })
    ) {
        return false;
    }
    let mut flat = Vec::new();
    flatten_single_alternatives(&sequence[1..sequence.len() - 1], &mut flat);
    // Work backwards. `tail` contains the possible leading characters of
    // the skippable suffix after the candidate pair; stop at an unknown atom.
    let valid_prefix = flat
        .iter()
        .take_while(|node| prefix_consumable(node, flags))
        .count();
    let mut tail = CharClass::empty();
    for (right_index, right) in flat.iter().enumerate().rev() {
        if let Some(right_chars) = unbounded_atom(right, flags)
            && let Some((left_index, left_chars)) = previous_repeat(&flat[..right_index], flags)
            && !left_chars.clone().intersect(right_chars.clone()).is_empty()
            && left_index <= valid_prefix
        {
            let mut consumable = left_chars.union(right_chars).union(tail.clone());
            for separator in &flat[left_index + 1..right_index] {
                if let Some(chars) = first_set(separator, flags) {
                    consumable = consumable.union(chars);
                }
            }
            // A non-newline character rejected by both repeated atoms and the
            // entire suffix makes the end anchor reject all divisions of a run.
            let printable = CharClass::Set(vec![(0x20, 0x7e)]);
            if !printable.subset_of(&consumable) {
                return true;
            }
        }
        if !node_can_match_empty(right) {
            break;
        }
        let Some(chars) = first_set(right, flags) else {
            break;
        };
        tail = tail.union(chars);
    }
    false
}

fn flatten_single_alternatives<'a>(sequence: &'a [PatternNode], out: &mut Vec<&'a PatternNode>) {
    for node in sequence {
        if let PatternNode::Group {
            kind, alternatives, ..
        } = node
            && !kind.is_lookaround()
            && let [alternative] = alternatives.as_slice()
        {
            flatten_single_alternatives(alternative, out);
        } else {
            out.push(node);
        }
    }
}

fn prefix_consumable(node: &PatternNode, flags: RegexFlags) -> bool {
    match node {
        PatternNode::Quantified {
            min, node: atom, ..
        } => *min == 0 || single_atom(atom, flags).is_some_and(|set| !set.is_empty()),
        _ => single_atom(node, flags).is_some_and(|set| !set.is_empty()),
    }
}

fn previous_repeat(nodes: &[&PatternNode], flags: RegexFlags) -> Option<(usize, CharClass)> {
    for (index, node) in nodes.iter().enumerate().rev() {
        if let Some(set) = unbounded_atom(node, flags) {
            return Some((index, set));
        }
        // Only simple optional separators can be skipped unconditionally.
        if !matches!(node, PatternNode::Quantified { min: 0, max: Some(_), node: inner, .. } if single_atom(inner, flags).is_some())
        {
            break;
        }
    }
    None
}

fn unbounded_atom(node: &PatternNode, flags: RegexFlags) -> Option<CharClass> {
    let PatternNode::Quantified {
        max: None,
        node: atom,
        ..
    } = node
    else {
        return None;
    };
    single_atom(atom, flags)
}

fn single_atom(node: &PatternNode, flags: RegexFlags) -> Option<CharClass> {
    // Other set calculations approximate unresolved escapes by the whole
    // character set; an approximation cannot establish a shared character.
    match node {
        PatternNode::Literal { .. } | PatternNode::ClassEscape { .. } => atom_class(node, flags),
        PatternNode::Class { items, .. }
            if !items
                .iter()
                .any(|item| matches!(item, ClassItem::Property { .. })) =>
        {
            atom_class(node, flags)
        }
        _ => None,
    }
}
