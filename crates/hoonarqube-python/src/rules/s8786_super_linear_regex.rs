use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;

use crate::engine::file_context::FileContext;
use crate::engine::rx::{
    RxAtom, RxGroupKind, RxItem, RxNode, RxSeq, collect_regex_sites, parse_regex,
    rx_atom_first_set, rx_is_unbounded_repeat, rx_sets_intersect,
};
use crate::support::issue_at;

const RULE_KEY: &str = "python:S8786";
const MESSAGE: &str = "Simplify this regular expression to reduce its runtime, as it has super-linear performance due to backtracking.";

/// python:S8786 — a literal `re` pattern with two unbounded, non-nested
/// quantifiers whose match sets can overlap makes the engine re-scan the
/// trailing run for every retraction of the leading one: super-linear
/// (non-exponential) backtracking. Patterns that fail to parse, dynamic
/// patterns, `re.VERBOSE` patterns (free spacing and comments change the
/// token stream; the pinned campaign reports none), nested-quantifier
/// shapes (the exponential concern of the separate vulnerability rule),
/// and disjoint character sets stay silent. The pattern literal anchors
/// the finding.
pub(crate) fn check_s8786_super_linear_regex(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for site in collect_regex_sites(file_ctx.module_body, source) {
        if site.verbose {
            continue;
        }
        let Some(units) = &site.pattern else {
            continue;
        };
        let Ok(parsed) = parse_regex(units) else {
            continue;
        };
        if has_super_linear_pair(&parsed.root) {
            issues.push(issue_at(
                RULE_KEY,
                MESSAGE,
                site.pattern_range,
                index,
                source,
            ));
        }
    }
    issues
}

fn has_super_linear_pair(node: &RxNode) -> bool {
    match node {
        RxNode::Seq(seq) => branch_has_super_linear_pair(seq),
        RxNode::Alternation(branches) => branches.iter().any(branch_has_super_linear_pair),
    }
}

/// Two sibling unbounded quantifiers with intersecting match sets in one
/// branch. Quantified groups are opaque, so nested quantifiers never
/// compare as siblings; lookaround, atomic, flag-scope, and conditional
/// groups isolate their bodies the same way.
fn branch_has_super_linear_pair(seq: &RxSeq) -> bool {
    let mut items = Vec::new();
    collect_branch_items(seq, &mut items);
    for (index, later) in items.iter().enumerate() {
        if !rx_is_unbounded_repeat(later) {
            continue;
        }
        let Some(later_set) = rx_atom_first_set(&later.atom) else {
            continue;
        };
        for earlier in &items[..index] {
            if !rx_is_unbounded_repeat(earlier) {
                continue;
            }
            let Some(earlier_set) = rx_atom_first_set(&earlier.atom) else {
                continue;
            };
            if rx_sets_intersect(&earlier_set, &later_set) {
                return true;
            }
        }
    }
    false
}

/// Branch items with transparent (unquantified capturing or
/// non-capturing) group bodies flattened in place.
fn collect_branch_items<'a>(seq: &'a RxSeq, items: &mut Vec<&'a RxItem>) {
    for item in &seq.items {
        if item.quant.is_none()
            && let RxAtom::Group(group) = &item.atom
            && group_is_transparent(&group.kind)
        {
            flatten_node(&group.body, items);
        }
        items.push(item);
    }
}

fn flatten_node<'a>(node: &'a RxNode, items: &mut Vec<&'a RxItem>) {
    match node {
        RxNode::Seq(seq) => collect_branch_items(seq, items),
        RxNode::Alternation(branches) => {
            for branch in branches {
                collect_branch_items(branch, items);
            }
        }
    }
}

fn group_is_transparent(kind: &RxGroupKind) -> bool {
    matches!(kind, RxGroupKind::Capture | RxGroupKind::NonCapture)
}
