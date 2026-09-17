use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;

use crate::engine::file_context::FileContext;
use crate::engine::rx::{
    RxAtom, RxGroupKind, RxItem, RxMatchType, RxNode, RxSeq, RxSet, collect_regex_sites,
    parse_regex, rx_atom_first_set, rx_atom_nullable, rx_atom_zero_width, rx_is_unbounded_repeat,
    rx_sets_intersect,
};
use crate::support::issue_at;

const RULE_KEY: &str = "python:S8786";
const MESSAGE: &str = "Simplify this regular expression to reduce its runtime, as it has super-linear performance due to backtracking.";

/// python:S8786 — a literal `re` pattern with two unbounded, non-nested
/// quantifiers whose match sets can overlap makes the engine re-scan the
/// trailing run for every retraction of the leading one: super-linear
/// (non-exponential) backtracking.
///
/// Mirrors Sonar's `RedosFinder` overlapping-repetitions check (the only
/// `ALWAYS_QUADRATIC` source this rule reports): a repetition is "active"
/// when it is open-ended, non-possessive, and both the repetition and its
/// continuation can fail. `canFail` runs in "free end" mode when the site
/// is not a full match and the state is not anchored at the end; there a
/// state cannot fail iff it can reach the end of the regex without
/// consuming input. A match-all repetition (`.*`, `[^\s\S]*`, …) always
/// runs in free-end mode. Pairs additionally require forward reachability
/// plus the three intersection conditions on the elements and the gap
/// between them, and a partial-match site flags any repetition reachable
/// from the pattern start without consuming input (the implicit `.*?`
/// prefix overlap).
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
        if has_super_linear_pair(&parsed.root, site.match_type) {
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

fn has_super_linear_pair(node: &RxNode, match_type: RxMatchType) -> bool {
    let full = matches!(match_type, RxMatchType::Full | RxMatchType::Both);
    let partial = matches!(match_type, RxMatchType::Partial | RxMatchType::Both);
    for lin in node_linearizations(node) {
        if seq_has_super_linear(&lin, partial, full) {
            return true;
        }
    }
    false
}

/// All linearizations of a node: transparent (capture/non-capture) groups
/// splice their body items in place; alternations multiply the variants.
/// Bounded to keep pathological patterns cheap.
fn node_linearizations(node: &RxNode) -> Vec<Vec<&RxItem>> {
    match node {
        RxNode::Seq(seq) => seq_linearizations(seq),
        RxNode::Alternation(branches) => {
            let mut variants = Vec::new();
            for branch in branches {
                variants.extend(seq_linearizations(branch));
            }
            variants
        }
    }
}

fn seq_linearizations(seq: &RxSeq) -> Vec<Vec<&RxItem>> {
    let mut variants: Vec<Vec<&RxItem>> = vec![Vec::new()];
    for item in &seq.items {
        let expansions = expand_item(item);
        let mut next = Vec::with_capacity(variants.len() * expansions.len());
        for prefix in &variants {
            for expansion in &expansions {
                let mut combined = prefix.clone();
                combined.extend(expansion.iter().copied());
                next.push(combined);
            }
        }
        variants = next;
        if variants.len() > 64 {
            return Vec::new();
        }
    }
    variants
}

/// Item expansions: an unquantified transparent group splices its body
/// (each alternation branch is a separate expansion); every other item is
/// itself.
fn expand_item(item: &RxItem) -> Vec<Vec<&RxItem>> {
    if item.quant.is_none()
        && let RxAtom::Group(group) = &item.atom
        && matches!(group.kind, RxGroupKind::Capture | RxGroupKind::NonCapture)
    {
        let mut expansions = node_linearizations(&group.body);
        if expansions.is_empty() {
            expansions.push(Vec::new());
        }
        return expansions;
    }
    vec![vec![item]]
}

fn seq_has_super_linear(lin: &[&RxItem], partial: bool, full: bool) -> bool {
    // Sonar keeps a deque of the last ten active non-possessive
    // repetitions; each new active repetition is checked against every
    // earlier one still in the deque.
    let mut active: Vec<usize> = Vec::new();
    for (index, item) in lin.iter().enumerate() {
        if !rx_is_unbounded_repeat(item) || is_zero_width(item) {
            continue;
        }
        if !repetition_active(lin, index, full) {
            continue;
        }
        if partial && reachable_from_start(lin, index) {
            return true;
        }
        for &earlier in active.iter() {
            if pair_is_quadratic(lin, earlier, index) {
                return true;
            }
        }
        active.push(index);
        if active.len() > 10 {
            active.remove(0);
        }
    }
    false
}

fn repetition_active(lin: &[&RxItem], index: usize, full: bool) -> bool {
    let item = lin[index];
    if item.quant.as_ref().is_some_and(|quant| quant.possessive) {
        return false;
    }
    let rest = &lin[index + 1..];
    // Match-all repetitions always run free-end: they cannot fail when the
    // rest reaches the end without consuming input.
    if is_match_all(&item.atom) {
        return !can_reach_end(rest);
    }
    let free_end = !full && !anchored_at_end(rest);
    // Free-end mode: canFail is the reachability check. Strict mode (full
    // match or anchored at the end): every state can fail.
    !free_end || !can_reach_end(rest)
}

/// Whether every forward path from `rest` hits an end boundary (`$`,
/// `\Z`, `\z`) before the final state. For a linearized sequence this is
/// "some remaining item is an end anchor" — lookaround bodies count too.
fn anchored_at_end(rest: &[&RxItem]) -> bool {
    rest.iter().any(|item| node_has_end_anchor(&item.atom))
}

fn node_has_end_anchor(atom: &RxAtom) -> bool {
    match atom {
        RxAtom::Anchor(anchor) => anchor.is_end(),
        RxAtom::Group(group) => node_body_has_end_anchor(&group.body),
        _ => false,
    }
}

fn node_body_has_end_anchor(node: &RxNode) -> bool {
    match node {
        RxNode::Seq(seq) => seq.items.iter().any(|item| node_has_end_anchor(&item.atom)),
        RxNode::Alternation(branches) => branches.iter().all(|branch| {
            branch
                .items
                .iter()
                .any(|item| node_has_end_anchor(&item.atom))
        }),
    }
}

/// `canReachWithoutConsumingInput(state, endOfRegex)`: the rest can reach
/// the end through epsilon/negation/boundary transitions only. Every item
/// must be skippable; a lookaround is skippable when some body branch can
/// reach its own end without consuming (Sonar's EndOfLookaroundState
/// quirk). After an end boundary, line breaks and DOTALL dots also
/// traverse.
fn can_reach_end(rest: &[&RxItem]) -> bool {
    let mut saw_end_boundary = false;
    for item in rest {
        if item_is_nullable(item) {
            continue;
        }
        match &item.atom {
            RxAtom::Anchor(anchor) => {
                if anchor.is_end() {
                    saw_end_boundary = true;
                }
            }
            RxAtom::Group(group)
                if matches!(
                    group.kind,
                    RxGroupKind::Lookahead
                        | RxGroupKind::NegativeLookahead
                        | RxGroupKind::Lookbehind
                        | RxGroupKind::NegativeLookbehind
                ) =>
            {
                if !lookaround_body_reaches_end(&group.body) {
                    return false;
                }
            }
            RxAtom::Group(group) => {
                if !node_nullable(&group.body) {
                    return false;
                }
            }
            RxAtom::Literal(ch) if saw_end_boundary && matches!(ch, '\n' | '\r') => {}
            RxAtom::Dot if saw_end_boundary => {}
            _ => return false,
        }
    }
    true
}

/// Some branch of the lookaround body reaches its end without consuming
/// input (nullable path).
fn lookaround_body_reaches_end(node: &RxNode) -> bool {
    match node {
        RxNode::Seq(seq) => seq.items.iter().all(item_is_nullable),
        RxNode::Alternation(branches) => branches
            .iter()
            .any(|branch| branch.items.iter().all(item_is_nullable)),
    }
}

/// `canReachWithoutConsumingInput(startOfRegex, rep)`: every item before
/// `index` is skippable (same traversal as `can_reach_end`, minus the
/// post-boundary character rule which cannot apply at the start).
fn reachable_from_start(lin: &[&RxItem], index: usize) -> bool {
    lin[..index].iter().all(|item| {
        if item_is_nullable(item) {
            return true;
        }
        match &item.atom {
            RxAtom::Anchor(_) => true,
            RxAtom::Group(group)
                if matches!(
                    group.kind,
                    RxGroupKind::Lookahead
                        | RxGroupKind::NegativeLookahead
                        | RxGroupKind::Lookbehind
                        | RxGroupKind::NegativeLookbehind
                ) =>
            {
                lookaround_body_reaches_end(&group.body)
            }
            RxAtom::Group(group) => node_nullable(&group.body),
            _ => false,
        }
    })
}

/// The three intersection conditions of Sonar's overlapping-repetitions
/// check for an earlier repetition `i` and a later one `j`:
/// 1. `rep_i`'s element can consume the gap (empty gap or intersecting).
/// 2. The gap can consume `rep_j`'s element (empty gap or intersecting).
/// 3. The two elements intersect.
fn pair_is_quadratic(lin: &[&RxItem], i: usize, j: usize) -> bool {
    let gap = &lin[i + 1..j];
    let elem_i = &lin[i].atom;
    let elem_j = &lin[j].atom;
    if !atoms_intersect(elem_i, elem_j) {
        return false;
    }
    let gap_skippable = gap.iter().all(|item| gap_item_skippable(item));
    if gap_skippable {
        return true;
    }
    intersects_element_language(elem_i, gap) && intersects_element_language(elem_j, gap)
}

/// `canReachWithoutConsumingInputNorCrossingBoundaries` over the gap:
/// skippable items, but boundaries do not traverse.
fn gap_item_skippable(item: &RxItem) -> bool {
    if item_is_nullable(item) {
        return true;
    }
    match &item.atom {
        RxAtom::Anchor(_) => false,
        RxAtom::Group(group)
            if matches!(
                group.kind,
                RxGroupKind::Lookahead
                    | RxGroupKind::NegativeLookahead
                    | RxGroupKind::Lookbehind
                    | RxGroupKind::NegativeLookbehind
            ) =>
        {
            lookaround_body_reaches_end(&group.body)
        }
        RxAtom::Group(group) => node_nullable(&group.body),
        _ => false,
    }
}

/// `IntersectAutomataChecker.check(elem, gap)`: whether the single-element
/// language intersects the gap's language. A gap whose mandatory items
/// need two or more characters can only intersect a group element;
/// otherwise first-set intersection approximates it.
fn intersects_element_language(elem: &RxAtom, gap: &[&RxItem]) -> bool {
    let mandatory: Vec<&RxItem> = gap
        .iter()
        .copied()
        .filter(|item| item_is_mandatory(item))
        .collect();
    let min_len: u32 = mandatory.iter().map(|item| item_min_len(item)).sum();
    let Some(gap_first) = gap_first_set(gap) else {
        return true;
    };
    if min_len >= 2 {
        return matches!(elem, RxAtom::Group(_))
            && rx_atom_first_set(elem).is_some_and(|set| rx_sets_intersect(&set, &gap_first));
    }
    rx_atom_first_set(elem).is_none_or(|set| rx_sets_intersect(&set, &gap_first))
}

/// First-set of the gap's first mandatory item (nullable items before it
/// contribute their own sets too, since they can also start the string).
fn gap_first_set(gap: &[&RxItem]) -> Option<RxSet> {
    let mut combined: Option<RxSet> = None;
    for item in gap {
        if let Some(set) = rx_atom_first_set(&item.atom) {
            combined = Some(match combined {
                None => set,
                Some(previous) => union_sets(previous, set),
            });
        }
        if item_is_mandatory(item) {
            break;
        }
    }
    combined
}

fn union_sets(left: RxSet, right: RxSet) -> RxSet {
    match (left, right) {
        (RxSet::All, _) | (_, RxSet::All) => RxSet::All,
        (left, _) => left,
    }
}

fn atoms_intersect(left: &RxAtom, right: &RxAtom) -> bool {
    match (rx_atom_first_set(left), rx_atom_first_set(right)) {
        (Some(a), Some(b)) => rx_sets_intersect(&a, &b),
        _ => true,
    }
}

fn item_is_nullable(item: &RxItem) -> bool {
    rx_atom_nullable(&item.atom) || item.quant.as_ref().is_some_and(|quant| quant.min == 0)
}

fn item_is_mandatory(item: &RxItem) -> bool {
    !rx_atom_nullable(&item.atom)
        && !rx_atom_zero_width(&item.atom)
        && item.quant.as_ref().is_none_or(|quant| quant.min >= 1)
}

/// Minimum characters the item consumes when it matches.
fn item_min_len(item: &RxItem) -> u32 {
    let base = match &item.atom {
        RxAtom::Group(group) => node_min_len(&group.body),
        _ => 1,
    };
    base * item.quant.as_ref().map_or(1, |quant| quant.min.max(1))
}

fn node_min_len(node: &RxNode) -> u32 {
    match node {
        RxNode::Seq(seq) => seq
            .items
            .iter()
            .filter(|item| item_is_mandatory(item))
            .map(item_min_len)
            .sum(),
        RxNode::Alternation(branches) => branches
            .iter()
            .map(|branch| {
                branch
                    .items
                    .iter()
                    .filter(|item| item_is_mandatory(item))
                    .map(item_min_len)
                    .sum()
            })
            .min()
            .unwrap_or(0),
    }
}

fn node_nullable(node: &RxNode) -> bool {
    match node {
        RxNode::Seq(seq) => seq.items.iter().all(item_is_nullable),
        RxNode::Alternation(branches) => branches
            .iter()
            .any(|branch| branch.items.iter().all(item_is_nullable)),
    }
}

fn is_zero_width(item: &RxItem) -> bool {
    rx_atom_zero_width(&item.atom)
}

/// `canMatchAnyCharacter`: `.` counts as match-all (Sonar's simplified
/// character class treats the dot's line-break exclusions as covered), as
/// does a negated class with no excluded members.
fn is_match_all(atom: &RxAtom) -> bool {
    match atom {
        RxAtom::Dot => true,
        RxAtom::Class(class) => class.negated && class.items.is_empty(),
        _ => false,
    }
}
