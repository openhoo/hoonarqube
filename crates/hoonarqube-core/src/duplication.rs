//! Deterministic token/statement duplication detection.
//!
//! The detector indexes fixed-size fingerprints and verifies every candidate
//! with the interned symbol IDs from [`crate::source_facts::SourceFacts`].
//! Fingerprints are only an index key: equal hashes are never treated as
//! equal source.  A candidate is extended on both sides to a maximal matching
//! run, then equivalent runs are merged into groups.  Overlapping runs are
//! retained when their maximal ranges differ; shorter runs wholly represented
//! by a longer run are suppressed.
//!
//! Non-Java files use normalized lexical tokens and require both the token and
//! physical-line thresholds.  Java files use the statement units emitted by
//! the source-facts frontend and apply `min_statements` only.  JavaScript and
//! TypeScript intentionally remain separate language domains.  Java wrapper
//! units marked with the reserved `\0barrier:` symbol prefix receive a fresh
//! ID per occurrence, so they are hard separators and never count as matched
//! statements.
//!
//! Let `T` be the total number of source-facts units and `W` the number of
//! fixed windows.  Index construction is `O(T)` space and expected `O(T)`
//! time.  Candidate verification is bounded by `max_candidate_pairs` and a
//! deterministic comparison budget; exceeding either limit returns an error
//! rather than a partial report.  Group containment checks use the same
//! budget, so repetitive input cannot turn suppression into an unbounded
//! quadratic pass.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;

use crate::Language;
use crate::source_facts::{SourceFacts, UnitDefinition};

/// Limits and thresholds used by [`detect_duplications`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicationOptions {
    /// Minimum number of normalized lexical tokens in a non-Java block.
    pub min_tokens: usize,
    /// Minimum inclusive physical line span in a non-Java block.
    pub min_lines: u32,
    /// Minimum number of normalized Java statement units in a Java block.
    pub min_statements: usize,
    /// Maximum number of source-facts units accepted across all files.
    pub max_tokens: usize,
    /// Maximum number of fixed-window candidate pairs examined.
    pub max_candidate_pairs: usize,
}

impl Default for DuplicationOptions {
    fn default() -> Self {
        Self {
            min_tokens: 100,
            min_lines: 10,
            min_statements: 10,
            max_tokens: 2_000_000,
            max_candidate_pairs: 1_000_000,
        }
    }
}

impl DuplicationOptions {
    /// Validates thresholds and cap arithmetic before any source data is
    /// indexed.  A zero threshold/cap is rejected because it either makes
    /// every empty input a duplicate or disables the explicit work bound.
    ///
    /// # Errors
    ///
    /// Returns an error when a threshold or cap is zero or when its budget
    /// arithmetic overflows.
    pub fn validate(&self) -> Result<(), String> {
        if self.min_tokens == 0 {
            return Err("duplication min_tokens must be nonzero".to_owned());
        }
        if self.min_lines == 0 {
            return Err("duplication min_lines must be nonzero".to_owned());
        }
        if self.min_statements == 0 {
            return Err("duplication min_statements must be nonzero".to_owned());
        }
        if self.max_tokens == 0 {
            return Err("duplication max_tokens must be nonzero".to_owned());
        }
        if self.max_candidate_pairs == 0 {
            return Err("duplication max_candidate_pairs must be nonzero".to_owned());
        }

        // This is the largest per-candidate comparison allowance used below.
        // Check it here so a pathological usize configuration fails before
        // any allocation or matching work begins.
        let largest_threshold = self.min_tokens.max(self.min_statements);
        let per_candidate = largest_threshold
            .checked_add(COMPARISON_OVERHEAD)
            .ok_or_else(|| "duplication comparison budget overflows usize".to_owned())?;
        let candidate_allowance = self
            .max_candidate_pairs
            .checked_mul(per_candidate)
            .ok_or_else(|| "duplication comparison budget overflows usize".to_owned())?;
        self.max_tokens
            .checked_add(candidate_allowance)
            .ok_or_else(|| "duplication comparison budget overflows usize".to_owned())?;
        Ok(())
    }
}

/// One file and the normalized source facts used for duplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicationFile {
    pub path: PathBuf,
    pub language: Language,
    pub facts: SourceFacts,
}

/// Duplication groups, per-file metrics, and weighted aggregate metrics.
#[derive(Debug, Clone, PartialEq)]
pub struct DuplicationResult {
    pub groups: Vec<hoonarqube_ir::DuplicateGroup>,
    pub files: Vec<hoonarqube_ir::DuplicationFileMetrics>,
    pub metrics: hoonarqube_ir::DuplicationMetrics,
}

const HASH_BASE_A: u64 = 1_000_003;
const HASH_BASE_B: u64 = 1_000_033;
const BARRIER_PREFIX: &str = "\0barrier:";
const COMPARISON_OVERHEAD: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct WindowKey {
    language: Language,
    length: usize,
    hash_a: u64,
    hash_b: u64,
}

/// Exact structural identity for a Java unit. `own` is already canonical
/// through the project-wide string interner; child IDs are canonical keys
/// produced for definitions earlier in the post-order vector. The derived
/// hash is only a bucket index: equality remains exact key equality.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UnitKey {
    own: u32,
    children: Vec<u32>,
}

fn is_java_unit_symbol(symbol: &str) -> bool {
    let Some(encoded) = symbol.strip_prefix("java-unit") else {
        return false;
    };
    let Some((length_text, payload)) = encoded.split_once(':') else {
        return false;
    };
    let Ok(length) = length_text.parse::<usize>() else {
        return false;
    };
    length_text == length.to_string()
        && payload
            .as_bytes()
            .get(length)
            .is_some_and(|byte| *byte == b'|')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowRef {
    file: usize,
    start: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DiagonalKey {
    file_a: usize,
    file_b: usize,
    delta: i128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StartInterval {
    start: usize,
    /// One past the last fixed-window start covered by this interval.
    end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TokenOccurrence {
    file: usize,
    start: usize,
    end: usize,
}

#[derive(Debug, Clone)]
struct ProjectedOccurrence {
    file: usize,
    path: PathBuf,
    start_byte: u32,
    end_byte: u32,
    start_line: u32,
    end_line: u32,
}

#[derive(Debug)]
struct GroupState {
    language: Language,
    length: usize,
    hash_a: u64,
    hash_b: u64,
    representative: TokenOccurrence,
    occurrences: Vec<TokenOccurrence>,
    occurrence_set: HashSet<TokenOccurrence>,
}

#[derive(Debug)]
struct PreparedFile {
    path: PathBuf,
    language: Language,
    lines: u32,
    ids: Vec<u32>,
    starts: Vec<u32>,
    ends: Vec<u32>,
    byte_starts: Vec<u32>,
    byte_ends: Vec<u32>,
    prefix_a: Vec<u64>,
    prefix_b: Vec<u64>,
}

#[derive(Debug)]
struct WorkBudget {
    used: usize,
    limit: usize,
}

impl WorkBudget {
    fn new(total_tokens: usize, options: &DuplicationOptions) -> Result<Self, String> {
        let largest_threshold = options.min_tokens.max(options.min_statements);
        let per_candidate = largest_threshold
            .checked_add(COMPARISON_OVERHEAD)
            .ok_or_else(|| "duplication comparison budget overflows usize".to_owned())?;
        let candidate_allowance = options
            .max_candidate_pairs
            .checked_mul(per_candidate)
            .ok_or_else(|| "duplication comparison budget overflows usize".to_owned())?;
        let limit = total_tokens
            .checked_add(candidate_allowance)
            .ok_or_else(|| "duplication comparison budget overflows usize".to_owned())?;
        Ok(Self { used: 0, limit })
    }

    fn charge(&mut self, units: usize) -> Result<(), String> {
        let next = self
            .used
            .checked_add(units)
            .ok_or_else(|| "duplication comparison work overflows usize".to_owned())?;
        if next > self.limit {
            return Err(format!(
                "duplication comparison work limit exceeded ({})",
                self.limit
            ));
        }
        self.used = next;
        Ok(())
    }
}

/// Detects maximal matching token/statement runs.
///
/// `files` must contain complete source facts.  A facts parse/read error is
/// returned as an error so callers cannot mistake a partial project for a
/// complete duplication report.  `max_tokens` applies to the total number of
/// normalized units, including Java statement units.  No cross-language
/// candidate is considered.
/// Physical ranges are inclusive lines plus half-open byte spans.  Metrics
/// deduplicate actual byte spans while line totals use their unique inclusive
/// union; zero-width marker-only spans are omitted from reported groups.
///
/// # Errors
///
/// Returns an error when input facts are incomplete or invalid, a configured
/// work/input limit is exceeded, or bounded arithmetic cannot be completed.
pub fn detect_duplications(
    files: &[DuplicationFile],
    options: &DuplicationOptions,
) -> Result<DuplicationResult, String> {
    options.validate()?;
    let (prepared, total_tokens) = prepare_files(files, options)?;
    let (powers_a, powers_b) = build_hash_powers(&prepared)?;
    let index = build_window_index(&prepared, options, &powers_a, &powers_b);
    let (groups, mut budget) = find_groups(
        &prepared,
        &index,
        &powers_a,
        &powers_b,
        options,
        total_tokens,
    )?;
    let groups = suppress_contained_groups(groups, &prepared, &mut budget)?;
    build_result(&groups, &prepared)
}

fn prepare_files(
    files: &[DuplicationFile],
    options: &DuplicationOptions,
) -> Result<(Vec<PreparedFile>, usize), String> {
    let mut order: Vec<usize> = (0..files.len()).collect();
    order.sort_by(|&left, &right| {
        files[left]
            .path
            .cmp(&files[right].path)
            .then_with(|| {
                language_rank(files[left].language).cmp(&language_rank(files[right].language))
            })
            .then_with(|| left.cmp(&right))
    });
    let total_tokens = validate_input_files(files, &order, options)?;
    let mut interner: HashMap<String, u32> = HashMap::new();
    let mut unit_interner: HashMap<UnitKey, u32> = HashMap::new();
    let mut next_symbol_id = 0_u64;
    let mut prepared = Vec::with_capacity(files.len());
    for &index in &order {
        prepared.push(build_prepared_file(
            &files[index],
            &mut interner,
            &mut unit_interner,
            &mut next_symbol_id,
        )?);
    }
    Ok((prepared, total_tokens))
}

fn validate_input_files(
    files: &[DuplicationFile],
    order: &[usize],
    options: &DuplicationOptions,
) -> Result<usize, String> {
    let mut total_tokens = 0_usize;
    let mut paths = BTreeSet::new();
    for &index in order {
        let file = &files[index];
        if !paths.insert(file.path.clone()) {
            return Err(format!(
                "duplicate duplication input path {}",
                file.path.display()
            ));
        }
        if file.language != file.facts.language {
            return Err(format!(
                "duplication facts language mismatch for {}",
                file.path.display()
            ));
        }
        if let Some(error) = &file.facts.error {
            return Err(format!(
                "incomplete duplication facts for {}: {error}",
                file.path.display()
            ));
        }
        total_tokens = total_tokens
            .checked_add(file.facts.tokens.len())
            .ok_or_else(|| "duplication source-facts token count overflows usize".to_owned())?;
        if total_tokens > options.max_tokens {
            return Err(format!(
                "duplication input exceeds max_tokens ({})",
                options.max_tokens
            ));
        }
        validate_tokens(file)?;
    }
    Ok(total_tokens)
}

fn build_prepared_file(
    file: &DuplicationFile,
    interner: &mut HashMap<String, u32>,
    unit_interner: &mut HashMap<UnitKey, u32>,
    next_symbol_id: &mut u64,
) -> Result<PreparedFile, String> {
    let facts = &file.facts;
    let mut ids = Vec::with_capacity(facts.tokens.len());
    for token in &facts.tokens {
        let symbol_index = usize::try_from(token.symbol).map_err(|_| {
            format!(
                "duplication token symbol {} is out of range for {}",
                token.symbol,
                file.path.display()
            )
        })?;
        let symbol = facts.symbols.get(symbol_index).ok_or_else(|| {
            format!(
                "duplication token symbol {} is out of range for {}",
                token.symbol,
                file.path.display()
            )
        })?;
        let id = if symbol.starts_with(BARRIER_PREFIX) {
            // Java statement extraction uses barriers for wrapper syntax.
            // A fresh ID per occurrence keeps wrappers from matching while
            // retaining them as hard separators in the unit stream.
            allocate_symbol_id(next_symbol_id)?
        } else if let Some(id) = interner.get(symbol) {
            *id
        } else {
            let id = allocate_symbol_id(next_symbol_id)?;
            interner.insert(symbol.clone(), id);
            id
        };
        ids.push(id);
    }
    if facts.language == Language::Java || !facts.units.is_empty() {
        let mut composition = UnitComposition {
            path: &file.path,
            facts,
            ids: &mut ids,
            unit_interner,
            next_symbol_id,
            definition_ids: Vec::with_capacity(facts.units.len()),
            seen_tokens: HashSet::with_capacity(facts.units.len()),
            parent_of: vec![None; facts.units.len()],
            child_edges: 0,
        };
        for (definition_index, definition) in facts.units.iter().enumerate() {
            composition.compose_definition(definition_index, definition)?;
        }
        composition.require_exact_coverage()?;
    }

    let mut starts = Vec::with_capacity(ids.len());
    let mut ends = Vec::with_capacity(ids.len());
    let mut byte_starts = Vec::with_capacity(ids.len());
    let mut byte_ends = Vec::with_capacity(ids.len());
    for token in &facts.tokens {
        starts.push(token.start_line);
        ends.push(token.end_line);
        byte_starts.push(token.start_byte);
        byte_ends.push(token.end_byte);
    }
    let prefix_a = build_hash_prefix(&ids, HASH_BASE_A)?;
    let prefix_b = build_hash_prefix(&ids, HASH_BASE_B)?;
    Ok(PreparedFile {
        path: file.path.clone(),
        language: file.language,
        lines: facts.metrics.lines,
        ids,
        starts,
        ends,
        byte_starts,
        byte_ends,
        prefix_a,
        prefix_b,
    })
}

/// Per-file state while Java unit definitions are validated and composed
/// into structural unit IDs.  Definitions are consumed in post-order, so
/// every child's composed ID already exists when its parent needs it; the
/// `ids` slots of unit tokens are rewritten to the composed structural IDs.
struct UnitComposition<'a> {
    path: &'a std::path::Path,
    facts: &'a SourceFacts,
    ids: &'a mut [u32],
    unit_interner: &'a mut HashMap<UnitKey, u32>,
    next_symbol_id: &'a mut u64,
    definition_ids: Vec<u32>,
    seen_tokens: HashSet<usize>,
    parent_of: Vec<Option<usize>>,
    child_edges: usize,
}

impl UnitComposition<'_> {
    fn invalid(&self, definition_index: usize, detail: &str) -> String {
        format!(
            "duplication unit definition {definition_index} {detail} for {}",
            self.path.display()
        )
    }

    fn compose_definition(
        &mut self,
        definition_index: usize,
        definition: &UnitDefinition,
    ) -> Result<(), String> {
        let (token_index, own) = self.validate_header(definition_index, definition)?;
        self.child_edges = self
            .child_edges
            .checked_add(definition.children.len())
            .ok_or_else(|| "duplication unit definition edge count overflows usize".to_owned())?;
        if self.child_edges > self.facts.tokens.len() {
            return Err(self.invalid(
                definition_index,
                "definitions exceed bounded child-edge storage",
            ));
        }
        if definition.children.len() > self.facts.tokens.len() {
            return Err(self.invalid(definition_index, "exceeds child bound"));
        }
        let children = self.validate_children(definition_index, definition)?;
        let key = UnitKey { own, children };
        let id = if let Some(&id) = self.unit_interner.get(&key) {
            id
        } else {
            let id = allocate_symbol_id(self.next_symbol_id)?;
            self.unit_interner.insert(key, id);
            id
        };
        self.definition_ids.push(id);
        // `validate_header` verified the token index is within range.
        self.ids[token_index] = id;
        Ok(())
    }

    /// Validates one definition's token and own-parts symbol and returns the
    /// token index plus the token's current own-parts ID.
    fn validate_header(
        &mut self,
        definition_index: usize,
        definition: &UnitDefinition,
    ) -> Result<(usize, u32), String> {
        let token_index = usize::try_from(definition.token)
            .map_err(|_| self.invalid(definition_index, "token is out of range"))?;
        let Some(token) = self.facts.tokens.get(token_index) else {
            return Err(self.invalid(definition_index, "token is out of range"));
        };
        let Some(&own) = self.ids.get(token_index) else {
            return Err(self.invalid(definition_index, "token is out of range"));
        };
        let Some(symbol_text) = usize::try_from(definition.symbol)
            .ok()
            .and_then(|symbol| self.facts.symbols.get(symbol))
        else {
            return Err(self.invalid(definition_index, "symbol is out of range"));
        };
        if !is_java_unit_symbol(symbol_text)
            || token.symbol != definition.symbol
            || !self.seen_tokens.insert(token_index)
        {
            return Err(self.invalid(definition_index, "has an inconsistent token"));
        }
        Ok((token_index, own))
    }

    /// Validates one definition's child references (precedence, ordering,
    /// spans, single parenthood) and returns their composed unit IDs.
    fn validate_children(
        &mut self,
        definition_index: usize,
        definition: &UnitDefinition,
    ) -> Result<Vec<u32>, String> {
        let token_index = usize::try_from(definition.token)
            .map_err(|_| self.invalid(definition_index, "token is out of range"))?;
        let (parent_start, parent_end) = {
            let token = &self.facts.tokens[token_index];
            (token.start_byte, token.end_byte)
        };
        let mut previous_end = parent_start;
        let mut children = Vec::with_capacity(definition.children.len());
        for &child in &definition.children {
            let child_index = usize::try_from(child)
                .map_err(|_| self.invalid(definition_index, "child is out of range"))?;
            if child_index >= definition_index {
                return Err(self.invalid(definition_index, "references a non-preceding child"));
            }
            let Some(child_definition) = self.facts.units.get(child_index) else {
                return Err(self.invalid(definition_index, "references an unavailable child"));
            };
            let (child_start, child_end) =
                self.child_token_span(definition_index, child_definition)?;
            if child_start < parent_start
                || child_end > parent_end
                || child_start < previous_end
                || self.parent_of[child_index]
                    .replace(definition_index)
                    .is_some()
            {
                return Err(self.invalid(definition_index, "child spans or parents are invalid"));
            }
            previous_end = child_end;
            let Some(&child_id) = self.definition_ids.get(child_index) else {
                return Err(self.invalid(definition_index, "references an unavailable child"));
            };
            children.push(child_id);
        }
        Ok(children)
    }

    fn child_token_span(
        &self,
        definition_index: usize,
        child_definition: &UnitDefinition,
    ) -> Result<(u32, u32), String> {
        let child_token_index = usize::try_from(child_definition.token)
            .map_err(|_| self.invalid(definition_index, "child token is out of range"))?;
        let Some(child_token) = self.facts.tokens.get(child_token_index) else {
            return Err(self.invalid(definition_index, "child token is out of range"));
        };
        Ok((child_token.start_byte, child_token.end_byte))
    }

    /// Requires the definitions to cover exactly the tokens whose symbol is
    /// a Java unit signature, so partially defined files fail closed.
    fn require_exact_coverage(&self) -> Result<(), String> {
        let expected_tokens: HashSet<usize> = self
            .facts
            .tokens
            .iter()
            .enumerate()
            .filter(|(_, token)| {
                usize::try_from(token.symbol)
                    .ok()
                    .and_then(|symbol| self.facts.symbols.get(symbol))
                    .is_some_and(|symbol| is_java_unit_symbol(symbol))
            })
            .map(|(index, _)| index)
            .collect();
        if expected_tokens != self.seen_tokens {
            return Err(format!(
                "duplication Java unit definitions do not cover all unit tokens in {}",
                self.path.display()
            ));
        }
        Ok(())
    }
}

fn build_hash_prefix(ids: &[u32], base: u64) -> Result<Vec<u64>, String> {
    let capacity = ids
        .len()
        .checked_add(1)
        .ok_or_else(|| "duplication prefix length overflows usize".to_owned())?;
    let mut prefix = Vec::with_capacity(capacity);
    prefix.push(0_u64);
    for id in ids {
        prefix.push(
            prefix
                .last()
                .copied()
                .unwrap_or_default()
                .wrapping_mul(base)
                .wrapping_add(u64::from(*id) + 1),
        );
    }
    Ok(prefix)
}

fn allocate_symbol_id(next: &mut u64) -> Result<u32, String> {
    let id =
        u32::try_from(*next).map_err(|_| "duplication symbol interner exceeds u32".to_owned())?;
    *next = next
        .checked_add(1)
        .ok_or_else(|| "duplication symbol interner counter overflows u64".to_owned())?;
    Ok(id)
}

fn build_hash_powers(files: &[PreparedFile]) -> Result<(Vec<u64>, Vec<u64>), String> {
    let max_items = files
        .iter()
        .map(|file| file.ids.len())
        .max()
        .unwrap_or_default();
    let power_capacity = max_items
        .checked_add(1)
        .ok_or_else(|| "duplication hash power length overflows usize".to_owned())?;
    let mut powers_a = Vec::with_capacity(power_capacity);
    let mut powers_b = Vec::with_capacity(power_capacity);
    powers_a.push(1_u64);
    powers_b.push(1_u64);
    for _ in 0..max_items {
        powers_a.push(
            powers_a
                .last()
                .copied()
                .unwrap_or(1)
                .wrapping_mul(HASH_BASE_A),
        );
        powers_b.push(
            powers_b
                .last()
                .copied()
                .unwrap_or(1)
                .wrapping_mul(HASH_BASE_B),
        );
    }
    Ok((powers_a, powers_b))
}

fn build_window_index(
    files: &[PreparedFile],
    options: &DuplicationOptions,
    powers_a: &[u64],
    powers_b: &[u64],
) -> HashMap<WindowKey, Vec<WindowRef>> {
    let mut index: HashMap<WindowKey, Vec<WindowRef>> = HashMap::new();
    for (file_index, file) in files.iter().enumerate() {
        let window_length = if file.language == Language::Java {
            options.min_statements
        } else {
            options.min_tokens
        };
        if file.ids.len() < window_length {
            continue;
        }
        let window_count = file.ids.len() - window_length + 1;
        for start in 0..window_count {
            let key = WindowKey {
                language: file.language,
                length: window_length,
                hash_a: range_hash(&file.prefix_a, powers_a, start, window_length),
                hash_b: range_hash(&file.prefix_b, powers_b, start, window_length),
            };
            index.entry(key).or_default().push(WindowRef {
                file: file_index,
                start,
            });
        }
    }
    index
}

fn find_groups(
    files: &[PreparedFile],
    index: &HashMap<WindowKey, Vec<WindowRef>>,
    powers_a: &[u64],
    powers_b: &[u64],
    options: &DuplicationOptions,
    total_tokens: usize,
) -> Result<(Vec<GroupState>, WorkBudget), String> {
    let mut engine = MatchEngine {
        files,
        powers_a,
        powers_b,
        options,
        budget: WorkBudget::new(total_tokens, options)?,
        coverage: HashMap::new(),
        groups: Vec::new(),
        groups_by_key: HashMap::new(),
        candidate_pairs: 0,
    };
    let groups = engine.run(index)?;
    Ok((groups, engine.budget))
}

struct MatchEngine<'a> {
    files: &'a [PreparedFile],
    powers_a: &'a [u64],
    powers_b: &'a [u64],
    options: &'a DuplicationOptions,
    budget: WorkBudget,
    coverage: HashMap<DiagonalKey, BTreeMap<usize, usize>>,
    groups: Vec<GroupState>,
    groups_by_key: HashMap<WindowKey, Vec<usize>>,
    candidate_pairs: usize,
}

impl MatchEngine<'_> {
    fn run(
        &mut self,
        index: &HashMap<WindowKey, Vec<WindowRef>>,
    ) -> Result<Vec<GroupState>, String> {
        let mut keys: Vec<WindowKey> = index.keys().copied().collect();
        keys.sort_by(|left, right| {
            language_rank(left.language)
                .cmp(&language_rank(right.language))
                .then_with(|| left.length.cmp(&right.length))
                .then_with(|| left.hash_a.cmp(&right.hash_a))
                .then_with(|| left.hash_b.cmp(&right.hash_b))
        });
        for key in keys {
            let references = index
                .get(&key)
                .ok_or_else(|| "duplication window index changed unexpectedly".to_owned())?;
            self.process_bucket(key, references)?;
        }
        Ok(std::mem::take(&mut self.groups))
    }

    fn process_bucket(&mut self, key: WindowKey, references: &[WindowRef]) -> Result<(), String> {
        for left_position in 0..references.len() {
            for right_position in (left_position + 1)..references.len() {
                self.process_pair(key, references[left_position], references[right_position])?;
            }
        }
        Ok(())
    }

    fn process_pair(
        &mut self,
        key: WindowKey,
        first: WindowRef,
        second: WindowRef,
    ) -> Result<(), String> {
        if first.file == second.file && first.start == second.start {
            return Ok(());
        }
        let (left, right) = orient_references(first, second);
        let diagonal = diagonal_key(left, right)?;
        if covered_start(&self.coverage, diagonal, left.start, &mut self.budget)? {
            return Ok(());
        }

        self.candidate_pairs = self
            .candidate_pairs
            .checked_add(1)
            .ok_or_else(|| "duplication candidate-pair count overflows usize".to_owned())?;
        if self.candidate_pairs > self.options.max_candidate_pairs {
            return Err(format!(
                "duplication candidate-pair limit exceeded ({})",
                self.options.max_candidate_pairs
            ));
        }
        self.budget.charge(1)?;

        let (left_start, right_start, length) = {
            let left_file = &self.files[left.file];
            let right_file = &self.files[right.file];
            if !equal_ids(
                left_file,
                left.start,
                right_file,
                right.start,
                key.length,
                &mut self.budget,
            )? {
                return Ok(());
            }
            extend_match(
                left_file,
                left.start,
                right_file,
                right.start,
                key.length,
                &mut self.budget,
            )?
        };
        let left_occurrence = make_occurrence(left.file, left_start, length)?;
        let right_occurrence = make_occurrence(right.file, right_start, length)?;
        let covered_window_count = length
            .checked_sub(key.length)
            .and_then(|extra| extra.checked_add(1))
            .ok_or_else(|| "duplication coverage window count underflows".to_owned())?;
        let interval_end = left_start
            .checked_add(covered_window_count)
            .ok_or_else(|| "duplication coverage interval overflows usize".to_owned())?;
        let interval = StartInterval {
            start: left_start,
            end: interval_end,
        };
        insert_coverage(&mut self.coverage, diagonal, interval, &mut self.budget)?;

        let left_file = &self.files[left.file];
        let right_file = &self.files[right.file];
        if !eligible_span(key.language, left_file, left_start, length, self.options)?
            || !eligible_span(key.language, right_file, right_start, length, self.options)?
        {
            return Ok(());
        }
        let full_key = WindowKey {
            language: key.language,
            length,
            hash_a: range_hash(&left_file.prefix_a, self.powers_a, left_start, length),
            hash_b: range_hash(&left_file.prefix_b, self.powers_b, left_start, length),
        };
        self.merge_match(full_key, left_occurrence, right_occurrence)?;
        Ok(())
    }

    fn merge_match(
        &mut self,
        key: WindowKey,
        left: TokenOccurrence,
        right: TokenOccurrence,
    ) -> Result<(), String> {
        let matching_group = if let Some(indices) = self.groups_by_key.get(&key) {
            let mut found = None;
            for &group_index in indices {
                self.budget.charge(1)?;
                let representative = self.groups[group_index].representative;
                if equal_occurrences(self.files, left, representative, &mut self.budget)? {
                    found = Some(group_index);
                    break;
                }
            }
            found
        } else {
            None
        };

        if let Some(group_index) = matching_group {
            let group = &mut self.groups[group_index];
            if group.occurrence_set.insert(left) {
                group.occurrences.push(left);
            }
            if group.occurrence_set.insert(right) {
                group.occurrences.push(right);
            }
            return Ok(());
        }

        let group_index = self.groups.len();
        let mut occurrence_set = HashSet::with_capacity(2);
        occurrence_set.insert(left);
        occurrence_set.insert(right);
        self.groups.push(GroupState {
            language: key.language,
            length: key.length,
            hash_a: key.hash_a,
            hash_b: key.hash_b,
            representative: left,
            occurrences: vec![left, right],
            occurrence_set,
        });
        self.groups_by_key.entry(key).or_default().push(group_index);
        Ok(())
    }
}

fn validate_tokens(file: &DuplicationFile) -> Result<(), String> {
    for (index, token) in file.facts.tokens.iter().enumerate() {
        if token.start_line == 0 || token.end_line == 0 || token.start_line > token.end_line {
            return Err(format!(
                "invalid duplication token span at index {index} in {}",
                file.path.display()
            ));
        }
        let symbol_index = usize::try_from(token.symbol).map_err(|_| {
            format!(
                "duplication token symbol {} is out of range for {}",
                token.symbol,
                file.path.display()
            )
        })?;
        if symbol_index >= file.facts.symbols.len() {
            return Err(format!(
                "duplication token symbol {} is out of range for {}",
                token.symbol,
                file.path.display()
            ));
        }
    }
    Ok(())
}

fn language_rank(language: Language) -> u8 {
    match language {
        Language::Python => 0,
        Language::JavaScript => 1,
        Language::TypeScript => 2,
        Language::CSharp => 3,
        Language::Go => 4,
        Language::Java => 5,
        Language::Rust => 6,
        Language::Ruby => 7,
    }
}

fn language_name(language: Language) -> &'static str {
    match language {
        Language::Python => "python",
        Language::JavaScript => "javascript",
        Language::TypeScript => "typescript",
        Language::CSharp => "csharp",
        Language::Go => "go",
        Language::Java => "java",
        Language::Rust => "rust",
        Language::Ruby => "ruby",
    }
}

fn range_hash(prefix: &[u64], powers: &[u64], start: usize, length: usize) -> u64 {
    let end = start + length;
    prefix[end].wrapping_sub(prefix[start].wrapping_mul(powers[length]))
}

fn orient_references(first: WindowRef, second: WindowRef) -> (WindowRef, WindowRef) {
    if first.file < second.file || (first.file == second.file && first.start <= second.start) {
        (first, second)
    } else {
        (second, first)
    }
}

fn diagonal_key(left: WindowRef, right: WindowRef) -> Result<DiagonalKey, String> {
    let right_start = i128::try_from(right.start)
        .map_err(|_| "duplication diagonal offset overflows i128".to_owned())?;
    let left_start = i128::try_from(left.start)
        .map_err(|_| "duplication diagonal offset overflows i128".to_owned())?;
    Ok(DiagonalKey {
        file_a: left.file,
        file_b: right.file,
        delta: right_start - left_start,
    })
}
/// Charges a conservative ordered-map height proxy for bounded work.
///
/// The concrete `BTreeMap` implementation does not expose comparison counts;
/// this logarithmic charge is an accounting model rather than an observation
/// about its internal tree layout.
fn ordered_map_work(entries: usize) -> usize {
    let entries = entries.max(1);
    usize::try_from(usize::BITS - entries.leading_zeros()).unwrap_or(usize::MAX)
}

fn insert_coverage(
    coverage: &mut HashMap<DiagonalKey, BTreeMap<usize, usize>>,
    diagonal: DiagonalKey,
    interval: StartInterval,
    budget: &mut WorkBudget,
) -> Result<(), String> {
    if interval.start >= interval.end {
        return Err("duplication coverage interval is empty".to_owned());
    }

    // The outer hash lookup is charged as constant work; ordered operations
    // charge a logarithmic tree-height bound plus each visited or removed
    // interval.  Each touched interval is charged separately, so a merge is
    // not incorrectly modeled as one logarithmic operation.
    budget.charge(1)?;
    let intervals = coverage.entry(diagonal).or_default();
    if intervals.is_empty() {
        budget.charge(1)?;
        intervals.insert(interval.start, interval.end);
        return Ok(());
    }

    budget.charge(ordered_map_work(intervals.len()))?;
    let predecessor = intervals
        .range(..=interval.start)
        .next_back()
        .map(|(&start, &end)| (start, end));
    let mut merged_start = interval.start;
    let mut merged_end = interval.end;
    if let Some((start, end)) = predecessor
        && end >= merged_start
    {
        merged_start = start;
        merged_end = merged_end.max(end);
    }

    loop {
        budget.charge(ordered_map_work(intervals.len()))?;
        let next = intervals
            .range(merged_start..)
            .next()
            .map(|(&start, &end)| (start, end));
        let Some((start, end)) = next else {
            break;
        };
        budget.charge(1)?;
        if start > merged_end {
            break;
        }
        merged_end = merged_end.max(end);
        budget.charge(ordered_map_work(intervals.len()))?;
        intervals.remove(&start);
    }
    let insertion_entries = intervals.len().saturating_add(1);
    budget.charge(ordered_map_work(insertion_entries))?;
    intervals.insert(merged_start, merged_end);
    Ok(())
}

fn covered_start(
    coverage: &HashMap<DiagonalKey, BTreeMap<usize, usize>>,
    diagonal: DiagonalKey,
    left_start: usize,
    budget: &mut WorkBudget,
) -> Result<bool, String> {
    budget.charge(1)?;
    let Some(intervals) = coverage.get(&diagonal) else {
        return Ok(false);
    };
    budget.charge(ordered_map_work(intervals.len()))?;
    let Some((_, &end)) = intervals.range(..=left_start).next_back() else {
        return Ok(false);
    };
    Ok(left_start < end)
}

fn equal_ids(
    left: &PreparedFile,
    left_start: usize,
    right: &PreparedFile,
    right_start: usize,
    length: usize,
    budget: &mut WorkBudget,
) -> Result<bool, String> {
    for offset in 0..length {
        budget.charge(1)?;
        if left.ids[left_start + offset] != right.ids[right_start + offset] {
            return Ok(false);
        }
    }
    Ok(true)
}

fn extend_match(
    left: &PreparedFile,
    mut left_start: usize,
    right: &PreparedFile,
    mut right_start: usize,
    initial_length: usize,
    budget: &mut WorkBudget,
) -> Result<(usize, usize, usize), String> {
    let mut length = initial_length;
    while left_start > 0 && right_start > 0 {
        budget.charge(1)?;
        if left.ids[left_start - 1] != right.ids[right_start - 1] {
            break;
        }
        left_start -= 1;
        right_start -= 1;
        length += 1;
    }
    while left_start < left.ids.len() - length && right_start < right.ids.len() - length {
        budget.charge(1)?;
        if left.ids[left_start + length] != right.ids[right_start + length] {
            break;
        }
        length += 1;
    }
    Ok((left_start, right_start, length))
}

fn make_occurrence(file: usize, start: usize, length: usize) -> Result<TokenOccurrence, String> {
    if length == 0 {
        return Err("duplication match has zero length".to_owned());
    }
    let end = start
        .checked_add(length - 1)
        .ok_or_else(|| "duplication occurrence index overflows usize".to_owned())?;
    Ok(TokenOccurrence { file, start, end })
}

fn eligible_span(
    language: Language,
    file: &PreparedFile,
    start: usize,
    length: usize,
    options: &DuplicationOptions,
) -> Result<bool, String> {
    if language == Language::Java {
        return Ok(length >= options.min_statements);
    }
    let end = start
        .checked_add(length - 1)
        .ok_or_else(|| "duplication span index overflows usize".to_owned())?;
    let start_line = file.starts[start];
    let end_line = file.ends[end];
    let span = end_line
        .checked_sub(start_line)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| "duplication physical line span overflows u32".to_owned())?;
    Ok(length >= options.min_tokens && span >= options.min_lines)
}

fn occurrence_length(occurrence: TokenOccurrence) -> usize {
    occurrence.end - occurrence.start + 1
}

fn equal_occurrences(
    files: &[PreparedFile],
    left: TokenOccurrence,
    right: TokenOccurrence,
    budget: &mut WorkBudget,
) -> Result<bool, String> {
    let length = occurrence_length(left);
    if length != occurrence_length(right) {
        return Ok(false);
    }
    let left_file = &files[left.file];
    let right_file = &files[right.file];
    equal_ids(
        left_file,
        left.start,
        right_file,
        right.start,
        length,
        budget,
    )
}

fn suppress_contained_groups(
    groups: Vec<GroupState>,
    files: &[PreparedFile],
    budget: &mut WorkBudget,
) -> Result<Vec<GroupState>, String> {
    if groups.len() < 2 {
        return Ok(groups);
    }

    let mut order: Vec<usize> = (0..groups.len()).collect();
    order.sort_by(|&left, &right| containment_group_order(&groups[left], &groups[right]));

    let mut accepted = Vec::with_capacity(groups.len());
    let mut accepted_by_file: Vec<Vec<TokenOccurrence>> =
        (0..files.len()).map(|_| Vec::new()).collect();

    for group_index in order {
        let group = &groups[group_index];
        if group_is_redundant(group, &accepted_by_file, files, budget)? {
            continue;
        }
        accepted.push(group_index);
        for occurrence in &group.occurrences {
            accepted_by_file[occurrence.file].push(*occurrence);
        }
    }

    accepted.sort_by(|&left, &right| accepted_group_order(&groups[left], &groups[right], files));

    let mut states: Vec<Option<GroupState>> = groups.into_iter().map(Some).collect();
    let mut result = Vec::with_capacity(accepted.len());
    for index in accepted {
        let state = states
            .get_mut(index)
            .and_then(Option::take)
            .ok_or_else(|| "duplication group index changed unexpectedly".to_owned())?;
        result.push(state);
    }
    Ok(result)
}

fn group_is_redundant(
    group: &GroupState,
    accepted_by_file: &[Vec<TokenOccurrence>],
    files: &[PreparedFile],
    budget: &mut WorkBudget,
) -> Result<bool, String> {
    for short_occurrence in &group.occurrences {
        if !occurrence_is_covered(
            *short_occurrence,
            group.length,
            accepted_by_file,
            files,
            budget,
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn occurrence_is_covered(
    short_occurrence: TokenOccurrence,
    group_length: usize,
    accepted_by_file: &[Vec<TokenOccurrence>],
    files: &[PreparedFile],
    budget: &mut WorkBudget,
) -> Result<bool, String> {
    for long_occurrence in &accepted_by_file[short_occurrence.file] {
        budget.charge(1)?;
        let long_length = occurrence_length(*long_occurrence);
        if long_length <= group_length
            || long_occurrence.start > short_occurrence.start
            || long_occurrence.end < short_occurrence.end
        {
            continue;
        }
        let offset = short_occurrence.start - long_occurrence.start;
        let file = &files[short_occurrence.file];
        if equal_ids(
            file,
            long_occurrence.start + offset,
            file,
            short_occurrence.start,
            group_length,
            budget,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn containment_group_order(left: &GroupState, right: &GroupState) -> Ordering {
    right
        .length
        .cmp(&left.length)
        .then_with(|| language_rank(left.language).cmp(&language_rank(right.language)))
        .then_with(|| left.representative.file.cmp(&right.representative.file))
        .then_with(|| left.representative.start.cmp(&right.representative.start))
        .then_with(|| left.hash_a.cmp(&right.hash_a))
        .then_with(|| left.hash_b.cmp(&right.hash_b))
}

fn accepted_group_order(left: &GroupState, right: &GroupState, files: &[PreparedFile]) -> Ordering {
    language_rank(left.language)
        .cmp(&language_rank(right.language))
        .then_with(|| {
            let left_occurrence = left
                .occurrences
                .iter()
                .min_by(|a, b| occurrence_order(**a, **b, files));
            let right_occurrence = right
                .occurrences
                .iter()
                .min_by(|a, b| occurrence_order(**a, **b, files));
            match (left_occurrence, right_occurrence) {
                (Some(left_occurrence), Some(right_occurrence)) => {
                    occurrence_order(*left_occurrence, *right_occurrence, files)
                }
                _ => Ordering::Equal,
            }
        })
        .then_with(|| right.length.cmp(&left.length))
        .then_with(|| left.hash_a.cmp(&right.hash_a))
        .then_with(|| left.hash_b.cmp(&right.hash_b))
}
fn occurrence_order(
    left: TokenOccurrence,
    right: TokenOccurrence,
    files: &[PreparedFile],
) -> Ordering {
    files[left.file]
        .path
        .cmp(&files[right.file].path)
        .then_with(|| left.file.cmp(&right.file))
        .then_with(|| {
            files[left.file].starts[left.start].cmp(&files[right.file].starts[right.start])
        })
        .then_with(|| files[left.file].ends[left.end].cmp(&files[right.file].ends[right.end]))
        .then_with(|| left.start.cmp(&right.start))
        .then_with(|| left.end.cmp(&right.end))
}

fn project_group_occurrences(
    group: &GroupState,
    files: &[PreparedFile],
) -> Vec<ProjectedOccurrence> {
    let mut seen: BTreeSet<(usize, u32, u32)> = BTreeSet::new();
    let mut projected = Vec::with_capacity(group.occurrences.len());
    for occurrence in &group.occurrences {
        let file = &files[occurrence.file];
        let Some(projected_occurrence) = project_occurrence(*occurrence, file) else {
            continue;
        };
        let key = (
            projected_occurrence.file,
            projected_occurrence.start_byte,
            projected_occurrence.end_byte,
        );
        if seen.insert(key) {
            projected.push(projected_occurrence);
        }
    }
    sort_projected_occurrences(&mut projected);
    projected
}

fn project_occurrence(
    occurrence: TokenOccurrence,
    file: &PreparedFile,
) -> Option<ProjectedOccurrence> {
    let mut first_nonempty = None;
    let mut last_nonempty = None;
    for index in occurrence.start..=occurrence.end {
        if file.byte_starts[index] < file.byte_ends[index] {
            if first_nonempty.is_none() {
                first_nonempty = Some(index);
            }
            last_nonempty = Some(index);
        }
    }
    let (Some(first), Some(last)) = (first_nonempty, last_nonempty) else {
        return None;
    };
    Some(ProjectedOccurrence {
        file: occurrence.file,
        path: file.path.clone(),
        start_byte: file.byte_starts[first],
        end_byte: file.byte_ends[last],
        start_line: file.starts[first],
        end_line: file.ends[last],
    })
}

fn sort_projected_occurrences(projected: &mut [ProjectedOccurrence]) {
    projected.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.start_byte.cmp(&right.start_byte))
            .then_with(|| left.end_byte.cmp(&right.end_byte))
            .then_with(|| left.start_line.cmp(&right.start_line))
            .then_with(|| left.end_line.cmp(&right.end_line))
    });
}
fn build_result(
    groups: &[GroupState],
    files: &[PreparedFile],
) -> Result<DuplicationResult, String> {
    let mut output_groups = Vec::with_capacity(groups.len());
    let mut per_file_ranges: Vec<BTreeSet<(u32, u32)>> =
        (0..files.len()).map(|_| BTreeSet::new()).collect();
    let mut per_file_spans: Vec<BTreeSet<(u32, u32)>> =
        (0..files.len()).map(|_| BTreeSet::new()).collect();
    let mut project_ranges: BTreeSet<(PathBuf, u32, u32)> = BTreeSet::new();
    let mut project_spans: BTreeSet<(PathBuf, u32, u32)> = BTreeSet::new();

    for group in groups {
        append_projected_group(
            group,
            files,
            &mut output_groups,
            &mut per_file_ranges,
            &mut per_file_spans,
            &mut project_ranges,
            &mut project_spans,
        );
    }

    let metrics = build_project_metrics(files, &project_ranges, &project_spans)?;
    let file_metrics = build_file_metrics(files, &per_file_ranges, &per_file_spans)?;
    Ok(DuplicationResult {
        groups: output_groups,
        files: file_metrics,
        metrics,
    })
}
fn append_projected_group(
    group: &GroupState,
    files: &[PreparedFile],
    output_groups: &mut Vec<hoonarqube_ir::DuplicateGroup>,
    per_file_ranges: &mut [BTreeSet<(u32, u32)>],
    per_file_spans: &mut [BTreeSet<(u32, u32)>],
    project_ranges: &mut BTreeSet<(PathBuf, u32, u32)>,
    project_spans: &mut BTreeSet<(PathBuf, u32, u32)>,
) {
    let projected = project_group_occurrences(group, files);
    if projected.len() < 2 {
        return;
    }

    let mut occurrences = Vec::with_capacity(projected.len());
    for projected_occurrence in projected {
        let file_index = projected_occurrence.file;
        let path = projected_occurrence.path;
        let start_byte = projected_occurrence.start_byte;
        let end_byte = projected_occurrence.end_byte;
        let start_line = projected_occurrence.start_line;
        let end_line = projected_occurrence.end_line;
        per_file_ranges[file_index].insert((start_line, end_line));
        per_file_spans[file_index].insert((start_byte, end_byte));
        project_ranges.insert((path.clone(), start_line, end_line));
        project_spans.insert((path.clone(), start_byte, end_byte));
        occurrences.push(hoonarqube_ir::DuplicateOccurrence {
            path,
            start_byte,
            end_byte,
            start_line,
            end_line,
        });
    }
    output_groups.push(hoonarqube_ir::DuplicateGroup {
        language: language_name(group.language).to_owned(),
        occurrences,
    });
}

fn build_project_metrics(
    files: &[PreparedFile],
    project_ranges: &BTreeSet<(PathBuf, u32, u32)>,
    project_spans: &BTreeSet<(PathBuf, u32, u32)>,
) -> Result<hoonarqube_ir::DuplicationMetrics, String> {
    let total_lines = files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(u64::from(file.lines))
            .ok_or_else(|| "duplication physical line total overflows u64".to_owned())
    })?;
    let mut project_ranges_by_path: BTreeMap<PathBuf, BTreeSet<(u32, u32)>> = BTreeMap::new();
    for (path, start, end) in project_ranges {
        project_ranges_by_path
            .entry(path.clone())
            .or_default()
            .insert((*start, *end));
    }
    let duplicated_lines = project_ranges_by_path
        .values()
        .try_fold(0_u64, |total, ranges| {
            let union = union_line_ranges(ranges)?;
            total
                .checked_add(union)
                .ok_or_else(|| "duplication duplicated line total overflows u64".to_owned())
        })?;
    let duplicated_blocks = u64::try_from(project_spans.len())
        .map_err(|_| "duplication block total overflows u64".to_owned())?;
    let duplicated_files = project_spans
        .iter()
        .map(|(path, _, _)| path)
        .collect::<BTreeSet<_>>()
        .len();
    Ok(duplication_metrics(
        duplicated_lines,
        duplicated_blocks,
        u64::try_from(duplicated_files)
            .map_err(|_| "duplication file total overflows u64".to_owned())?,
        total_lines,
    ))
}

fn build_file_metrics(
    files: &[PreparedFile],
    per_file_ranges: &[BTreeSet<(u32, u32)>],
    per_file_spans: &[BTreeSet<(u32, u32)>],
) -> Result<Vec<hoonarqube_ir::DuplicationFileMetrics>, String> {
    let mut file_metrics = Vec::with_capacity(files.len());
    for (index, file) in files.iter().enumerate() {
        let ranges = &per_file_ranges[index];
        let spans = &per_file_spans[index];
        let duplicated_lines = union_line_ranges(ranges)?;
        let duplicated_blocks = u64::try_from(spans.len())
            .map_err(|_| "duplication block total overflows u64".to_owned())?;
        let duplicated_files = u64::from(!spans.is_empty());
        file_metrics.push(hoonarqube_ir::DuplicationFileMetrics {
            path: file.path.clone(),
            metrics: duplication_metrics(
                duplicated_lines,
                duplicated_blocks,
                duplicated_files,
                u64::from(file.lines),
            ),
        });
    }
    Ok(file_metrics)
}

fn union_line_ranges(ranges: &BTreeSet<(u32, u32)>) -> Result<u64, String> {
    let Some(&(first_start, first_end)) = ranges.iter().next() else {
        return Ok(0);
    };
    let mut current_start = first_start;
    let mut current_end = first_end;
    let mut total = 0_u64;
    for &(start, end) in ranges.iter().skip(1) {
        if start <= current_end.saturating_add(1) {
            current_end = current_end.max(end);
            continue;
        }
        total = total
            .checked_add(inclusive_line_span(current_start, current_end)?)
            .ok_or_else(|| "duplication duplicated line total overflows u64".to_owned())?;
        current_start = start;
        current_end = end;
    }
    total
        .checked_add(inclusive_line_span(current_start, current_end)?)
        .ok_or_else(|| "duplication duplicated line total overflows u64".to_owned())
}

fn inclusive_line_span(start: u32, end: u32) -> Result<u64, String> {
    u64::from(end)
        .checked_sub(u64::from(start))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| "duplication physical line range overflows u64".to_owned())
}

fn duplication_metrics(
    duplicated_lines: u64,
    duplicated_blocks: u64,
    duplicated_files: u64,
    denominator: u64,
) -> hoonarqube_ir::DuplicationMetrics {
    let duplicated_lines_density = if denominator == 0 {
        None
    } else {
        Some((u64_as_f64(duplicated_lines) / u64_as_f64(denominator)) * 100.0)
    };
    hoonarqube_ir::DuplicationMetrics {
        duplicated_lines,
        duplicated_blocks,
        duplicated_files,
        duplicated_lines_density,
    }
}

fn u64_as_f64(value: u64) -> f64 {
    let Ok(high) = u32::try_from(value >> 32) else {
        unreachable!("upper u64 half always fits u32");
    };
    let Ok(low) = u32::try_from(value & u64::from(u32::MAX)) else {
        unreachable!("lower u64 half always fits u32");
    };
    f64::from(high) * 4_294_967_296.0 + f64::from(low)
}

#[cfg(test)]
mod tests {
    use super::{
        DiagonalKey, DuplicationFile, DuplicationOptions, StartInterval, WorkBudget, covered_start,
        detect_duplications, insert_coverage,
    };
    use crate::Language;
    use crate::source_facts::{NormalizedToken, SourceFacts, collect_source_facts};
    use hoonarqube_ir::FileMetrics;
    use std::collections::{BTreeMap, HashMap};
    use std::path::{Path, PathBuf};

    fn facts(
        language: Language,
        symbols: &[&str],
        units: &[(&str, u32, u32)],
        lines: u32,
    ) -> SourceFacts {
        let symbols: Vec<String> = symbols.iter().map(|symbol| (*symbol).to_owned()).collect();
        let tokens = units
            .iter()
            .enumerate()
            .map(|(index, &(symbol, start_line, end_line))| {
                let start_byte = u32::try_from(index).unwrap_or_default().saturating_mul(2);
                NormalizedToken {
                    symbol: u32::try_from(
                        symbols
                            .iter()
                            .position(|value| value.as_str() == symbol)
                            .unwrap_or_default(),
                    )
                    .unwrap_or_default(),
                    start_byte,
                    end_byte: start_byte.saturating_add(1),
                    start_line,
                    end_line,
                }
            })
            .collect();
        SourceFacts {
            metrics: FileMetrics {
                lines,
                code_lines: lines,
                comment_lines: 0,
            },
            tokens,
            units: Vec::new(),
            symbols,
            error: None,
            language,
        }
    }

    fn file(
        path: &str,
        language: Language,
        symbols: &[&str],
        units: &[(&str, u32, u32)],
        lines: u32,
    ) -> DuplicationFile {
        DuplicationFile {
            path: PathBuf::from(path),
            language,
            facts: facts(language, symbols, units, lines),
        }
    }

    fn options(min_tokens: usize, min_lines: u32) -> DuplicationOptions {
        DuplicationOptions {
            min_tokens,
            min_lines,
            min_statements: min_tokens,
            max_tokens: 10_000,
            max_candidate_pairs: 10_000,
        }
    }

    #[test]
    fn thresholds_require_tokens_and_physical_span() {
        let symbols = &["a", "b", "c"];
        let units = &[("a", 1, 1), ("b", 1, 1), ("c", 2, 2)];
        let inputs = vec![
            file("a.py", Language::Python, symbols, units, 2),
            file("b.py", Language::Python, symbols, units, 2),
        ];
        assert!(
            detect_duplications(&inputs, &options(3, 3))
                .expect("detection")
                .groups
                .is_empty()
        );
        assert_eq!(
            detect_duplications(&inputs, &options(3, 2))
                .expect("detection")
                .groups
                .len(),
            1
        );
    }

    #[test]
    fn language_domains_do_not_cross_match() {
        let symbols = &["a", "b"];
        let units = &[("a", 1, 1), ("b", 2, 2)];

        let inputs = vec![
            file("a.js", Language::JavaScript, symbols, units, 2),
            file("b.ts", Language::TypeScript, symbols, units, 2),
        ];
        assert!(
            detect_duplications(&inputs, &options(2, 1))
                .expect("detection")
                .groups
                .is_empty()
        );
    }
    #[test]
    fn keeps_same_line_byte_ranges_and_rejects_duplicate_paths() {
        let symbols = &["a", "b"];
        let units = &[("a", 1, 1), ("b", 1, 1), ("a", 1, 1), ("b", 1, 1)];
        let result = detect_duplications(
            &[file("same.py", Language::Python, symbols, units, 1)],
            &options(2, 1),
        )
        .expect("detection");
        assert_eq!(result.groups.len(), 1);
        assert_eq!(result.groups[0].occurrences.len(), 2);
        assert_eq!(result.groups[0].occurrences[0].start_byte, 0);
        assert_eq!(result.groups[0].occurrences[1].start_byte, 4);
        assert_eq!(result.metrics.duplicated_lines, 1);
        assert_eq!(result.metrics.duplicated_blocks, 2);

        let duplicate = vec![
            file("same.py", Language::Python, symbols, &units[..2], 1),
            file("same.py", Language::Python, symbols, &units[..2], 1),
        ];
        assert!(detect_duplications(&duplicate, &options(2, 1)).is_err());
    }

    #[test]
    fn merges_cross_file_three_copy_group() {
        let symbols = &["a", "b", "c"];
        let units = &[("a", 1, 1), ("b", 2, 2), ("c", 3, 3)];
        let inputs = vec![
            file("a.py", Language::Python, symbols, units, 3),
            file("b.py", Language::Python, symbols, units, 3),
            file("c.py", Language::Python, symbols, units, 3),
        ];
        let result = detect_duplications(&inputs, &options(3, 1)).expect("detection");
        assert_eq!(result.groups.len(), 1);
        assert_eq!(result.groups[0].occurrences.len(), 3);
        assert_eq!(result.metrics.duplicated_lines, 9);
        assert_eq!(result.metrics.duplicated_blocks, 3);
        assert_eq!(result.metrics.duplicated_files, 3);
    }

    #[test]
    fn keeps_same_file_nonidentical_and_overlapping_maximal_ranges() {
        let symbols = &["a", "b", "c", "x"];
        let nonidentical = &[
            ("a", 1, 1),
            ("b", 2, 2),
            ("c", 3, 3),
            ("x", 4, 4),
            ("a", 5, 5),
            ("b", 6, 6),
            ("c", 7, 7),
        ];
        let result = detect_duplications(
            &[file("a.py", Language::Python, symbols, nonidentical, 7)],
            &options(3, 1),
        )
        .expect("detection");
        assert_eq!(result.groups.len(), 1);
        assert_eq!(result.groups[0].occurrences.len(), 2);

        let periodic = &[
            ("a", 1, 1),
            ("b", 2, 2),
            ("c", 3, 3),
            ("a", 4, 4),
            ("b", 5, 5),
            ("c", 6, 6),
            ("a", 7, 7),
            ("b", 8, 8),
            ("c", 9, 9),
        ];
        let result = detect_duplications(
            &[file("periodic.py", Language::Python, symbols, periodic, 9)],
            &options(3, 1),
        )
        .expect("detection");
        assert_eq!(result.groups.len(), 1);
        assert_eq!(result.groups[0].occurrences.len(), 2);
        assert_eq!(result.metrics.duplicated_lines, 9);
        assert_eq!(result.metrics.duplicated_blocks, 2);
    }

    #[test]
    fn coverage_intervals_merge_fragments_with_half_open_endpoints() {
        let diagonal = DiagonalKey {
            file_a: 0,
            file_b: 1,
            delta: 0,
        };
        let other_diagonal = DiagonalKey {
            file_a: 0,
            file_b: 1,
            delta: 1,
        };
        let mut coverage = HashMap::new();
        let mut budget = WorkBudget {
            used: 0,
            limit: usize::MAX,
        };

        for interval in [
            StartInterval { start: 10, end: 12 },
            StartInterval { start: 2, end: 4 },
            StartInterval { start: 7, end: 9 },
        ] {
            insert_coverage(&mut coverage, diagonal, interval, &mut budget)
                .expect("fragment insertion");
        }
        let fragmented = BTreeMap::from([(2, 4), (7, 9), (10, 12)]);
        assert_eq!(coverage.get(&diagonal), Some(&fragmented));
        for &(start, end) in &[(2_usize, 4_usize), (7, 9), (10, 12)] {
            assert!(covered_start(&coverage, diagonal, start, &mut budget).expect("start"));
            assert!(covered_start(&coverage, diagonal, end - 1, &mut budget).expect("end - 1"));
            assert!(!covered_start(&coverage, diagonal, end, &mut budget).expect("end"));
        }

        insert_coverage(
            &mut coverage,
            diagonal,
            StartInterval { start: 4, end: 7 },
            &mut budget,
        )
        .expect("bridge insertion");
        let bridged = BTreeMap::from([(2, 9), (10, 12)]);
        assert_eq!(coverage.get(&diagonal), Some(&bridged));
        assert!(covered_start(&coverage, diagonal, 2, &mut budget).expect("bridge start"));
        assert!(covered_start(&coverage, diagonal, 8, &mut budget).expect("bridge end - 1"));
        assert!(!covered_start(&coverage, diagonal, 9, &mut budget).expect("bridge end"));

        insert_coverage(
            &mut coverage,
            other_diagonal,
            StartInterval { start: 4, end: 6 },
            &mut budget,
        )
        .expect("independent diagonal insertion");
        assert!(covered_start(&coverage, other_diagonal, 4, &mut budget).expect("other start"));
        assert!(covered_start(&coverage, other_diagonal, 5, &mut budget).expect("other end - 1"));
        assert!(!covered_start(&coverage, other_diagonal, 6, &mut budget).expect("other end"));
        assert_eq!(coverage.get(&diagonal), Some(&bridged));

        let mut exhausted = WorkBudget { used: 0, limit: 0 };
        assert!(
            insert_coverage(
                &mut coverage,
                diagonal,
                StartInterval { start: 0, end: 1 },
                &mut exhausted,
            )
            .is_err()
        );
    }

    #[test]
    fn fragmented_same_diagonal_matches_many_runs_within_budget() {
        const RUN_COUNT: usize = 100;
        const RUN_LENGTH: usize = 5;

        let mut symbols = Vec::with_capacity(RUN_COUNT * (RUN_LENGTH + 3));
        let mut run_symbols = Vec::with_capacity(RUN_COUNT);
        let mut separators = Vec::with_capacity(RUN_COUNT);
        for run in 0..RUN_COUNT {
            let mut current_run = Vec::with_capacity(RUN_LENGTH);
            for token in 0..RUN_LENGTH {
                current_run.push(symbols.len());
                symbols.push(format!("run_{run}_{token}"));
            }
            let left_separator = symbols.len();
            symbols.push(format!("left_separator_{run}"));
            let right_separator = symbols.len();
            symbols.push(format!("right_separator_{run}"));
            run_symbols.push(current_run);
            separators.push((left_separator, right_separator));
        }
        let symbol_refs: Vec<&str> = symbols.iter().map(std::string::String::as_str).collect();
        let capacity = RUN_COUNT * (RUN_LENGTH + 1);
        let mut left_units = Vec::with_capacity(capacity);
        let mut right_units = Vec::with_capacity(capacity);
        for run in 0..RUN_COUNT {
            for &symbol in &run_symbols[run] {
                let line = u32::try_from(left_units.len() + 1).expect("line");
                left_units.push((symbol_refs[symbol], line, line));
                right_units.push((symbol_refs[symbol], line, line));
            }
            let line = u32::try_from(left_units.len() + 1).expect("separator line");
            let (left_separator, right_separator) = separators[run];
            left_units.push((symbol_refs[left_separator], line, line));
            right_units.push((symbol_refs[right_separator], line, line));
        }
        let lines = u32::try_from(left_units.len()).expect("fixture line count");
        let mut config = options(3, 1);
        config.max_candidate_pairs = 250;
        let inputs = vec![
            file(
                "fragmented-a.py",
                Language::Python,
                &symbol_refs,
                &left_units,
                lines,
            ),
            file(
                "fragmented-b.py",
                Language::Python,
                &symbol_refs,
                &right_units,
                lines,
            ),
        ];
        let result = detect_duplications(&inputs, &config).expect("fragmented detection");
        assert_eq!(result.groups.len(), RUN_COUNT);
        assert_eq!(
            result.metrics.duplicated_lines,
            u64::try_from(RUN_COUNT * RUN_LENGTH * 2).expect("line total")
        );
        assert_eq!(
            result.metrics.duplicated_blocks,
            u64::try_from(RUN_COUNT * 2).expect("block total")
        );
        assert_eq!(result.metrics.duplicated_files, 2);
    }

    #[test]
    fn java_uses_statement_threshold_without_line_threshold() {
        let symbols = &["if", "body"];
        let units = &[("if", 1, 4), ("body", 5, 8)];
        let inputs = vec![
            file("a.java", Language::Java, symbols, units, 8),
            file("b.java", Language::Java, symbols, units, 8),
        ];
        let mut config = options(100, 100);
        config.min_statements = 2;
        let result = detect_duplications(&inputs, &config).expect("detection");
        assert_eq!(result.groups.len(), 1);
        assert_eq!(result.groups[0].occurrences[0].start_line, 1);
        assert_eq!(result.groups[0].occurrences[0].end_line, 8);
    }

    #[test]
    fn java_barriers_are_fresh_and_statement_count_excludes_wrappers() {
        let symbols = &["statement", "\0barrier:wrapper"];
        let mut units = Vec::new();
        for index in 0_u32..9 {
            let barrier_line = index * 2 + 1;
            let statement_line = barrier_line + 1;
            units.push(("\0barrier:wrapper", barrier_line, barrier_line));
            units.push(("statement", statement_line, statement_line));
        }
        let inputs = vec![
            file("a.java", Language::Java, symbols, &units, 18),
            file("b.java", Language::Java, symbols, &units, 18),
        ];
        let mut config = options(1, 1);
        config.min_statements = 10;
        assert!(
            detect_duplications(&inputs, &config)
                .expect("detection")
                .groups
                .is_empty()
        );
    }

    #[test]
    fn drops_zero_width_projected_occurrences() {
        let symbols = &["a", "b"];
        let units = &[("a", 1, 1), ("b", 2, 2)];
        let mut first = file("zero-a.py", Language::Python, symbols, units, 2);
        let mut second = file("zero-b.py", Language::Python, symbols, units, 2);
        for token in first
            .facts
            .tokens
            .iter_mut()
            .chain(second.facts.tokens.iter_mut())
        {
            token.end_byte = token.start_byte;
        }
        let result = detect_duplications(&[first, second], &options(2, 1)).expect("detection");
        assert!(result.groups.is_empty());
        assert_eq!(result.metrics.duplicated_lines, 0);
        assert_eq!(result.metrics.duplicated_blocks, 0);
        assert_eq!(result.metrics.duplicated_files, 0);
    }

    #[test]
    fn density_and_empty_denominator_are_weighted() {
        let symbols = &["a", "b"];
        let units = &[("a", 1, 1), ("b", 2, 2)];
        let inputs = vec![
            file("a.py", Language::Python, symbols, units, 4),
            file("b.py", Language::Python, symbols, units, 8),
        ];
        let result = detect_duplications(&inputs, &options(2, 1)).expect("detection");
        assert_eq!(
            result.metrics.duplicated_lines_density,
            Some(33.333_333_333_333_33)
        );

        let empty = vec![file("empty.py", Language::Python, &[], &[], 0)];
        let result = detect_duplications(&empty, &options(2, 1)).expect("detection");
        assert_eq!(result.metrics.duplicated_lines, 0);
        assert_eq!(result.metrics.duplicated_lines_density, None);
        assert_eq!(result.files[0].metrics.duplicated_lines_density, None);
    }

    #[test]
    fn repetitive_input_hits_candidate_cap_without_partial_result() {
        let symbols = &["a", "b"];
        let units: Vec<(&str, u32, u32)> = (0..100)
            .map(|index| {
                if index % 2 == 0 {
                    ("a", index + 1, index + 1)
                } else {
                    ("b", index + 1, index + 1)
                }
            })
            .collect();
        let mut config = options(2, 1);
        config.max_candidate_pairs = 4;
        let error = detect_duplications(
            &[file("repeat.py", Language::Python, symbols, &units, 100)],
            &config,
        )
        .expect_err("repetitive input must be bounded");
        assert!(error.contains("limit") || error.contains("work"));
    }

    #[test]
    fn rejects_zero_thresholds_and_budget_overflow() {
        let config = DuplicationOptions {
            min_tokens: 0,
            ..DuplicationOptions::default()
        };
        assert!(config.validate().is_err());
        let config = DuplicationOptions {
            max_candidate_pairs: usize::MAX,
            min_tokens: usize::MAX,
            ..DuplicationOptions::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn java_identical_nested_units_match_at_ten_statements() {
        let body = (0..10)
            .map(|_| "if (x) { foo(); }")
            .collect::<Vec<_>>()
            .join(" ");
        let source = format!("class C {{ void f() {{ {body} }} }}");
        let left = collect_source_facts(Path::new("left.java"), &source).expect("java facts");
        let right = collect_source_facts(Path::new("right.java"), &source).expect("java facts");
        let files = vec![
            DuplicationFile {
                path: PathBuf::from("left.java"),
                language: Language::Java,
                facts: left,
            },
            DuplicationFile {
                path: PathBuf::from("right.java"),
                language: Language::Java,
                facts: right,
            },
        ];
        let result = detect_duplications(&files, &options(10, 1)).expect("java detection");
        let body_start = u32::try_from(source.find(&body).expect("nested statement body"))
            .expect("small fixture offset");
        let body_end = body_start + u32::try_from(body.len()).expect("small fixture body");
        assert!(result.groups.iter().any(|group| {
            group.language == "java"
                && ["left.java", "right.java"].iter().all(|path| {
                    group.occurrences.iter().any(|occurrence| {
                        occurrence.path == Path::new(path)
                            && occurrence.start_byte <= body_start
                            && occurrence.end_byte >= body_end
                    })
                })
        }));
    }

    #[test]
    fn java_different_nested_units_do_not_match_nine_statement_tail() {
        let tail = (0..9)
            .map(|index| format!("int value{index} = {index};"))
            .collect::<Vec<_>>()
            .join(" ");
        let left_source = format!("class C {{ void f() {{ if (x) {{ foo(); }} {tail} }} }}");
        let right_source = format!("class C {{ void f() {{ if (x) {{ bar(); }} {tail} }} }}");
        let left = collect_source_facts(Path::new("left.java"), &left_source).expect("java facts");
        let right =
            collect_source_facts(Path::new("right.java"), &right_source).expect("java facts");
        let files = vec![
            DuplicationFile {
                path: PathBuf::from("left.java"),
                language: Language::Java,
                facts: left,
            },
            DuplicationFile {
                path: PathBuf::from("right.java"),
                language: Language::Java,
                facts: right,
            },
        ];
        let result = detect_duplications(&files, &options(10, 1)).expect("java detection");
        assert!(result.groups.is_empty());
    }
}
