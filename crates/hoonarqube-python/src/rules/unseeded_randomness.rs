use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;

pub(crate) fn check_unseeded_randomness(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut uses_randomness = false;
    let mut seeds_randomness = false;
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if let Some(path) = dotted_name(&call.func) {
            uses_randomness |= random_entry_point(&path);
            seeds_randomness |= seeding_call(&path);
        }
    });
    if uses_randomness && !seeds_randomness {
        return vec![issue_at(
            "python:S6709",
            "Seed the random number generator for reproducible results.",
            TextRange::new(TextSize::new(0), TextSize::new(0)),
            index,
            source,
        )];
    }
    Vec::new()
}

// --- migrated from support/mod.rs (S6709) ---
// --- python:S6709 — unseeded randomness (file-level presence heuristic) ---------------

pub(crate) fn random_entry_point(path: &str) -> bool {
    let random_module = path.starts_with("random.") && path != "random.seed";
    let numpy_random = (path.starts_with("np.random.") || path.starts_with("numpy.random."))
        && !["seed", "default_rng", "Generator", "RandomState"]
            .contains(&path.rsplit('.').next().unwrap_or(""));
    random_module || numpy_random
}

pub(crate) fn seeding_call(path: &str) -> bool {
    path.contains("seed") || path.ends_with("default_rng") || path.ends_with("manual_seed")
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s6709_flags_files_using_unseeded_randomness() {
        let unseeded = scan("import random\nvalue = random.random()\n");
        let found = findings(&unseeded, "python:S6709");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start, pos(1, 0));
        let seeded = scan("random.seed(7)\nvalue = random.random()\n");
        assert!(findings(&seeded, "python:S6709").is_empty());
    }
}
