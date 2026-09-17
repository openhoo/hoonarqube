use crate::engine::file_context::FileContext;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;

pub(crate) fn check_unseeded_randomness(
    _index: &LineIndex,
    _source: &str,
    _file_ctx: &FileContext,
) -> Vec<Issue> {
    // Sonar's RandomSeedCheck (S6709) targets numpy/sklearn `random_state`
    // parameters via resolved symbols — not a file-level "seed for
    // reproducibility" heuristic. Without symbol resolution the rule
    // cannot fire faithfully, so it stays silent.
    Vec::new()
}
