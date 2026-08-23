use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use crate::support::random_entry_point;
use crate::support::seeding_call;
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
