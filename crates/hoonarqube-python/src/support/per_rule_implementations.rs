// --- per-rule implementations

use crate::AnalyzerOptions;
use crate::engine::rx::RxParsed;
use crate::engine::rx::RxUnit;
use crate::rules::rx_repetition_hazards::check_rx_repetition_hazards;
use crate::rules::rx_style_shapes::check_rx_style_shapes;
use crate::rules::rx_syntax_shapes::check_rx_syntax_shapes;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;

pub(crate) fn run_structural_regex_rules(
    parsed: &RxParsed,
    units: &[RxUnit],
    verbose: bool,
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let mut push = |key: &str, message: &str, span: TextRange| {
        issues.push(issue_at(key, message, span, index, source));
    };
    check_rx_syntax_shapes(parsed, units, verbose, &mut push);
    check_rx_repetition_hazards(parsed, &mut push);
    check_rx_style_shapes(parsed, source, verbose, options, &mut push);
}
