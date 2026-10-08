// --- per-rule implementations

use crate::AnalyzerOptions;
use crate::engine::rx::RegexSite;
use crate::engine::rx::RxParsed;
use crate::engine::rx::RxUnit;
use crate::engine::rx::rx_complexity_contributions;
use crate::rules::redundancy_locations;
use crate::rules::rx_repetition_hazards::check_rx_repetition_hazards;
use crate::rules::rx_style_shapes::check_rx_style_shapes;
use crate::rules::rx_syntax_shapes::check_rx_syntax_shapes;
use crate::support::issue_at;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;

pub(crate) fn run_structural_regex_rules(
    parsed: &RxParsed,
    units: &[RxUnit],
    site: &RegexSite,
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let mut push = |key: &str, message: &str, span: TextRange| {
        let span = if key == "python:S6395" && site.verbose {
            TextRange::new(
                span.start(),
                units
                    .iter()
                    .find(|unit| unit.at >= span.end())
                    .map_or(site.content_end, |unit| unit.at),
            )
        } else {
            span
        };
        let mut issue = issue_at(key, message, span, index, source);
        issue.flows = regex_supporting_locations(key, span, parsed, units, site)
            .into_iter()
            .map(|(message, range)| hoonarqube_ir::IssueFlow {
                locations: vec![hoonarqube_ir::FlowLocation::in_primary_file(
                    message,
                    to_range(range, index, source),
                )],
            })
            .collect();
        issues.push(issue);
    };
    check_rx_syntax_shapes(parsed, units, site.verbose, &mut push);
    check_rx_repetition_hazards(parsed, site.match_type, &mut push);
    check_rx_style_shapes(
        parsed,
        source,
        site.verbose,
        options,
        site.opener_range,
        &mut push,
    );
}

fn regex_supporting_locations(
    key: &str,
    primary: TextRange,
    parsed: &RxParsed,
    units: &[RxUnit],
    site: &RegexSite,
) -> Vec<(String, TextRange)> {
    match key {
        "python:S5855" => redundancy_locations(&parsed.root, primary)
            .into_iter()
            .map(|(message, range)| (message.to_owned(), range))
            .collect(),
        "python:S5843" => rx_complexity_contributions(parsed, units, site.content_end)
            .into_iter()
            .map(|(range, amount)| {
                let message = if amount == 1 {
                    "+1".to_owned()
                } else {
                    format!("+{amount} (incl {} for nesting)", amount - 1)
                };
                (message, range)
            })
            .collect(),
        _ => Vec::new(),
    }
}
