use super::collectors::{ComplexityWalker, FunctionMetricsCollector};
use crate::support::RuleScope;
use oxc_span::Span;

/// `S3776`: functions exceeding this cognitive complexity are flagged
/// (frozen catalog default of the `threshold` parameter).
const MAX_COGNITIVE_COMPLEXITY: u32 = 15;

/// `S1541`: functions exceeding this cyclomatic complexity are flagged
/// (frozen catalog default of `maximumFunctionComplexityThreshold`).
const MAX_CYCLOMATIC_COMPLEXITY: u32 = 10;

impl FunctionMetricsCollector<'_> {
    /// Emits the threshold findings for one measured unit.
    pub(crate) fn report_complexity(&mut self, walker: &ComplexityWalker, anchor: Span) {
        if walker.cognitive > MAX_COGNITIVE_COMPLEXITY {
            self.sink.emit_span(
                RuleScope::Both,
                "S3776",
                &format!(
                    "Refactor this function to reduce its Cognitive Complexity from {} to the {} allowed.",
                    walker.cognitive, MAX_COGNITIVE_COMPLEXITY
                ),
                anchor,
            );
        }
        if walker.cyclomatic > MAX_CYCLOMATIC_COMPLEXITY {
            self.sink.emit_span(
                RuleScope::Both,
                "S1541",
                &format!(
                    "Function has a complexity of {} which is greater than {} authorized.",
                    walker.cyclomatic, MAX_CYCLOMATIC_COMPLEXITY
                ),
                anchor,
            );
        }
    }
}
