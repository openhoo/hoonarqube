use crate::AnalyzerOptions;
use crate::engine::rx::RxAtom;
use crate::engine::rx::RxParsed;
use crate::engine::rx::for_each_class;
use crate::engine::rx::for_each_rx_item;
use crate::engine::rx::rx_complexity;
use crate::rules::curly_quantifier::check_curly_quantifier;
use crate::rules::rx_class::check_rx_class;
use ruff_text_size::{TextRange, TextSize};

pub(crate) fn check_rx_style_shapes(
    parsed: &RxParsed,
    source: &str,
    verbose: bool,
    options: &AnalyzerOptions,
    pattern_range: TextRange,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    let _ = verbose;
    // python:S5843 — overall complexity budget.
    let score = rx_complexity(&parsed.root, 1);
    if score > options.regex_maximum_complexity {
        push(
            "python:S5843",
            &format!(
                "Simplify this regular expression to reduce its complexity from {score} to the {} allowed.",
                options.regex_maximum_complexity
            ),
            TextRange::at(pattern_range.start(), TextSize::new(1)),
        );
    }
    // python:S5857 — reluctant quantifiers on the wildcard.
    for_each_rx_item(&parsed.root, &mut |item| {
        if matches!(item.atom, RxAtom::Dot)
            && let Some(quant) = item.quant.as_ref().filter(|quant| quant.lazy)
        {
            let next = source[usize::from(item.span.end())..]
                .chars()
                .next()
                .unwrap_or('>');
            let repetition = if quant.min == 0 { '*' } else { '+' };
            push(
                "python:S5857",
                &format!(
                    "Replace this use of a reluctant quantifier with \"[^{next}]{repetition}\"."
                ),
                item.span,
            );
        }
        // python:S6396 / python:S6353 — curly-quantifier conciseness.
        if let Some(quant) = &item.quant {
            check_curly_quantifier(quant, source, push);
        }
    });
    // Class-level checks.
    for_each_class(&parsed.root, &mut |class| {
        check_rx_class(class, source, push);
    });
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::test_support::regex_finds;
    use crate::{AnalyzerOptions, analyze};

    #[test]
    fn s5857_flags_reluctant_wildcard_quantifiers() {
        assert!(regex_finds(
            "import re\nre.compile(r'<.+?>')\n",
            "python:S5857"
        ));
        assert!(!regex_finds(
            "import re\nre.compile(r'<[^>]*>')\n",
            "python:S5857"
        ));
    }

    #[test]
    fn s5843_enforces_the_complexity_budget() {
        let complex = "import re\nre.compile(r'(a|b|c|d|e|f|g|h|i|j)+(k|l|m|n|o|p|q|r|s|t)+(u|v|x|y|z|A|B|C|D|E)+')\n";
        assert!(regex_finds(complex, "python:S5843"));
        assert!(!regex_finds(
            "import re\nre.compile(r'\\d{4}-\\d{2}')\n",
            "python:S5843"
        ));
        // Raising the budget silences the finding.
        let options = AnalyzerOptions {
            regex_maximum_complexity: 500,
            ..AnalyzerOptions::default()
        };
        let report = analyze(PathBuf::from("t.py"), complex, &options);
        assert!(
            report
                .issues
                .iter()
                .all(|issue| issue.rule_key != "python:S5843")
        );
    }
}
