use crate::AnalyzerOptions;
use crate::engine::rx::RxAtom;
use crate::engine::rx::RxParsed;
use crate::engine::rx::for_each_class;
use crate::engine::rx::for_each_rx_item;
use crate::engine::rx::rx_complexity;
use crate::engine::rx::rx_root_span;
use crate::rules::curly_quantifier::check_curly_quantifier;
use crate::rules::rx_class::check_rx_class;
use ruff_text_size::TextRange;

pub(crate) fn check_rx_style_shapes(
    parsed: &RxParsed,
    verbose: bool,
    options: &AnalyzerOptions,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    let _ = verbose;
    // python:S5843 — overall complexity budget.
    let score = rx_complexity(&parsed.root, 1);
    if score > options.regex_maximum_complexity {
        push(
            "python:S5843",
            "Reduce the complexity of this regular expression.",
            rx_root_span(&parsed.root),
        );
    }
    // python:S5857 — reluctant quantifiers on the wildcard.
    for_each_rx_item(&parsed.root, &mut |item| {
        if matches!(item.atom, RxAtom::Dot) && item.quant.as_ref().is_some_and(|quant| quant.lazy) {
            push(
                "python:S5857",
                "Replace this reluctant quantifier with a negated character class.",
                item.quant.as_ref().expect("checked").span,
            );
        }
        // python:S6396 / python:S6353 — curly-quantifier conciseness.
        if let Some(quant) = &item.quant {
            check_curly_quantifier(quant, push);
        }
    });
    // Class-level checks.
    for_each_class(&parsed.root, &mut |class| {
        check_rx_class(class, push);
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
