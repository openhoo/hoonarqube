use crate::engine::rx::RxSeq;
use crate::engine::rx::lazy_next_forced_empty;
use ruff_text_size::TextRange;

pub(crate) fn check_rx_lazy_quantifiers(seq: &RxSeq, push: &mut dyn FnMut(&str, &str, TextRange)) {
    for window in seq.items.windows(2) {
        let (lazy, next) = (&window[0], &window[1]);
        let Some(quant) = &lazy.quant else {
            continue;
        };
        if !quant.lazy {
            continue;
        }
        let next_forces_empty = lazy_next_forced_empty(next);
        if next_forces_empty {
            push(
                "python:S6019",
                "This reluctant quantifier is followed by an expression that can match the empty string; it behaves like a greedy quantifier.",
                quant.span,
            );
        }
    }
    // A trailing lazy quantifier at the end of a branch is also pointless.
    if let Some(last) = seq.items.last()
        && last.quant.as_ref().is_some_and(|quant| quant.lazy)
    {
        push(
            "python:S6019",
            "This reluctant quantifier is followed by an expression that can match the empty string; it behaves like a greedy quantifier.",
            last.quant.as_ref().expect("checked").span,
        );
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::regex_finds;

    #[test]
    fn s6019_flags_lazy_quantifiers_before_empty_matches() {
        assert!(regex_finds(
            "import re\nre.match(r'^\\d*?$', s)\n",
            "python:S6019"
        ));
        assert!(regex_finds(
            "import re\nre.sub(r'start\\w*?(end)?', 'x', s)\n",
            "python:S6019"
        ));
        // The sanctioned lazy-terminator idiom is exempt.
        assert!(!regex_finds(
            "import re\nre.sub(r'start\\w*?(end|$)', 'x', s)\n",
            "python:S6019"
        ));
        // Hazards inside group bodies are reported too.
        assert!(regex_finds(
            "import re\nre.match(r'x(?:a*?b?)y', s)\n",
            "python:S6019"
        ));
    }
}
