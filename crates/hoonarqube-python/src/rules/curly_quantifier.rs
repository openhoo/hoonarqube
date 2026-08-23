use crate::engine::rx::RxQuant;
use ruff_text_size::TextRange;

pub(crate) fn check_curly_quantifier(quant: &RxQuant, push: &mut dyn FnMut(&str, &str, TextRange)) {
    if !quant.curly {
        // `*`, `+`, `?` are already the concise forms.
        return;
    }
    let superfluous = quant.max == Some(quant.min) && quant.min <= 1;
    let concise = match (quant.min, quant.max) {
        (0, Some(1) | None) | (1, None) => true,
        (min, Some(max)) => min == max && min >= 2,
        _ => false,
    };
    if superfluous {
        push(
            "python:S6396",
            "Remove this superfluous quantifier.",
            quant.span,
        );
    } else if concise {
        push(
            "python:S6353",
            "Use the concise equivalent for this quantifier.",
            quant.span,
        );
    }
}
