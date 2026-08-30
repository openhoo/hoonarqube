use crate::engine::rx::RxQuant;
use ruff_text_size::TextRange;

pub(crate) fn check_curly_quantifier(
    quant: &RxQuant,
    source: &str,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    if !quant.curly {
        // `*`, `+`, `?` are already the concise forms.
        return;
    }
    let superfluous = quant.max == Some(quant.min) && quant.min <= 1;
    // `{n,n}` is a style improvement over the redundant comma spelling.
    // Bare `{n}` is already the concise form — no suggestion needed.
    let concise = match (quant.min, quant.max) {
        (0, Some(1) | None) | (1, None) => true,
        (min, Some(max)) => min == max && min >= 2 && source[quant.span].contains(','),
        _ => false,
    };
    let finding = match (superfluous, concise) {
        (true, _) => Some(("python:S6396", "Remove this superfluous quantifier.")),
        (false, true) => Some((
            "python:S6353",
            "Use the concise equivalent for this quantifier.",
        )),
        (false, false) => None,
    };
    if let Some((rule, message)) = finding {
        push(rule, message, quant.span);
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, regex_finds, scan};

    #[test]
    fn s6353_flags_redundant_comma_form() {
        assert!(regex_finds(
            "import re\nre.compile(r'a{2,2}b')\n",
            "python:S6353"
        ));
    }

    #[test]
    fn s6353_does_not_fire_on_bare_curly() {
        // Bare `{n}` is already the concise form — no suggestion needed.
        assert!(!regex_finds(
            "import re\nre.compile(r'a{2}b')\n",
            "python:S6353"
        ));
    }

    #[test]
    fn s6353_flags_open_range_forms() {
        assert!(regex_finds(
            "import re\nre.compile(r'a{1,}b')\n",
            "python:S6353"
        ));
        // {0,1} → ? is S6353 (concise equivalent), not S6396.
        assert!(regex_finds(
            "import re\nre.compile(r'a{0,1}b')\n",
            "python:S6353"
        ));
    }

    #[test]
    fn s6396_flags_exact_repeat_single_element() {
        // {1,1} is equivalent to no quantifier at all.
        assert!(regex_finds(
            "import re\nre.compile(r'a{1,1}b')\n",
            "python:S6396"
        ));
    }

    #[test]
    fn s6396_does_not_fire_on_meaningful_quantifiers() {
        assert!(!regex_finds(
            "import re\nre.compile(r'a{2,3}b')\n",
            "python:S6396"
        ));
    }

    #[test]
    fn s6396_does_not_fire_on_concise_forms() {
        assert!(!regex_finds(
            "import re\nre.compile(r'a*b')\n",
            "python:S6396"
        ));
        assert!(!regex_finds(
            "import re\nre.compile(r'a+b')\n",
            "python:S6396"
        ));
        assert!(!regex_finds(
            "import re\nre.compile(r'a?b')\n",
            "python:S6396"
        ));
    }

    #[test]
    fn findings_helper_works() {
        let flagged = scan("import re\nre.compile(r'a{2,2}b')\n");
        let found = findings(&flagged, "python:S6353");
        assert_eq!(found.len(), 1);
    }
}
