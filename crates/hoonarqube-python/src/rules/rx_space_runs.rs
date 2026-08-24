use crate::engine::rx::RxAtom;
use crate::engine::rx::RxItem;
use crate::engine::rx::RxSeq;
use crate::engine::rx::flush_space_run;
use ruff_text_size::TextRange;

pub(crate) fn check_rx_space_runs(seq: &RxSeq, push: &mut dyn FnMut(&str, &str, TextRange)) {
    let mut run: Vec<&RxItem> = Vec::new();
    for item in &seq.items {
        if matches!(item.atom, RxAtom::Literal(' ')) && item.quant.is_none() {
            run.push(item);
        } else {
            flush_space_run(&run, push);
            run.clear();
        }
    }
    flush_space_run(&run, push);
}

#[cfg(test)]
mod tests {

    use crate::test_support::regex_finds;

    #[test]
    fn s6326_flags_multiple_spaces_unless_verbose_flag_set() {
        assert!(regex_finds(
            "import re\nre.compile(r'Hello,   world!')\n",
            "python:S6326"
        ));
        assert!(!regex_finds(
            "import re\nre.compile(r'Hello,   world!', re.X)\n",
            "python:S6326"
        ));
        assert!(!regex_finds(
            "import re\nre.compile(r'Hello world!')\n",
            "python:S6326"
        ));
    }
}
