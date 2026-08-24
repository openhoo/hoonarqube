use super::walker::{A11yCollector, SubtreeFacts, jsx_element_tag};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S4084`: audio and video elements need caption tracks.
    pub(crate) fn check_media_captions(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !matches!(tag, "audio" | "video") {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        if !facts.track_captions {
            self.sink.emit_span(
                RuleScope::Both,
                "S4084",
                "Provide captions for this media element with a <track kind=\"captions\"> descendant.",
                element.opening_element.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s4084_flags_video_and_audio_without_captions() {
        let video = jsx_keys("const el = <video src=\"a.mp4\" controls/>;\n");
        assert_eq!(count_key(&video, "javascript:S4084"), 1);

        let audio = jsx_keys("const el = <audio src=\"a.mp3\" controls/>;\n");
        assert_eq!(count_key(&audio, "javascript:S4084"), 1);
    }

    #[test]
    fn s4084_accepts_caption_tracks_anywhere_in_subtree() {
        let captioned = jsx_keys(
            "const el = <video src=\"a.mp4\"><source src=\"a.webm\"/><track kind=\"captions\"/></video>;\n",
        );
        assert_eq!(count_key(&captioned, "javascript:S4084"), 0);
    }

    #[test]
    fn s4084_requires_the_captions_track_kind() {
        let subtitles =
            jsx_keys("const el = <video src=\"a.mp4\"><track kind=\"subtitles\"/></video>;\n");
        assert_eq!(count_key(&subtitles, "javascript:S4084"), 1);
    }
}
