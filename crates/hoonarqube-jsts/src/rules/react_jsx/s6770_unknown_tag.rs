use super::walker::{ReactCollector, jsx_element_tag, jsx_tag_is_intrinsic};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6770`: lowercase tag names that are neither DOM elements nor
    /// custom elements.
    pub(crate) fn check_unknown_tag(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if jsx_tag_is_intrinsic(tag) && !tag.contains('-') && !HTML_TAG_ALLOWLIST.contains(&tag) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6770",
                "Capitalize this component name; lowercase tags are treated as built-in DOM elements.",
                element.opening_element.name.span(),
            );
        }
    }
}

/// Known intrinsic tag names (`S6770`): HTML plus a common SVG surface.
const HTML_TAG_ALLOWLIST: &[&str] = &[
    "a",
    "abbr",
    "acronym",
    "address",
    "animate",
    "animateMotion",
    "animateTransform",
    "applet",
    "area",
    "article",
    "aside",
    "audio",
    "b",
    "base",
    "basefont",
    "bdi",
    "bdo",
    "big",
    "blockquote",
    "body",
    "br",
    "button",
    "canvas",
    "caption",
    "circle",
    "cite",
    "clipPath",
    "code",
    "col",
    "colgroup",
    "data",
    "datalist",
    "dd",
    "defs",
    "del",
    "desc",
    "details",
    "dfn",
    "dialog",
    "dir",
    "div",
    "dl",
    "dt",
    "ellipse",
    "em",
    "embed",
    "feBlend",
    "feColorMatrix",
    "feComponentTransfer",
    "feComposite",
    "feConvolveMatrix",
    "feDiffuseLighting",
    "feDisplacementMap",
    "feDistantLight",
    "feDropShadow",
    "feFlood",
    "feFuncA",
    "feFuncB",
    "feFuncG",
    "feFuncR",
    "feGaussianBlur",
    "feImage",
    "feMerge",
    "feMergeNode",
    "feMorphology",
    "feOffset",
    "fePointLight",
    "feSpecularLighting",
    "feSpotLight",
    "feTile",
    "feTurbulence",
    "fieldset",
    "figcaption",
    "figure",
    "filter",
    "font",
    "footer",
    "foreignObject",
    "form",
    "frame",
    "frameset",
    "g",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "head",
    "header",
    "hgroup",
    "hr",
    "html",
    "i",
    "iframe",
    "image",
    "img",
    "input",
    "ins",
    "kbd",
    "label",
    "legend",
    "li",
    "line",
    "linearGradient",
    "link",
    "main",
    "map",
    "mark",
    "marker",
    "marquee",
    "mask",
    "menu",
    "menuitem",
    "meta",
    "metadata",
    "meter",
    "mpath",
    "nav",
    "nobr",
    "noframes",
    "noscript",
    "object",
    "ol",
    "optgroup",
    "option",
    "output",
    "p",
    "param",
    "path",
    "pattern",
    "picture",
    "polygon",
    "polyline",
    "pre",
    "progress",
    "q",
    "radialGradient",
    "rect",
    "rp",
    "rt",
    "ruby",
    "s",
    "samp",
    "script",
    "search",
    "section",
    "select",
    "set",
    "slot",
    "small",
    "solidcolor",
    "source",
    "span",
    "stop",
    "strike",
    "strong",
    "style",
    "sub",
    "summary",
    "sup",
    "svg",
    "symbol",
    "table",
    "tbody",
    "td",
    "template",
    "text",
    "textPath",
    "textarea",
    "tfoot",
    "th",
    "thead",
    "time",
    "title",
    "tr",
    "track",
    "tspan",
    "tt",
    "u",
    "ul",
    "use",
    "var",
    "video",
    "view",
    "wbr",
];

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6770_flags_lowercase_unknown_tag() {
        let findings = jsx_keys("const el = <widget></widget>;\n");
        assert_eq!(count_key(&findings, "javascript:S6770"), 1);
    }

    #[test]
    fn s6770_allows_known_intrinsic_tag() {
        let findings = jsx_keys("const el = <div></div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6770"), 0);
    }

    #[test]
    fn s6770_allows_custom_element_with_dash() {
        let findings = jsx_keys("const el = <my-widget></my-widget>;\n");
        assert_eq!(count_key(&findings, "javascript:S6770"), 0);
    }

    #[test]
    fn s6770_allows_capitalized_component_tag() {
        let findings = jsx_keys("const el = <Widget></Widget>;\n");
        assert_eq!(count_key(&findings, "javascript:S6770"), 0);
    }
}
