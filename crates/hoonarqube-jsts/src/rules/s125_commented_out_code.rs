// Rule module s125_commented_out_code (generated).

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, ScannedComment, source_slice};
use hoonarqube_ir::Issue;

/// `S125`: heuristics for comments that look like commented-out code:
/// statement keyword starts, a trailing `;` with an assignment or call, or
/// balanced non-empty braces plus a `;`.
fn check_commented_out_code(
    sink: &mut IssueSink,
    comment: ScannedComment,
    body: &str,
    source: &str,
) {
    // `/** … */` doc comments are documentation, not commented-out code —
    // JSDoc `@typedef {{ … }}` blocks carry braces and semicolons that the
    // code heuristic would otherwise mistake for a block.
    if source_slice(source, comment.token).starts_with("/**") {
        return;
    }
    if !looks_like_code(body) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S125",
        "Remove this commented out code.",
        comment.token,
    );
}

fn looks_like_code(body: &str) -> bool {
    let trimmed = body.trim();
    if trimmed.len() < 4
        || ["TODO", "FIXME", "NOSONAR"]
            .iter()
            .any(|tag| trimmed.contains(tag))
    {
        return false;
    }
    let first_word = trimmed
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '$')
        .find(|word| !word.is_empty());
    if let Some(word) = first_word {
        if matches!(word, "import" | "export") {
            // `import`/`export` also open prose ("import (lib + typings)
            // are vendored"); only statement-shaped text counts.
            if looks_like_module_statement(trimmed, word) {
                return true;
            }
        } else if CODE_START_KEYWORDS.contains(&word) {
            return true;
        }
    }
    if trimmed.ends_with(';') && (trimmed.contains('=') || trimmed.contains('(')) {
        return true;
    }
    trimmed.matches('{').count() == trimmed.matches('}').count()
        && trimmed.contains('{')
        && trimmed.contains(';')
}

/// Whether `import …`/`export …` comment text is shaped like a module
/// statement rather than prose: `import "m"`, `import {x} from "m"`,
/// `import x from "m"`, `export {x}`, `export * from "m"`, or a
/// declaration keyword after `export`.
fn looks_like_module_statement(trimmed: &str, keyword: &str) -> bool {
    let rest = trimmed[keyword.len()..].trim_start();
    if keyword == "export" {
        return rest.starts_with(['{', '*'])
            || [
                "default",
                "const",
                "let",
                "var",
                "function",
                "class",
                "async",
                "type",
                "interface",
                "enum",
                "import",
                "export",
            ]
            .iter()
            .any(|decl| rest.starts_with(decl));
    }
    if rest.starts_with(['{', '*', '"', '\'']) {
        return true;
    }
    // `import <binding> from "m"` — require `from` followed by a quote so
    // prose like "import (lib + typings)" does not count.
    let mut words = rest.split_whitespace();
    while let Some(word) = words.next() {
        if word == "from" {
            return words.next().is_some_and(|w| w.starts_with(['"', '\'']));
        }
        if let Some(quoted) = word.strip_prefix("from") {
            return quoted.starts_with(['"', '\'']);
        }
    }
    false
}

/// Keywords whose comment prefix suggests commented-out code for `S125`.
const CODE_START_KEYWORDS: [&str; 9] = [
    "if", "for", "while", "switch", "var", "let", "const", "function", "return",
];

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    for &comment in &ctx.comments {
        let body = source_slice(ctx.source, comment.body);
        check_commented_out_code(&mut sink, comment, body, ctx.source);
    }
    sink.issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn commented_out_code_heuristic_flags_keyword_comments() {
        let flagged = js_keys("// return value;\n");
        assert_eq!(count_key(&flagged, "javascript:S125"), 1);

        let prose = js_keys("// this comment only explains things\n");
        assert_eq!(count_key(&prose, "javascript:S125"), 0);
    }
    #[test]
    fn commented_out_code_detects_semicolon_and_block_shapes() {
        let assignment = js_keys("// let total = compute(a, b);\n");
        assert_eq!(count_key(&assignment, "javascript:S125"), 1);

        let call = js_keys("// renderChart(data);\n");
        assert_eq!(count_key(&call, "javascript:S125"), 1);

        let block = js_keys("// { cleanup(); }\n");
        assert_eq!(count_key(&block, "javascript:S125"), 1);
    }

    #[test]
    fn commented_out_code_spares_tag_comments_even_if_code_like() {
        let tagged = js_keys("// FIXME: draw(x);\n");
        assert_eq!(count_key(&tagged, "javascript:S125"), 0);
    }

    #[test]
    fn commented_out_code_spares_jsdoc_typedefs_and_import_prose() {
        // #544: JSDoc typedef blocks are documentation, not commented code.
        let typedef = js_keys(
            "/**\n * @typedef {Object} ModuleOptions\n * @property {string} name\n * @property {number} [level]\n */\nfunction configure(options) { return options; }\n",
        );
        assert_eq!(count_key(&typedef, "javascript:S125"), 0);

        // Prose starting with `import`/`export` is not an import statement.
        let prose = js_keys("// import of the module happens lazily\n");
        assert_eq!(count_key(&prose, "javascript:S125"), 0);

        // A real commented-out import still flags.
        let commented_import = js_keys("// import { readFile } from \"fs\";\n");
        assert_eq!(count_key(&commented_import, "javascript:S125"), 1);
    }
}
