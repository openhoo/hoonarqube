use super::support::count_word_occurrences;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1128 — using directives whose target segment appears nowhere
/// else in the file import nothing this file uses.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let directives = collect_kinds(root, &["using_directive"]);
    if directives.is_empty() {
        return Vec::new();
    }
    // Blank every directive (back to front keeps earlier offsets valid)
    // before counting references in the remainder.
    let mut body = source.to_string();
    for directive in directives.iter().rev() {
        let range = directive.byte_range();
        let length = range.end - range.start;
        body.replace_range(range, &" ".repeat(length));
    }
    directives
        .into_iter()
        .filter_map(|directive| {
            let segment = using_target_segment(directive, source)?;
            (count_word_occurrences(&body, segment) == 0).then_some(directive)
        })
        .map(|directive| {
            issue(
                language,
                "S1128",
                "Remove this unnecessary 'using'.",
                range_of(directive, source),
            )
        })
        .collect()
}

/// Last meaningful name segment of a using directive's target
/// (`using Alias = System.IO.File;` → `File`).
fn using_target_segment<'a>(directive: Node<'_>, source: &'a str) -> Option<&'a str> {
    let text = node_text(directive, source).trim();
    let inner = text.strip_prefix("using")?.trim();
    let inner = inner.strip_prefix("global").map_or(inner, str::trim);
    let inner = inner.strip_prefix("static").map_or(inner, str::trim);
    let inner = inner.strip_suffix(';')?.trim();
    let target = match inner.split_once('=') {
        Some((_, aliased)) => aliased.trim(),
        None => inner,
    };
    if target.is_empty() {
        None
    } else {
        target.rsplit('.').next()
    }
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1128_flags_each_segment_even_when_directives_share_it() {
        let report = analyze_default("using A.Tools;\nusing B.Tools;\nclass C\n{\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S1128").len(), 2);
    }

    #[test]
    fn s1128_flags_alias_targets_never_spelled_out() {
        let report = analyze_default(
            "using Repo = Acme.Data.Repository;\nclass C\n{\n    void M()\n    {\n        Repo.Load();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1128").len(), 1);
    }

    #[test]
    fn s1128_keeps_segments_written_at_call_sites() {
        let report = analyze_default(
            "using System.IO;\nclass C\n{\n    string M()\n    {\n        return System.IO.File.ReadAllText(\"x\");\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1128").is_empty());
    }

    #[test]
    fn s1128_audits_directives_nested_in_namespaces() {
        let report = analyze_default(
            "namespace N\n{\n    using System.Linq;\n    class C\n    {\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1128").len(), 1);
    }

    #[test]
    fn s1128_leaves_global_usings_untouched() {
        let report = analyze_default("global using System.Threading;\nclass C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S1128").is_empty());
    }

    #[test]
    fn s1128_treats_comment_mentions_as_references() {
        let report = analyze_default(
            "using System.Net.Http;\n// Http traffic flows through the gateway.\nclass C\n{\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1128").is_empty());
    }
}
