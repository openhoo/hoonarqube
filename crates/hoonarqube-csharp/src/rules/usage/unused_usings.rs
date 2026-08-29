use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1128 — using directives whose target segment appears nowhere
/// else in the file import nothing this file uses.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let directives: Vec<Node<'_>> = collect_kinds(root, &["using_directive"])
        .into_iter()
        .filter(|directive| !is_error_tainted(*directive))
        .collect();
    if directives.is_empty() {
        return Vec::new();
    }
    let referenced: std::collections::HashSet<&str> = collect_kinds(root, &["identifier"])
        .into_iter()
        .filter(|identifier| {
            !ancestors_of(*identifier).any(|ancestor| ancestor.kind() == "using_directive")
        })
        .map(|identifier| node_text(identifier, source))
        .collect();
    directives
        .into_iter()
        .filter_map(|directive| {
            let (alias, target) = using_reference_names(directive, source)?;
            let used = referenced.contains(target)
                || alias.is_some_and(|alias| referenced.contains(alias));
            (!used).then_some(directive)
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

/// Alias and last meaningful target segment of a using directive
/// (`using Alias = System.IO.File;` yields `Alias` and `File`).
fn using_reference_names<'a>(
    directive: Node<'_>,
    source: &'a str,
) -> Option<(Option<&'a str>, &'a str)> {
    let text = node_text(directive, source).trim();
    let inner = text.strip_prefix("using")?.trim();
    let inner = inner.strip_prefix("global").map_or(inner, str::trim);
    let inner = inner.strip_prefix("static").map_or(inner, str::trim);
    let inner = inner.strip_suffix(';')?.trim();
    let (alias, target) = match inner.split_once('=') {
        Some((alias, aliased)) => (Some(alias.trim()), aliased.trim()),
        None => (None, inner),
    };
    if target.is_empty() {
        None
    } else {
        Some((
            alias.filter(|alias| !alias.is_empty()),
            target.rsplit('.').next()?,
        ))
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
    fn s1128_keeps_used_aliases() {
        let report = analyze_default(
            "using Repo = Acme.Data.Repository;\nclass C\n{\n    void M()\n    {\n        Repo.Load();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1128").is_empty());
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
    fn s1128_ignores_comment_mentions() {
        let report = analyze_default(
            "using System.Net.Http;\n// Http traffic flows through the gateway.\nclass C\n{\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1128").len(), 1);
    }
}
