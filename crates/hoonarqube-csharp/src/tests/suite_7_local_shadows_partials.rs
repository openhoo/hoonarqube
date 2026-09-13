//! Same-file cross-partial `cs/local-shadows-member` coverage.
//!
//! The cross-file partial join is covered by `hoonarqube-core`'s project
//! seam test (`csharp_local_shadows_member_joins_partial_declarations_across_files`),
//! because the project index crosses the core boundary.

use crate::analyze_github_quality;

const PAIR_PARTIALS: &str = "public partial class Pair\n{\n    private readonly int cancel;\n}\n\npublic partial class Pair\n{\n    internal void Run(int cancel)\n    {\n        System.Console.Write(cancel);\n    }\n}\n";

#[test]
fn local_shadows_member_reports_across_same_file_partial_declarations() {
    let found = analyze_github_quality(PAIR_PARTIALS);
    let shadows: Vec<_> = found
        .iter()
        .filter(|issue| issue.rule_key == "cs/local-shadows-member")
        .collect();
    assert_eq!(shadows.len(), 1);
    assert_eq!(shadows[0].range.start.line, 8);
    assert_eq!(
        shadows[0].message,
        "Local scope variable 'cancel' shadows $@."
    );
    let location = &shadows[0].flows[0].locations[0];
    assert_eq!(location.message, "Pair.cancel");
    assert_eq!(location.path, None);
    assert_eq!(location.range.start.line, 3);
}
