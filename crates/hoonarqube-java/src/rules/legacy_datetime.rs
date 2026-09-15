//! `java:S2143` — `java.time` classes should be used for dates and times.
//!
//! Contract pinned against the live `SonarQube` 26.8 Community reference
//! (rule show: scope MAIN, INFO `CODE_SMELL`, no parameters; oracle: the
//! pinned `gson` scan with 18 findings). The reference attaches one
//! file-level finding (no text range) to every compilation unit that uses a
//! legacy date/time type: `java.util.Date`, `java.util.Calendar`
//! (including `GregorianCalendar`), or `java.sql.Time`. `java.sql.Timestamp`
//! is explicitly excluded by the reference, and the modern `java.time`
//! family (`LocalDate`, `LocalTime`, `LocalDateTime`, …) never triggers.
//! Comments, string and char literals, and `import` statements do not count
//! as uses.

use crate::support::{node_text, walk_all};
use hoonarqube_ir::{Issue, Range};
use tree_sitter::Node;

/// Legacy type simple names that make a file noncompliant.
const LEGACY_TYPES: [&str; 4] = ["Date", "Calendar", "GregorianCalendar", "Time"];

const MESSAGE: &str = "Use the \"java.time\" API for date and time.";

pub(crate) fn check(root: Node<'_>, source: &str) -> Vec<Issue> {
    let mut used = false;
    walk_all(root, &mut |node: Node<'_>| {
        // Both `type_identifier` (declarations, generics, `.class`) and
        // `identifier` (invocation receivers like `Calendar.getInstance()`,
        // qualified `java.sql.Date` segments) count as a use; imports do not.
        if used || !matches!(node.kind(), "type_identifier" | "identifier") {
            return;
        }
        let text = node_text(node, source);
        if under_import_or_package(node) || !LEGACY_TYPES.contains(&text) {
            return;
        }
        used = true;
    });
    if used {
        vec![Issue::new("java:S2143", MESSAGE, Range::file_level())]
    } else {
        Vec::new()
    }
}

fn under_import_or_package(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "import_declaration" | "package_declaration") {
            return true;
        }
        node = parent;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::parse;

    fn findings(source: &str) -> usize {
        let tree = parse(source).expect("valid Java fixture");
        check(tree.root_node(), source).len()
    }

    #[test]
    fn probe_kinds() {
        let source = "import java.util.Date; class A { Date now; }";
        let tree = crate::context::parse(source).unwrap();
        crate::support::walk_all(tree.root_node(), &mut |n: tree_sitter::Node<'_>| {
            if n.kind().contains("identifier") {
                println!("kind={} text={:?}", n.kind(), node_text(n, source));
            }
        });
    }

    #[test]
    fn legacy_type_use_marks_whole_file() {
        assert_eq!(findings("import java.util.Date; class A { Date now; }"), 1);
        assert_eq!(
            findings("import java.util.Calendar; class A { Object c = Calendar.getInstance(); }"),
            1
        );
        assert_eq!(
            findings("class A { java.sql.Date day; java.sql.Time at; }"),
            1
        );
    }

    #[test]
    fn references_in_comments_strings_and_imports_stay_silent() {
        let source = concat!(
            "import java.util.regex.Pattern;\n",
            "/** uses {@link Date} for docs */\n",
            "class A {\n",
            "  String s = \"Date and Calendar\";\n",
            "  char c = 'T';\n",
            "}\n"
        );
        assert_eq!(findings(source), 0);
    }

    #[test]
    fn timestamp_and_java_time_stay_silent() {
        let source = concat!(
            "import java.sql.Timestamp;\n",
            "import java.time.LocalDate;\n",
            "class A {\n",
            "  Timestamp at = new Timestamp(0);\n",
            "  LocalDate day = LocalDate.now();\n",
            "}\n"
        );
        assert_eq!(findings(source), 0);
    }

    #[test]
    fn issue_is_file_level_with_reference_message() {
        let tree = parse("import java.util.Date; class A { Date now; }").expect("valid Java");
        let issues = check(
            tree.root_node(),
            "import java.util.Date; class A { Date now; }",
        );
        let issue = &issues[0];
        assert_eq!(issue.rule_key, "java:S2143");
        assert_eq!(
            issue.message,
            "Use the \"java.time\" API for date and time."
        );
        assert!(issue.range.is_file_level());
    }
}
