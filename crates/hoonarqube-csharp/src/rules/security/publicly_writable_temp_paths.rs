use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments, invocation_receiver};
use crate::rules::literals::{literal_inner_text, string_literals};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5443 — publicly writable directories let any local user swap
/// the files you just wrote.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const MESSAGE: &str = "Use a directory that is not publicly writable.";
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let value = literal_inner_text(literal, source);
        if is_sensitive_directory(value) {
            issues.push(issue(language, "S5443", MESSAGE, range_of(literal, source)));
        }
    }
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation) {
            continue;
        }
        let is_temp_path = callee_name(invocation, source) == Some("GetTempPath")
            && invocation_receiver(invocation)
                .is_some_and(|receiver| is_framework_type(node_text(receiver, source), "Path"))
            && is_temp_path_assignment(invocation);
        let is_insecure_environment = callee_name(invocation, source)
            == Some("GetEnvironmentVariable")
            && invocation_receiver(invocation).is_some_and(|receiver| {
                is_framework_type(node_text(receiver, source), "Environment")
            })
            && invocation_arguments(invocation)
                .first()
                .map(|argument| actual_argument_expression(*argument))
                .is_some_and(|argument| {
                    matches!(
                        argument.kind(),
                        "string_literal" | "verbatim_string_literal"
                    ) && matches!(
                        literal_inner_text(argument, source)
                            .to_ascii_lowercase()
                            .as_str(),
                        "tmp" | "temp" | "tmpdir"
                    )
                });
        if is_temp_path || is_insecure_environment {
            issues.push(issue(
                language,
                "S5443",
                MESSAGE,
                range_of(invocation, source),
            ));
        }
    }
    issues
}

fn is_framework_type(text: &str, short_name: &str) -> bool {
    matches!(
        (short_name, text.trim()),
        ("Path", "Path" | "System.IO.Path" | "global::System.IO.Path")
            | (
                "Environment",
                "Environment" | "System.Environment" | "global::System.Environment"
            )
    )
}

fn is_sensitive_directory(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase().replace('\\', "/");
    is_windows_temp(&normalized)
        || [
            "/var/tmp",
            "/usr/tmp",
            "/dev/shm",
            "/library/caches",
            "/users/shared",
            "/private/tmp",
            "/private/var/tmp",
            "/dev/mqueue",
            "/run/lock",
            "/var/run/lock",
        ]
        .iter()
        .any(|directory| is_directory_or_child(&normalized, directory))
        || normalized.starts_with("%tmp%/")
        || normalized.starts_with("%temp%/")
        || normalized.starts_with("%tmpdir%/")
        || normalized.starts_with("%userprofile%/appdata/local/temp")
        || normalized == "%tmp%"
        || normalized == "%temp%"
        || normalized == "%tmpdir%"
}

fn is_windows_temp(path: &str) -> bool {
    let rest =
        if path.len() >= 2 && path.as_bytes()[0].is_ascii_lowercase() && path.as_bytes()[1] == b':'
        {
            &path[2..]
        } else if let Some(path) = path.strip_prefix("//") {
            let Some(server_end) = path.find('/') else {
                return false;
            };
            &path[server_end + 1..]
        } else if path.starts_with('/') {
            path
        } else {
            return false;
        };
    let mut segments = rest.split('/').filter(|segment| !segment.is_empty());
    let first = segments.next();
    let candidate = if first == Some("windows") {
        segments.next()
    } else {
        first
    };
    matches!(candidate, Some("temp" | "tmp"))
}

fn is_directory_or_child(path: &str, directory: &str) -> bool {
    path == directory
        || path
            .strip_prefix(directory)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
fn actual_argument_expression(argument: Node<'_>) -> Node<'_> {
    let mut cursor = argument.walk();
    argument
        .named_children(&mut cursor)
        .last()
        .unwrap_or(argument)
}

fn is_temp_path_assignment(invocation: Node<'_>) -> bool {
    matches!(
        invocation.parent().map(|parent| parent.kind()),
        Some(
            "variable_declarator"
                | "assignment_expression"
                | "arrow_expression_clause"
                | "return_statement"
        )
    )
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s5443_flags_the_real_temp_path_source() {
        let report = analyze_default(
            "using System.IO;\n\npublic static class TemporaryOutput\n{\n    public static void Write(string payload)\n    {\n        var root = Path.GetTempPath();\n        var path = Path.Combine(root, \"app-crash.log\");\n        File.WriteAllText(path, payload);\n    }\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S5443");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Use a directory that is not publicly writable."
        );
        assert_eq!(found[0].range.start.line, 7);
        assert_eq!(found[0].range.start.column, 19);
    }

    #[test]
    fn s5443_accepts_application_data_paths_and_random_names() {
        let report = analyze_default(
            "using System;\nusing System.IO;\n\npublic static class TemporaryOutput\n{\n    public static void Write(string payload)\n    {\n        var root = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);\n        var directory = Path.Combine(root, \"Hoonarqube\", \"spool\");\n        Directory.CreateDirectory(directory);\n        var path = Path.Combine(directory, Path.GetRandomFileName());\n        File.WriteAllText(path, payload);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S5443").is_empty());
    }

    #[test]
    fn s5443_keeps_literal_temp_path_coverage() {
        let report =
            analyze_default("class Scratch\n{\n    string Spot() => \"/tmp/build-cache\";\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S5443").len(), 1);
    }
}
