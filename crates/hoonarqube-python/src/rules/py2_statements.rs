use crate::support::{to_range, to_u32, unmasked_segments};
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{TextRange, TextSize};

const RULE_EXEC: &str = "python:ExecStatementUsage";
const RULE_PRINT: &str = "python:PrintStatementUsage";

/// Python 2 `exec` and `print` statement forms. Ruff intentionally parses as
/// Python 3, so these legacy nodes need a narrow lexical fallback. Masked
/// strings/comments never participate; ordinary Python 3 calls stay exempt.
pub(crate) fn check_py2_statements(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (base, segment) in unmasked_segments(parsed, source) {
        for (keyword, rule, message, bare_is_statement) in [
            ("exec", RULE_EXEC, "Do not use exec statement.", false),
            (
                "print",
                RULE_PRINT,
                "Replace print statement by built-in function.",
                true,
            ),
        ] {
            for (relative, _) in segment.match_indices(keyword) {
                let start = base + relative;
                if is_statement_form(source, start, keyword, bare_is_statement) {
                    let start = TextSize::from(to_u32(start));
                    let end = start + TextSize::from(to_u32(keyword.len()));
                    issues.push(Issue::new(
                        rule,
                        message,
                        to_range(TextRange::new(start, end), index, source),
                    ));
                }
            }
        }
    }
    issues
}

fn is_statement_form(source: &str, start: usize, keyword: &str, bare_is_statement: bool) -> bool {
    let bytes = source.as_bytes();
    let end = start + keyword.len();
    let identifier = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    if start > 0 && identifier(bytes[start - 1]) || end < bytes.len() && identifier(bytes[end]) {
        return false;
    }

    let line_start = source[..start].rfind('\n').map_or(0, |newline| newline + 1);
    let prefix = source[line_start..start].trim_end_matches([' ', '\t', '\r']);
    if !prefix.is_empty() && !prefix.ends_with([';', ':']) {
        return false;
    }

    let mut next = end;
    while next < bytes.len() && matches!(bytes[next], b' ' | b'\t' | b'\r') {
        next += 1;
    }
    if next == bytes.len() || bytes[next] == b'\n' || bytes[next] == b'#' {
        return bare_is_statement;
    }
    !matches!(bytes[next], b'(' | b'=' | b'.' | b'[')
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn exact_legacy_statement_forms_match_sonar_ranges_and_messages() {
        let report = scan("exec 'print 1'\nprint 1\n");
        let exec = findings(&report, "python:ExecStatementUsage");
        let print = findings(&report, "python:PrintStatementUsage");
        assert_eq!(exec.len(), 1);
        assert_eq!(exec[0].message, "Do not use exec statement.");
        assert_eq!(
            (exec[0].range.start.line, exec[0].range.start.column),
            (1, 0)
        );
        assert_eq!((exec[0].range.end.line, exec[0].range.end.column), (1, 4));
        assert_eq!(print.len(), 1);
        assert_eq!(
            print[0].message,
            "Replace print statement by built-in function."
        );
        assert_eq!(
            (print[0].range.start.line, print[0].range.start.column),
            (2, 0)
        );
        assert_eq!((print[0].range.end.line, print[0].range.end.column), (2, 5));
    }

    #[test]
    fn python3_calls_and_assignments_stay_exempt() {
        let report = scan(
            "exec('print 1')\nprint('1')\nexec = callback\nprint = callback\nobj.exec(1)\nobj.print(1)\n",
        );
        assert!(findings(&report, "python:ExecStatementUsage").is_empty());
        assert!(findings(&report, "python:PrintStatementUsage").is_empty());
    }

    #[test]
    fn strings_comments_and_longer_identifiers_stay_exempt() {
        let report =
            scan("text = \"print 1; exec x\"\n# print 1\n# exec x\nprinter = 1\nexecutor = 2\n");
        assert!(findings(&report, "python:ExecStatementUsage").is_empty());
        assert!(findings(&report, "python:PrintStatementUsage").is_empty());
    }

    #[test]
    fn compound_and_semicolon_statements_are_detected() {
        let report = scan("if ready: print value\nx = 1; exec code\nprint >>stream, value\n");
        assert_eq!(findings(&report, "python:PrintStatementUsage").len(), 2);
        assert_eq!(findings(&report, "python:ExecStatementUsage").len(), 1);
    }

    #[test]
    fn bare_print_is_a_statement_but_bare_exec_is_not() {
        let report = scan("print\nexec\n");
        assert_eq!(findings(&report, "python:PrintStatementUsage").len(), 1);
        assert!(findings(&report, "python:ExecStatementUsage").is_empty());
    }
}
