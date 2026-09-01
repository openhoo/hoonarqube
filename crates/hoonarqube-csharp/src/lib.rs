//! Tolerant C# analyzer lowering starter-rule findings into `hoonarqube-ir`.
//!
//! The crate parses C# with tree-sitter (always produces a concrete syntax
//! tree, even for broken input) and lowers its checks into
//! [`hoonarqube_ir::FileReport`]s. Rule keys use the repository prefix of the
//! catalog (`csharpsquid:S103`); severity and type always resolve through the
//! frozen `hoonarqube-catalog` catalog via [`hoonarqube_ir::Issue::rule_key`],
//! never duplicated here. Syntax errors emit no issues (no catalog-backed
//! `ParsingError` rule exists for C#), except exact S2306 declaration recovery
//! for valid contextual-keyword identifiers misparsed by tree-sitter.
//!
//! # Documented coverage gaps (INFRA skips)
//!
//! Seven rules of the frozen `csharpsquid` catalog are intentionally not
//! implemented because the analysis infrastructure they require does not
//! exist in this crate; the coverage audit gaps are explained here in code:
//!
//! - `csharpsquid:S110`, `csharpsquid:S1200`, `csharpsquid:S1944`,
//!   `csharpsquid:S3242`, `csharpsquid:S3246`, `csharpsquid:S4047`
//!   (type-lattice and inheritance-coupling checks): detection needs
//!   Roslyn-grade type lattice / inheritance coupling graphs that a
//!   single-pass tree-sitter syntax tree cannot provide.
//! - `csharpsquid:S6802` (Blazor loop lambdas): detection needs a compilation
//!   containing `RenderTreeBuilder` plus semantic invocation binding, which a
//!   single-pass tree-sitter syntax tree cannot provide.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use tree_sitter::Parser;

/// Knobs for the C# analyzer; defaults mirror the frozen catalog
/// `ParameterFact` defaults (`maximumLineLength` default `200` for
/// `csharpsquid:S103`, `maximumFileLocThreshold` default `1000` for
/// `csharpsquid:S104`, the naming formats of `csharpsquid:S2342` and
/// `csharpsquid:S6669`, the `csharpsquid:S1451` header knobs, and the
/// `csharpsquid:S2436` generic-parameter caps `max`/`maxMethod`).
///
/// `header_format` intentionally defaults to empty (rule disabled) instead of
/// the sample template shipped in the catalog, so a default-configured
/// analyzer does not flag every file.
/// The Tier-A structural thresholds (`S107`, `S1151`, `S134`, `S138`,
/// `S1479`, `S1541`, `S1067`, `S3776`) mirror their catalog parameter
/// defaults, as do the Tier-A9 literal-scan knobs (`S1192` duplication
/// threshold, `S2068` credential words, `S6418` secret words and entropy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerOptions {
    pub maximum_line_length: u32,
    /// `csharpsquid:S104` `maximumFileLocThreshold`.
    pub maximum_file_loc_threshold: u32,
    /// `csharpsquid:S1451` `headerFormat`; empty disables the header check.
    pub header_format: String,
    /// `csharpsquid:S1451` `isRegularExpression`. Regular-expression headers
    /// are not evaluated because this analyzer carries no regex engine.
    pub header_is_regular_expression: bool,
    /// `csharpsquid:S2342` `format` (enums without `[Flags]`).
    pub enum_naming_format: String,
    /// `csharpsquid:S2342` `flagsAttributeFormat` (enums with `[Flags]`).
    pub flags_enum_naming_format: String,
    /// `csharpsquid:S6669` logger-name `format`.
    pub logger_name_format: String,
    /// `csharpsquid:S2436` `max`: tolerated type parameters per type.
    pub maximum_generic_parameters_for_types: u32,
    /// `csharpsquid:S2436` `maxMethod`: tolerated type parameters per method.
    pub maximum_generic_parameters_for_methods: u32,
    /// `csharpsquid:S1479` tolerated statements per switch section.
    pub maximum_switch_section_statements: u32,
    /// `csharpsquid:S1151` tolerated lines per switch section.
    pub maximum_switch_section_lines: u32,
    /// `csharpsquid:S134` tolerated control-flow nesting depth.
    pub maximum_nesting_level: u32,
    /// `csharpsquid:S138` tolerated lines per function body.
    pub maximum_function_lines: u32,
    /// `csharpsquid:S107` tolerated parameters per method.
    pub maximum_method_parameters: u32,
    /// `csharpsquid:S1541` cyclomatic complexity threshold.
    pub maximum_function_complexity_threshold: u32,
    /// `csharpsquid:S3776` cognitive complexity threshold for callables.
    pub maximum_cognitive_complexity_threshold: u32,
    /// `csharpsquid:S3776` `propertyThreshold` for accessors.
    pub maximum_accessor_complexity_threshold: u32,
    /// `csharpsquid:S1067` tolerated logical operators per expression.
    pub maximum_logical_operators: u32,
    /// `csharpsquid:S1192` `threshold`: occurrences at which a repeated
    /// string literal is reported.
    pub duplicate_string_threshold: u32,
    /// `csharpsquid:S2068` `credentialWords`; entries match assigned names
    /// case-insensitively as substrings.
    pub credential_words: Vec<String>,
    /// `csharpsquid:S6418` `secretWords`. The catalog default entries are
    /// understood natively; custom entries degrade to substring matches.
    pub secret_words: Vec<String>,
    /// `csharpsquid:S6418` `randomnessSensibility`: distinct character
    /// classes required inside a suspected secret literal.
    pub secret_randomness_sensibility: u32,
}

impl Default for AnalyzerOptions {
    fn default() -> Self {
        Self {
            maximum_line_length: 200,
            maximum_file_loc_threshold: 1000,
            header_format: String::new(),
            header_is_regular_expression: false,
            enum_naming_format: "^([A-Z]{1,3}[a-z0-9]+)*([A-Z]{2})?$".to_string(),
            flags_enum_naming_format: "^([A-Z]{1,3}[a-z0-9]+)*([A-Z]{2})?s$".to_string(),
            logger_name_format: "^_?[Ll]og(ger)?$".to_string(),
            maximum_generic_parameters_for_types: 2,
            maximum_generic_parameters_for_methods: 3,
            maximum_switch_section_statements: 30,
            maximum_switch_section_lines: 8,
            maximum_nesting_level: 3,
            maximum_function_lines: 80,
            maximum_method_parameters: 7,
            maximum_function_complexity_threshold: 10,
            maximum_cognitive_complexity_threshold: 15,
            maximum_accessor_complexity_threshold: 3,
            maximum_logical_operators: 3,
            duplicate_string_threshold: 3,
            credential_words: vec![
                "password".to_string(),
                "passwd".to_string(),
                "pwd".to_string(),
                "passphrase".to_string(),
            ],
            secret_words: vec![
                r"api[_\-]?key".to_string(),
                "auth".to_string(),
                "credential".to_string(),
                "secret".to_string(),
                "token".to_string(),
            ],
            secret_randomness_sensibility: 3,
        }
    }
}

/// Language marker; one variant today, keeps call sites future-proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsLanguage {
    CSharp,
}

impl CsLanguage {
    /// Repository prefix used in issue `rule_key`s (`csharpsquid:S103`).
    #[must_use]
    pub fn prefix(self) -> &'static str {
        "csharpsquid"
    }
}

/// Analyzes one C# source file and lowers every rule finding into a
/// [`hoonarqube_ir::FileReport`] with sorted issues and file metrics.
#[must_use]
pub fn analyze(
    path: PathBuf,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> hoonarqube_ir::FileReport {
    let tree = parse(source);
    let root = tree.root_node();
    let metrics = metrics::file_metrics(root, source);
    if root.has_error() {
        // tree-sitter-c-sharp currently recovers valid contextual-keyword
        // declarations such as `int await` with ERROR nodes. Its declaration
        // names remain exact identifier nodes, so preserve S2306 and the
        // independent file-scope S3903 evidence without running other rules.
        let mut issues =
            rules::modifiers::contextual_keyword_identifiers::check(root, source, language);
        if !issues.is_empty() {
            issues.extend(rules::structure::types_outside_namespaces::check(
                root, source, language,
            ));
        }
        hoonarqube_ir::sort_issues(&mut issues);
        return hoonarqube_ir::FileReport {
            path,
            language: language.prefix().to_string(),
            issues,
            metrics,
        };
    }
    let mut issues = Vec::new();
    issues.extend(rules::text_scans::text_issues(
        root, &path, source, language, options,
    ));
    issues.extend(rules::naming::naming_issues(
        root, source, language, options,
    ));
    issues.extend(rules::modifiers::modifier_issues(
        root, source, language, options,
    ));
    issues.extend(rules::structure::structure_issues(
        root, source, language, options,
    ));
    issues.extend(rules::expressions::expression_issues(
        root, source, language,
    ));
    issues.extend(rules::declaration_contracts::contract_issues(
        root, source, language,
    ));
    issues.extend(rules::literals::literal_content_issues(
        root, source, language, options,
    ));
    issues.extend(rules::usage::usage_heuristic_issues(root, source, language));
    issues.extend(rules::type_members::declaration_contract_issues(
        root, source, language,
    ));
    issues.extend(rules::security::security_deny_list_issues(
        root, source, language,
    ));
    issues.extend(rules::datetime_aspnet::datetime_aspnet_issues(
        root, source, language,
    ));
    issues.extend(rules::logging::logging_issues(
        root, source, language, options,
    ));
    issues.extend(rules::linq_api::linq_api_issues(root, source, language));
    issues.extend(rules::usage_analysis::usage_analysis_issues(
        root, source, language,
    ));
    issues.extend(rules::dataflow::dataflow_cfg_issues(root, source, language));
    issues.extend(rules::api_patterns::framework_api_issues(
        root, source, language,
    ));
    issues.extend(rules::tier_c::tier_c_heuristic_issues(
        root, source, language,
    ));
    hoonarqube_ir::sort_issues(&mut issues);

    hoonarqube_ir::FileReport {
        path,
        language: language.prefix().to_string(),
        issues,
        metrics,
    }
}

/// Runs independently implemented non-Sonar C# rules. Rules requiring a
/// semantic model only emit when the local declaration provides exact type
/// evidence.
#[must_use]
pub fn analyze_native(source: &str) -> Vec<hoonarqube_ir::Issue> {
    let tree = parse(source);
    let root = tree.root_node();
    if root.has_error() {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for invocation in cst::collect_kinds(root, &["invocation_expression"]) {
        let Some(access) = invocation.child_by_field_name("function") else {
            continue;
        };
        if access.kind() != "member_access_expression"
            || !native_result_is_discarded(invocation, source)
        {
            continue;
        }
        let (Some(name), Some(receiver)) = (
            access.child_by_field_name("name"),
            access.child_by_field_name("expression"),
        ) else {
            continue;
        };
        if !matches!(cst::node_text(name, source), "Read" | "ReadAsync") {
            continue;
        }
        let type_evidence = NativeTypeEvidence::collect_for(root, receiver, source);
        let is_known_stream = rules::expressions::resolved_identifier_type(receiver, source)
            .is_some_and(|type_name| type_evidence.is_stream(type_name));
        if is_known_stream {
            issues.push(hoonarqube_ir::Issue::new(
                "hoonarqube-csharp:CA2022",
                "Inspect the returned byte count because a stream read can be partial.",
                cst::range_of(name, source),
            ));
        }
    }
    issues.extend(native_end_of_stream_issues(root, source));
    issues.extend(native_json_element_parse_issues(root, source));
    hoonarqube_ir::sort_issues(&mut issues);
    issues
}

fn native_end_of_stream_issues(
    root: tree_sitter::Node<'_>,
    source: &str,
) -> Vec<hoonarqube_ir::Issue> {
    let mut issues = Vec::new();
    for access in cst::collect_kinds(root, &["member_access_expression"]) {
        let Some(name) = access.child_by_field_name("name") else {
            continue;
        };
        if cst::node_text(name, source) != "EndOfStream" {
            continue;
        }
        let Some(receiver) = access.child_by_field_name("expression") else {
            continue;
        };
        let type_evidence = NativeTypeEvidence::collect_for(root, receiver, source);
        if rules::expressions::resolved_identifier_type(receiver, source)
            .is_none_or(|type_name| !type_evidence.matches(type_name, &["System.IO.StreamReader"]))
        {
            continue;
        }
        let inside_async = rules::expressions::enclosing_callable(access)
            .is_some_and(|callable| native_callable_is_async(callable, source));
        if inside_async {
            issues.push(hoonarqube_ir::Issue::new(
                "hoonarqube-csharp:CA2024",
                "Use ReadLineAsync and test its result instead of EndOfStream.",
                cst::range_of(name, source),
            ));
        }
    }
    issues
}

fn native_json_element_parse_issues(
    root: tree_sitter::Node<'_>,
    source: &str,
) -> Vec<hoonarqube_ir::Issue> {
    let mut issues = Vec::new();
    for access in cst::collect_kinds(root, &["member_access_expression"]) {
        let (Some(name), Some(invocation)) = (
            access.child_by_field_name("name"),
            access.child_by_field_name("expression"),
        ) else {
            continue;
        };
        if cst::node_text(name, source) != "RootElement"
            || invocation.kind() != "invocation_expression"
        {
            continue;
        }
        let Some(parse_access) = invocation.child_by_field_name("function") else {
            continue;
        };
        if parse_access.kind() != "member_access_expression" {
            continue;
        }
        let (Some(parse_name), Some(json_document)) = (
            parse_access.child_by_field_name("name"),
            parse_access.child_by_field_name("expression"),
        ) else {
            continue;
        };
        if cst::node_text(parse_name, source) != "Parse"
            || rules::expressions::resolved_identifier_type(json_document, source).is_some()
        {
            continue;
        }
        let type_evidence = NativeTypeEvidence::collect_for(root, json_document, source);
        if type_evidence.matches(
            cst::node_text(json_document, source),
            &["System.Text.Json.JsonDocument"],
        ) {
            issues.push(hoonarqube_ir::Issue::new(
                "hoonarqube-csharp:CA2026",
                "Use JsonElement.Parse instead of retaining RootElement from a temporary JsonDocument.",
                cst::range_of(name, source),
            ));
        }
    }
    issues
}

#[derive(Default)]
struct NativeTypeEvidence {
    imported_namespaces: HashSet<String>,
    aliases: HashMap<String, String>,
    declared_types: HashSet<String>,
}

impl NativeTypeEvidence {
    fn collect_for(root: tree_sitter::Node<'_>, at: tree_sitter::Node<'_>, source: &str) -> Self {
        let mut evidence = Self::default();
        for declaration in cst::collect_kinds(
            root,
            &[
                "class_declaration",
                "interface_declaration",
                "record_declaration",
                "struct_declaration",
            ],
        ) {
            if let Some(name) = declaration.child_by_field_name("name") {
                evidence
                    .declared_types
                    .insert(cst::node_text(name, source).to_string());
            }
        }
        for using in cst::collect_kinds(root, &["using_directive"]) {
            if !native_using_applies(using, at) {
                continue;
            }
            let compact: String = cst::node_text(using, source)
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect();
            let Some(body) = compact
                .strip_prefix("globalusing")
                .or_else(|| compact.strip_prefix("using"))
                .and_then(|body| body.strip_suffix(';'))
            else {
                continue;
            };
            if body.starts_with("static") {
                continue;
            }
            if let Some((alias, target)) = body.split_once('=') {
                evidence.aliases.insert(
                    alias.to_string(),
                    target.trim_start_matches("global::").to_string(),
                );
            } else {
                evidence
                    .imported_namespaces
                    .insert(body.trim_start_matches("global::").to_string());
            }
        }
        evidence
    }

    fn is_stream(&self, type_name: &str) -> bool {
        self.matches(
            type_name,
            &[
                "System.IO.Stream",
                "System.IO.FileStream",
                "System.IO.MemoryStream",
                "System.IO.BufferedStream",
                "System.Net.Sockets.NetworkStream",
                "System.Security.Cryptography.CryptoStream",
            ],
        )
    }

    fn matches(&self, type_name: &str, full_names: &[&str]) -> bool {
        let compact: String = type_name
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let normalized = compact.trim_end_matches('?').trim_start_matches("global::");
        full_names.iter().any(|full_name| {
            if normalized == *full_name {
                return true;
            }
            if self
                .aliases
                .get(normalized)
                .is_some_and(|target| target == full_name)
            {
                return true;
            }
            let Some((namespace, simple)) = full_name.rsplit_once('.') else {
                return false;
            };
            if let Some((prefix, type_simple)) = normalized.rsplit_once('.') {
                return type_simple == simple
                    && self
                        .aliases
                        .get(prefix)
                        .is_some_and(|target| target == namespace);
            }
            normalized == simple
                && self.imported_namespaces.contains(namespace)
                && !self.declared_types.contains(simple)
                && !self.aliases.contains_key(simple)
        })
    }
}

fn native_using_applies(using: tree_sitter::Node<'_>, at: tree_sitter::Node<'_>) -> bool {
    let owner = std::iter::successors(using.parent(), tree_sitter::Node::parent).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "compilation_unit" | "namespace_declaration" | "file_scoped_namespace_declaration"
        )
    });
    let Some(owner) = owner else {
        return false;
    };
    owner.kind() == "compilation_unit"
        || std::iter::successors(at.parent(), tree_sitter::Node::parent)
            .any(|ancestor| ancestor == owner)
}

fn native_callable_is_async(callable: tree_sitter::Node<'_>, source: &str) -> bool {
    cst::modifiers_of(callable, source).contains(&"async")
        || matches!(
            callable.kind(),
            "lambda_expression" | "anonymous_method_expression"
        ) && callable
            .children(&mut callable.walk())
            .any(|child| cst::node_text(child, source) == "async")
}

fn native_result_is_discarded(mut expression: tree_sitter::Node<'_>, source: &str) -> bool {
    while let Some(parent) = expression.parent() {
        match parent.kind() {
            "expression_statement" => return true,
            "await_expression" | "parenthesized_expression" => expression = parent,
            "assignment_expression"
                if parent.child_by_field_name("left").is_some_and(|left| {
                    cst::node_text(left, source) == "_"
                        && parent
                            .child_by_field_name("operator")
                            .is_some_and(|operator| cst::node_text(operator, source) == "=")
                }) =>
            {
                return true;
            }
            _ => return false,
        }
    }
    false
}

fn parse(source: &str) -> tree_sitter::Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .expect("tree-sitter-c-sharp grammar is compatible");
    parser
        .parse(source, None)
        .expect("parse always yields a tree")
}

mod cst;
mod metrics;
mod rules;
mod symbol_table;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod native_tests {
    use super::analyze_native;

    #[test]
    fn ca2024_requires_async_context_and_exact_stream_reader_type() {
        let bad = analyze_native(concat!(
            "using System.IO;\n",
            "using System.Threading.Tasks;\n",
            "class C {\n",
            "  async Task Read(StreamReader reader) {\n",
            "    while (!reader.EndOfStream) { await reader.ReadLineAsync(); }\n",
            "  }\n",
            "}\n",
        ));
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].rule_key, "hoonarqube-csharp:CA2024");

        for clean in [
            "using System.IO; class C { void Read(StreamReader reader) { if (reader.EndOfStream) {} } }",
            "class Reader { public bool EndOfStream => false; } class C { async void Read(Reader reader) { if (reader.EndOfStream) {} } }",
            "using System; using System.IO; class C { async void Read(StreamReader reader) { Action inspect = () => Console.Write(reader.EndOfStream); } }",
        ] {
            assert!(analyze_native(clean).is_empty(), "{clean}");
        }

        let async_lambda = analyze_native(concat!(
            "using System; using System.IO; using System.Threading.Tasks; class C { ",
            "void Read(StreamReader reader) { Func<Task> inspect = async () => { ",
            "if (reader.EndOfStream) {} await Task.Yield(); }; } }",
        ));
        assert!(
            async_lambda
                .iter()
                .any(|issue| issue.rule_key == "hoonarqube-csharp:CA2024")
        );
    }

    #[test]
    fn ca2022_requires_discarded_result_and_exact_stream_type() {
        let bad = analyze_native(concat!(
            "using System.IO; using System.Threading.Tasks; class C {\n",
            "  void Sync(Stream stream) { stream.Read(buffer, 0, len); }\n",
            "  async Task Async(FileStream stream) { await stream.ReadAsync(buffer); }\n",
            "  void ExplicitDiscard(Stream stream) { _ = stream.Read(buffer, 0, len); }\n",
            "}\n",
        ));
        assert_eq!(
            bad.iter()
                .filter(|issue| issue.rule_key == "hoonarqube-csharp:CA2022")
                .count(),
            3
        );

        for clean in [
            "using System.IO; class C { int M(Stream stream) { return stream.Read(buffer, 0, len); } }",
            "using System.IO; class C { void M(Stream stream) { int count = stream.Read(buffer, 0, len); } }",
            "class Reader { public int Read(byte[] b) => 0; } class C { void M(Reader reader) { reader.Read(buffer); } }",
            "class Stream { public int Read(byte[] b) => 0; } class C { void M(Stream stream) { stream.Read(buffer); } }",
            "using System.IO; class Stream { public int Read(byte[] b) => 0; } class C { void M(Stream stream) { stream.Read(buffer); } }",
        ] {
            assert!(
                !analyze_native(clean)
                    .iter()
                    .any(|issue| issue.rule_key == "hoonarqube-csharp:CA2022"),
                "{clean}"
            );
        }

        let scoped = analyze_native(concat!(
            "using System.IO; class Reader { public int Read(byte[] b) => 0; } class C { ",
            "void StreamUse(Stream value) { value.Read(buffer, 0, len); } ",
            "void CustomUse(Reader value) { value.Read(buffer); } }",
        ));
        assert_eq!(
            scoped
                .iter()
                .filter(|issue| issue.rule_key == "hoonarqube-csharp:CA2022")
                .count(),
            1
        );

        let alias = analyze_native(concat!(
            "using IOStream = System.IO.Stream; class C { ",
            "void Read(IOStream stream) { stream.Read(buffer, 0, len); } }",
        ));
        assert_eq!(
            alias
                .iter()
                .filter(|issue| issue.rule_key == "hoonarqube-csharp:CA2022")
                .count(),
            1,
        );

        let namespace_scope = analyze_native(concat!(
            "namespace Standard { using System.IO; class C { ",
            "void Read(Stream stream) { stream.Read(buffer, 0, len); } } } ",
            "namespace Custom { class C { ",
            "void Read(Stream stream) { stream.Read(buffer, 0, len); } } }",
        ));
        assert_eq!(
            namespace_scope
                .iter()
                .filter(|issue| issue.rule_key == "hoonarqube-csharp:CA2022")
                .count(),
            1,
            "namespace-local imports must not leak type evidence",
        );
    }

    #[test]
    fn ca2026_requires_exact_json_document_parse_root_element_chain() {
        let found = analyze_native(concat!(
            "using System.Text.Json; class C { JsonElement Parse(string json) { ",
            "return JsonDocument.Parse(json).RootElement; } }",
        ));
        assert_eq!(
            found
                .iter()
                .filter(|issue| issue.rule_key == "hoonarqube-csharp:CA2026")
                .count(),
            1,
        );

        let aliases = analyze_native(concat!(
            "using Doc = System.Text.Json.JsonDocument; ",
            "using Json = System.Text.Json; class C { object Parse(string value) { ",
            "var first = Doc.Parse(value).RootElement; ",
            "return Json.JsonDocument.Parse(value).RootElement; } }",
        ));
        assert_eq!(
            aliases
                .iter()
                .filter(|issue| issue.rule_key == "hoonarqube-csharp:CA2026")
                .count(),
            2,
        );

        for clean in [
            "class JsonDocument { public static JsonDocument Parse(string value) => new(); public object RootElement => null; } class C { object M(string value) => JsonDocument.Parse(value).RootElement; }",
            "using System.Text.Json; class C { object M(dynamic JsonDocument, string value) => JsonDocument.Parse(value).RootElement; }",
            "using System.Text.Json; class C { object M(JsonDocument document) => document.RootElement; }",
            "using System.Text.Json; class C { JsonDocument M(string value) => JsonDocument.Parse(value); }",
        ] {
            assert!(
                !analyze_native(clean)
                    .iter()
                    .any(|issue| issue.rule_key == "hoonarqube-csharp:CA2026"),
                "{clean}",
            );
        }
    }
}
