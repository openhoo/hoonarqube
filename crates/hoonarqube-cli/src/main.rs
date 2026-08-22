//! Catalog query CLI over the frozen embedded rule catalog.
//!
//! Every subcommand reads exclusively from
//! [`hoonarqube_catalog::embedded`]; no files are read at runtime.

use std::io::Write as _;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use hoonarqube_catalog::{Catalog, RuleRecord, embedded};

/// Embedded languages in canonical audit order: `(catalog name, language id)`.
const LANGUAGE_IDS: [(&str, &str); 4] = [
    ("csharp", "cs"),
    ("javascript", "js"),
    ("typescript", "ts"),
    ("python", "py"),
];

#[derive(Parser)]
#[command(name = "hoonarqube", about = "Hoonarqube analyzer command line")]
struct Cli {
    /// Emit machine-readable JSON instead of human text.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show frozen capture metadata for the embedded catalog.
    Snapshot,
    Rules {
        #[command(subcommand)]
        cmd: RulesCommand,
    },
}

#[derive(Subcommand)]
enum RulesCommand {
    /// List rules of one language, or all languages in canonical order.
    List {
        /// Embedded catalog name (`csharp`) or language id (`cs`).
        #[arg(long)]
        lang: Option<String>,
    },
    /// Case-insensitive substring search over keys, `sys_tags`, and tags.
    Search {
        /// Embedded catalog name (`csharp`) or language id (`cs`).
        #[arg(long)]
        lang: Option<String>,
        query: String,
    },
    /// Show one rule by its full external key (e.g. `python:BackticksUsage`).
    Info { external_key: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let catalog = embedded();
    match &cli.command {
        Command::Snapshot => print_snapshot(catalog, cli.json),
        Command::Rules { cmd } => run_rules(catalog, cmd, cli.json),
    }
}

fn run_rules(catalog: &Catalog, cmd: &RulesCommand, json: bool) -> ExitCode {
    match cmd {
        RulesCommand::List { lang } => match select_language(catalog, lang.as_deref()) {
            Some(languages) => {
                for rule in languages {
                    print_rule_row(rule);
                }
                ExitCode::SUCCESS
            }
            None => unknown_language(lang.as_deref().unwrap_or_default()),
        },
        RulesCommand::Search { lang, query } => {
            let Some(languages) = select_language(catalog, lang.as_deref()) else {
                return unknown_language(lang.as_deref().unwrap_or_default());
            };
            let query_lower = query.to_lowercase();
            let mut printed = false;
            for rule in languages {
                if rule_matches(rule, &query_lower) {
                    print_rule_row(rule);
                    printed = true;
                }
            }
            if !printed {
                println!("no matching rules");
            }
            ExitCode::SUCCESS
        }
        RulesCommand::Info { external_key } => if let Some(rule) = catalog.rule(external_key) {
            if json {
                print_json(rule);
            } else {
                print_rule_info(rule);
            }
            ExitCode::SUCCESS
        } else {
            eprintln!("unknown rule: {external_key}");
            ExitCode::from(1)
        },
    }
}

/// Resolves an optional `--lang` value into the selected rules.
///
/// `None` selects every language in canonical order; a value may be a catalog
/// name or a language id. An unknown value yields `None`.
fn select_language<'a>(
    catalog: &'a Catalog,
    lang: Option<&str>,
) -> Option<Box<dyn Iterator<Item = &'a RuleRecord> + 'a>> {
    match lang {
        None => {
            Some(Box::new(
                catalog.languages().flat_map(|(_, language)| language.rules()),
            ) as Box<dyn Iterator<Item = &'a RuleRecord> + 'a>)
        }
        Some(lang) => {
            let name = LANGUAGE_IDS
                .iter()
                .find(|(_, id)| *id == lang)
                .map_or(lang, |(name, _)| name);
            let rules = catalog.language(name)?;
            Some(Box::new(rules.rules().iter()) as Box<dyn Iterator<Item = &'a RuleRecord> + 'a>)
        }
    }
}



/// Whether the lowercased query occurs in the key, any `sys_tag`, or any tag.
fn rule_matches(rule: &RuleRecord, query_lower: &str) -> bool {
    rule.external_key.to_lowercase().contains(query_lower)
        || rule
            .sys_tags
            .iter()
            .chain(&rule.tags)
            .any(|tag| tag.to_lowercase().contains(query_lower))
}

fn print_snapshot(catalog: &Catalog, json: bool) -> ExitCode {
    let snapshot = catalog.snapshot();
    if json {
        print_json(snapshot);
        return ExitCode::SUCCESS;
    }
    println!("server_version: {}", snapshot.server_version);
    println!("edition: {}", snapshot.edition);
    println!("instance_mode: {}", snapshot.instance_mode);
    println!("captured_at_utc: {}", snapshot.captured_at_utc);
    println!("total_rules: {}", snapshot.total_rules);
    for (name, language) in catalog.languages() {
        println!("  {name}: {} rules", language.len());
    }
    ExitCode::SUCCESS
}

fn print_rule_row(rule: &RuleRecord) {
    println!(
        "{}  {}  {}",
        rule.external_key, rule.severity, rule.rule_type
    );
}

fn print_rule_info(rule: &RuleRecord) {
    println!("{}", rule.external_key);
    println!("  repository: {}", rule.repository);
    println!("  language: {}", rule.language);
    println!("  status: {}", rule.status);
    println!("  severity: {}", rule.severity);
    println!("  rule_type: {}", rule.rule_type);
    println!(
        "  clean_code_attribute: {}",
        rule.clean_code_attribute.as_deref().unwrap_or("-")
    );
    let impacts: Vec<String> = rule
        .impacts
        .iter()
        .map(|impact| format!("{}/{}", impact.software_quality, impact.severity))
        .collect();
    println!("  impacts: {}", impacts.join(", "));
    if !rule.tags.is_empty() {
        println!("  tags: {}", rule.tags.join(", "));
    }
    if !rule.sys_tags.is_empty() {
        println!("  sys_tags: {}", rule.sys_tags.join(", "));
    }
}

fn print_json<T: serde::Serialize>(value: &T) {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer(&mut out, value).expect("serialize catalog data");
    out.write_all(b"\n").expect("write trailing newline");
}

fn unknown_language(value: &str) -> ExitCode {
    eprintln!("unknown language: {value}");
    ExitCode::from(2)
}
