use std::collections::{HashMap, HashSet};

use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, FStringPart, InterpolatedStringElement, Operator, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const RULE_KEY: &str = "python:S8554";
const EAGER_FORMAT_MESSAGE: &str =
    "Pass formatting arguments to the logging call instead of pre-formatting the message string.";
const DEPRECATED_WARN_MESSAGE: &str = "Use \"warning\" instead of the deprecated \"warn\" method.";
const EXTRA_COLLISION_MESSAGE: &str =
    "Remove or rename this key; it overrides a built-in LogRecord attribute.";

/// Logging methods the reference matches on `logging` and `logging.Logger`
/// (`logging.log` and `logging.LoggerAdapter` are not part of the set).
const LOGGING_METHODS: &[&str] = &[
    "debug",
    "info",
    "warning",
    "warn",
    "error",
    "exception",
    "critical",
];

/// Built-in `LogRecord` attributes that `extra=` keys must not shadow.
const LOG_RECORD_ATTRIBUTES: &[&str] = &[
    "name",
    "msg",
    "args",
    "created",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "thread",
    "threadName",
    "exc_info",
    "exc_text",
    "stack_info",
    "taskName",
    "asctime",
];

/// Which logging owner a call resolves to.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoggingOwner {
    /// `logging.<method>` — the module-level function.
    Module,
    /// `<logger>.<method>` — a `logging.Logger` instance.
    Logger,
    /// `<adapter>.<method>` — a `logging.LoggerAdapter` instance.
    Adapter,
}

/// Per-file logging provenance: import bindings plus names assigned a
/// `logging.getLogger(...)` or `logging.LoggerAdapter(...)` result.
pub(crate) struct LoggingFacts {
    /// Local name → dotted path it was imported from (`log` → `logging`,
    /// `info` → `logging.info`, `cfg` → `logging.config`).
    imports: HashMap<String, String>,
    /// Names bound to a `logging.getLogger(...)` call.
    logger_names: HashSet<String>,
    /// Names bound to a `logging.LoggerAdapter(...)` call.
    adapter_names: HashSet<String>,
}

impl LoggingFacts {
    pub(crate) fn build(file_ctx: &FileContext) -> Self {
        let mut facts = Self {
            imports: HashMap::new(),
            logger_names: HashSet::new(),
            adapter_names: HashSet::new(),
        };
        for entry in &file_ctx.imports {
            facts.record_import(entry);
        }
        for stmt in &file_ctx.stmts {
            facts.record_assignment(stmt);
        }
        facts
    }

    fn record_import(&mut self, entry: &AnyImport<'_>) {
        match entry {
            AnyImport::Plain(import) => {
                for alias in &import.names {
                    let full = alias.name.as_str();
                    if !(full == "logging" || full.starts_with("logging.")) {
                        continue;
                    }
                    let bound = alias.asname.as_ref().map_or_else(
                        || full.split('.').next().unwrap_or_default(),
                        |name| name.as_str(),
                    );
                    // `import logging.config` binds `logging` itself, so the
                    // unaliased path stays the top-level package name.
                    let path = if alias.asname.is_some() { full } else { bound };
                    self.imports.insert(bound.to_string(), path.to_string());
                }
            }
            AnyImport::From(import) => {
                if import.level != 0
                    || import
                        .module
                        .as_ref()
                        .is_none_or(|module| module.as_str() != "logging")
                {
                    return;
                }
                for alias in &import.names {
                    let bound = alias
                        .asname
                        .as_ref()
                        .map_or(alias.name.as_str(), |name| name.as_str());
                    self.imports.insert(
                        bound.to_string(),
                        format!("logging.{}", alias.name.as_str()),
                    );
                }
            }
        }
    }

    fn record_assignment(&mut self, stmt: &Stmt) {
        let (targets, value) = match stmt {
            Stmt::Assign(assign) => (assign.targets.as_slice(), Some(assign.value.as_ref())),
            Stmt::AnnAssign(assign) => (
                std::slice::from_ref(assign.target.as_ref()),
                assign.value.as_deref(),
            ),
            _ => return,
        };
        let Some(Expr::Call(call)) = value else {
            return;
        };
        let Some(path) = self.resolved_path(&call.func) else {
            return;
        };
        let names = match path.as_str() {
            "logging.getLogger" => &mut self.logger_names,
            "logging.LoggerAdapter" => &mut self.adapter_names,
            _ => return,
        };
        for target in targets {
            if let Expr::Name(name) = target {
                names.insert(name.id.to_string());
            }
        }
    }

    /// Resolves a name or attribute chain through the file's logging
    /// imports; `None` when the root is not a logging-bound name.
    pub(crate) fn resolved_path(&self, expr: &Expr) -> Option<String> {
        let mut segments = Vec::new();
        let mut cursor = expr;
        loop {
            match cursor {
                Expr::Name(name) => {
                    segments.push(name.id.as_str());
                    break;
                }
                Expr::Attribute(attribute) => {
                    segments.push(attribute.attr.as_str());
                    cursor = &attribute.value;
                }
                _ => return None,
            }
        }
        let root = segments.pop()?;
        let base = self.imports.get(root)?;
        let mut path = base.clone();
        for segment in segments.iter().rev() {
            path.push('.');
            path.push_str(segment);
        }
        Some(path)
    }

    /// `(owner, method)` when the callee is one of the reference's logging
    /// call shapes: `logging.<method>`, `logging.Logger.<method>`, or a
    /// `getLogger`/`LoggerAdapter` receiver's `<method>`.
    pub(crate) fn logging_method(&self, call: &ExprCall) -> Option<(LoggingOwner, String)> {
        match call.func.as_ref() {
            Expr::Name(_) => {
                let path = self.resolved_path(&call.func)?;
                let method = path.strip_prefix("logging.")?;
                (!method.contains('.')).then_some((LoggingOwner::Module, method.to_string()))
            }
            Expr::Attribute(attribute) => {
                if let Some(path) = self.resolved_path(&call.func) {
                    for (prefix, owner) in [
                        ("logging.LoggerAdapter.", LoggingOwner::Adapter),
                        ("logging.Logger.", LoggingOwner::Logger),
                        ("logging.", LoggingOwner::Module),
                    ] {
                        if let Some(method) = path.strip_prefix(prefix)
                            && !method.contains('.')
                        {
                            return Some((owner, method.to_string()));
                        }
                    }
                }
                self.instance_owner(&attribute.value)
                    .map(|owner| (owner, attribute.attr.as_str().to_string()))
            }
            _ => None,
        }
    }

    /// Owner of a receiver expression bound to a logger or adapter: a name
    /// assigned `logging.getLogger(...)`/`logging.LoggerAdapter(...)`, or
    /// one of those calls inline.
    fn instance_owner(&self, receiver: &Expr) -> Option<LoggingOwner> {
        match receiver {
            Expr::Name(name) => {
                if self.logger_names.contains(name.id.as_str()) {
                    Some(LoggingOwner::Logger)
                } else if self.adapter_names.contains(name.id.as_str()) {
                    Some(LoggingOwner::Adapter)
                } else {
                    None
                }
            }
            Expr::Call(call) => match self.resolved_path(&call.func).as_deref() {
                Some("logging.getLogger") => Some(LoggingOwner::Logger),
                Some("logging.LoggerAdapter") => Some(LoggingOwner::Adapter),
                _ => None,
            },
            _ => None,
        }
    }
}

/// python:S8554 — logging calls should use lazy `%`-style arguments instead
/// of pre-formatted strings, `warning` instead of the deprecated `warn`,
/// and `extra=` keys that do not collide with built-in `LogRecord`
/// attributes. The reference matches `logging.<method>` and
/// `logging.Logger.<method>` calls (`debug`, `info`, `warning`, `warn`,
/// `error`, `exception`, `critical`); eager formatting is checked on the
/// first positional argument only: f-strings with interpolations,
/// `str.format(...)` calls, `%` formatting on a string literal, and `+`
/// concatenation containing a string literal.
pub(crate) fn check_logging_best_practices(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = LoggingFacts::build(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Some((owner, method)) = facts.logging_method(call) else {
            continue;
        };
        // The reference's call matcher covers `logging.*` and
        // `logging.Logger.*` only; `LoggerAdapter` calls are out of scope.
        if owner == LoggingOwner::Adapter || !LOGGING_METHODS.contains(&method.as_str()) {
            continue;
        }
        if method == "warn" {
            issues.push(issue_at(
                RULE_KEY,
                DEPRECATED_WARN_MESSAGE,
                call.func.range(),
                index,
                source,
            ));
        }
        if let Some(first) = call
            .arguments
            .args
            .iter()
            .find(|arg| !matches!(arg, Expr::Starred(_)))
        {
            check_eager_formatting(first, file_ctx, index, source, &mut issues);
        }
        check_extra_collision(call, index, source, &mut issues);
    }
    issues
}

/// Flags the first positional argument when it pre-formats the message:
/// an interpolated f-string, a `str.format(...)` call, `%` formatting with
/// a string literal on the left, or `+` concatenation containing a string
/// literal anywhere in the chain.
fn check_eager_formatting(
    expr: &Expr,
    file_ctx: &FileContext,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let eager = match expr {
        Expr::FString(f_string) => f_string.value.iter().any(|part| {
            matches!(part, FStringPart::FString(inner) if inner
                .elements
                .iter()
                .any(|element| matches!(element, InterpolatedStringElement::Interpolation(_))))
        }),
        Expr::Call(call) => is_str_format_call(call, file_ctx),
        Expr::BinOp(binary) => match binary.op {
            Operator::Mod => contains_string_literal(&binary.left),
            Operator::Add => contains_string_literal(expr),
            _ => false,
        },
        _ => false,
    };
    if eager {
        issues.push(issue_at(
            RULE_KEY,
            EAGER_FORMAT_MESSAGE,
            expr.range(),
            index,
            source,
        ));
    }
}

/// Whether the call is `str.format(...)`: a `.format` attribute call on a
/// provably `str` receiver (a string or f-string literal, a `str(...)`
/// call, or a name assigned exactly one of those).
fn is_str_format_call(call: &ExprCall, file_ctx: &FileContext) -> bool {
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return false;
    };
    attribute.attr.as_str() == "format" && receiver_is_known_str(&attribute.value, file_ctx)
}

/// Whether the receiver provably holds a `str`: a string or f-string
/// literal, a `str(...)` call, or a name whose single assignment in the
/// file is one of those.
fn receiver_is_known_str(receiver: &Expr, file_ctx: &FileContext) -> bool {
    let name = match receiver {
        Expr::StringLiteral(_) | Expr::FString(_) => return true,
        Expr::Call(call) => {
            return matches!(call.func.as_ref(), Expr::Name(n) if n.id.as_str() == "str");
        }
        Expr::Name(name) => name.id.as_str(),
        _ => return false,
    };
    let mut found: Option<&Expr> = None;
    for stmt in &file_ctx.stmts {
        let Stmt::Assign(assign) = stmt else {
            continue;
        };
        let [Expr::Name(target)] = assign.targets.as_slice() else {
            continue;
        };
        if target.id.as_str() != name {
            continue;
        }
        if found.is_some() {
            return false;
        }
        found = Some(assign.value.as_ref());
    }
    matches!(found, Some(Expr::StringLiteral(_) | Expr::FString(_)))
        || matches!(found, Some(Expr::Call(call)) if matches!(call.func.as_ref(), Expr::Name(n) if n.id.as_str() == "str"))
}

/// Whether the expression contains a string literal, recursing through `+`
/// concatenation like the reference's `containsStringLiteral`.
fn contains_string_literal(expr: &Expr) -> bool {
    match expr {
        Expr::StringLiteral(_) | Expr::FString(_) => true,
        Expr::BinOp(binary) if binary.op == Operator::Add => {
            contains_string_literal(&binary.left) || contains_string_literal(&binary.right)
        }
        _ => false,
    }
}

/// Flags `extra={...}` dict-literal keys that collide with built-in
/// `LogRecord` attributes; each colliding string-literal key anchors its
/// own finding.
fn check_extra_collision(
    call: &ExprCall,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let Some(Expr::Dict(dict)) = keyword_value(&call.arguments, "extra") else {
        return;
    };
    for item in &dict.items {
        let Some(key) = &item.key else {
            continue;
        };
        if string_literal_text(key)
            .is_some_and(|text| LOG_RECORD_ATTRIBUTES.contains(&text.as_str()))
        {
            issues.push(issue_at(
                RULE_KEY,
                EXTRA_COLLISION_MESSAGE,
                key.range(),
                index,
                source,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8554")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8554_flags_sonar_eager_formatting_examples() {
        // Sonar's own Noncompliant examples: f-string, .format(), %
        // operator, and + concatenation on the first positional argument.
        let flagged = found(concat!(
            "import logging\n",
            "user = \"Maria\"\n",
            "logging.info(f\"{user} - Something happened\")\n",
            "logging.info(\"{} - Something happened\".format(user))\n",
            "logging.info(\"%s - Something happened\" % user)\n",
            "logging.info(user + \" - Something happened\")\n",
        ));
        assert_eq!(flagged.len(), 4);
        assert!(
            flagged.iter().all(|issue| issue.message
                == "Pass formatting arguments to the logging call instead of pre-formatting the message string.")
        );
        assert_eq!(flagged[0].range.start, pos(3, 13));
        assert_eq!(flagged[0].range.end, pos(3, 43));
    }

    #[test]
    fn s8554_accepts_sonar_compliant_lazy_formatting() {
        let clean = found(concat!(
            "import logging\n",
            "user = \"Maria\"\n",
            "logging.info(\"%s - Something happened\", user)\n",
            "logging.info(\"plain message\")\n",
            "logging.info(f\"constant text\")\n",
            "logging.info(msg=\"%s\", args=(user,))\n",
        ));
        assert!(clean.is_empty());
    }

    #[test]
    fn s8554_flags_deprecated_warn_on_module_and_logger() {
        let flagged = found(concat!(
            "import logging\n",
            "logger = logging.getLogger(__name__)\n",
            "logging.warn(\"module\")\n",
            "logger.warn(\"instance\")\n",
        ));
        assert_eq!(flagged.len(), 2);
        assert!(
            flagged.iter().all(|issue| issue.message
                == "Use \"warning\" instead of the deprecated \"warn\" method.")
        );
        // The callee anchors the finding.
        assert_eq!(flagged[0].range.start, pos(3, 0));
        assert_eq!(flagged[0].range.end, pos(3, 12));
    }

    #[test]
    fn s8554_flags_extra_collisions_per_key() {
        let flagged = found(concat!(
            "import logging\n",
            "logger = logging.getLogger(__name__)\n",
            "logging.info(\"msg\", extra={\"name\": \"x\", \"lineno\": 1, \"custom\": 2})\n",
            "logger.error(\"msg\", extra={\"msg\": \"y\"})\n",
        ));
        assert_eq!(flagged.len(), 3);
        assert!(flagged.iter().all(|issue| issue.message
            == "Remove or rename this key; it overrides a built-in LogRecord attribute."));
        assert_eq!(flagged[0].range.start, pos(3, 27));
        assert_eq!(flagged[0].range.end, pos(3, 33));
    }

    #[test]
    fn s8554_covers_logger_instances_and_import_aliases() {
        let flagged = found(concat!(
            "import logging as log\n",
            "from logging import error\n",
            "log.debug(f\"{value}\")\n",
            "error(\"%s\" % value)\n",
            "log.getLogger(\"x\").info(f\"{value}\")\n",
        ));
        assert_eq!(flagged.len(), 3);
    }

    #[test]
    fn s8554_stays_silent_on_non_logging_and_other_arguments() {
        // Controls: non-logging calls, `logging.log` (outside the method
        // set), formatting beyond the first positional argument, and
        // non-string arithmetic.
        let clean = concat!(
            "import logging\n",
            "logger = logging.getLogger(__name__)\n",
            "print(f\"{value}\")\n",
            "logging.log(logging.INFO, f\"{value}\")\n",
            "logging.info(\"%s\", f\"{value}\")\n",
            "logging.info(count + 1)\n",
            "logging.info(2 % count)\n",
            "adapter = logging.LoggerAdapter(logger, {})\n",
            "adapter.info(f\"{value}\")\n",
        );
        assert!(found(clean).is_empty());
    }
}
