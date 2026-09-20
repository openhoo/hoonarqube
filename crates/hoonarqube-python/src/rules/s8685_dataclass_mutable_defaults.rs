use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, ModModule, Stmt, StmtClassDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::ImportFqns;
use crate::support::issue_at;
use crate::support::keyword_value;

const RULE_KEY: &str = "python:S8685";
const MESSAGE: &str =
    "Use \"field(default_factory=...)\" instead of a function call as a default value.";

/// Stateful factories whose result must be re-evaluated per instance —
/// clocks, UUIDs, secrets, OS randomness, and mutable container
/// constructors. Calls outside this allowlist stay silent: the reference
/// prefers false negatives over flagging user helpers or frozen-value
/// constructors.
const PROBLEMATIC_FACTORY_FQNS: &[&str] = &[
    "datetime.datetime.now",
    "datetime.datetime.utcnow",
    "datetime.datetime.today",
    "datetime.datetime.fromtimestamp",
    "datetime.datetime.utcfromtimestamp",
    "datetime.date.today",
    "datetime.date.fromtimestamp",
    "time.time",
    "time.time_ns",
    "time.monotonic",
    "time.monotonic_ns",
    "time.perf_counter",
    "time.perf_counter_ns",
    "time.process_time",
    "time.process_time_ns",
    "time.localtime",
    "time.gmtime",
    "uuid.uuid1",
    "uuid.uuid3",
    "uuid.uuid4",
    "uuid.uuid5",
    "secrets.token_hex",
    "secrets.token_bytes",
    "secrets.token_urlsafe",
    "secrets.choice",
    "secrets.randbelow",
    "secrets.randbits",
    "os.urandom",
    "builtins.list",
    "builtins.dict",
    "builtins.set",
    "builtins.bytearray",
    "collections.defaultdict",
    "collections.OrderedDict",
    "collections.Counter",
    "collections.deque",
];

/// `random.<name>` members that produce fresh state per call. The reference
/// matches these syntactically on the `random` module qualifier because the
/// module-level aliases resolve through an internal `Random()` instance.
const RANDOM_PROBLEMATIC_NAMES: &[&str] = &[
    "random",
    "randint",
    "randrange",
    "choice",
    "choices",
    "sample",
    "uniform",
    "gauss",
    "normalvariate",
    "triangular",
    "betavariate",
    "expovariate",
    "gammavariate",
    "lognormvariate",
    "paretovariate",
    "vonmisesvariate",
    "getrandbits",
    "randbytes",
];

/// python:S8685 — dataclass attribute defaults are evaluated once at class
/// definition, so a mutable literal or a stateful factory call is shared by
/// every instance. The finding anchors on the offending default expression
/// (the literal or the problematic call, including a `field(default=...)`
/// argument).
pub(crate) fn check_s8685_dataclass_mutable_defaults(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let _ = parsed;
    let fqns = ImportFqns::build(file_ctx);
    let mut issues = Vec::new();
    for class in &file_ctx.classes {
        if !is_dataclass(class, &fqns) {
            continue;
        }
        for stmt in &class.body {
            let Stmt::AnnAssign(assignment) = stmt else {
                continue;
            };
            check_field(assignment, &fqns, index, source, &mut issues);
        }
    }
    issues
}

/// Whether the class carries `dataclasses.dataclass` in any spelling —
/// bare, qualified, or invoked with arguments.
fn is_dataclass(class: &StmtClassDef, fqns: &ImportFqns) -> bool {
    class.decorator_list.iter().any(|decorator| {
        let expr = match &decorator.expression {
            Expr::Call(call) => call.func.as_ref(),
            expr => expr,
        };
        fqns.is_fqn(expr, "dataclasses.dataclass")
    })
}

/// Flags an annotated attribute whose default is a mutable literal or an
/// allowlisted stateful factory call. `ClassVar` annotations are
/// intentionally class-level and stay silent, as do unannotated
/// assignments (not dataclass fields).
fn check_field(
    assignment: &ruff_python_ast::StmtAnnAssign,
    fqns: &ImportFqns,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let Some(value) = assignment.value.as_deref() else {
        return;
    };
    if is_class_var(&assignment.annotation, fqns) {
        return;
    }
    if is_mutable_literal(value) {
        issues.push(issue_at(RULE_KEY, MESSAGE, value.range(), index, source));
        return;
    }
    if let Expr::Call(call) = value
        && let Some(range) = problematic_call_range(call, fqns)
    {
        issues.push(issue_at(RULE_KEY, MESSAGE, range, index, source));
    }
}

/// `typing.ClassVar[...]` (subscripted or bare) in any import spelling.
fn is_class_var(annotation: &Expr, fqns: &ImportFqns) -> bool {
    let target = match annotation {
        Expr::Subscript(subscript) => subscript.value.as_ref(),
        expr => expr,
    };
    fqns.is_fqn(target, "typing.ClassVar")
}

/// List, dict, and set literals — the mutable containers the reference
/// flags. Tuples are immutable and stay silent.
fn is_mutable_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::List(_) | Expr::Dict(_) | Expr::Set(_))
}

/// The range to flag for a default-value call: the call itself when it is
/// an allowlisted factory, or the `default=` argument of a
/// `dataclasses.field(...)` call when that argument is a mutable literal or
/// an allowlisted factory call. `field(default_factory=...)` is the
/// compliant fix and never flagged.
fn problematic_call_range(call: &ExprCall, fqns: &ImportFqns) -> Option<ruff_text_size::TextRange> {
    if is_problematic_factory_call(call, fqns) {
        return Some(call.range());
    }
    if !fqns.is_fqn(&call.func, "dataclasses.field") {
        return None;
    }
    let default = keyword_value(&call.arguments, "default")?;
    if is_mutable_literal(default) {
        return Some(default.range());
    }
    if let Expr::Call(inner) = default
        && is_problematic_factory_call(inner, fqns)
    {
        return Some(inner.range());
    }
    None
}
/// Whether the callee is an allowlisted stateful factory or a `random.*`
/// member call on the `random` module qualifier. Bare builtins resolve to
/// their unqualified spelling, so `list()` is compared as `builtins.list`.
fn is_problematic_factory_call(call: &ExprCall, fqns: &ImportFqns) -> bool {
    if let Expr::Attribute(attribute) = call.func.as_ref()
        && RANDOM_PROBLEMATIC_NAMES.contains(&attribute.attr.as_str())
        && fqns.is_fqn(&attribute.value, "random")
    {
        return true;
    }
    fqns.resolve(&call.func).is_some_and(|fqn| {
        PROBLEMATIC_FACTORY_FQNS.contains(&fqn.as_str())
            || PROBLEMATIC_FACTORY_FQNS.contains(&format!("builtins.{fqn}").as_str())
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s8685_flags_stateful_defaults_on_sonar_example() {
        // The reference Noncompliant example, verbatim.
        let flagged = scan(concat!(
            "from dataclasses import dataclass\n",
            "from datetime import datetime\n",
            "import uuid\n",
            "\n",
            "@dataclass\n",
            "class Event:\n",
            "    timestamp: datetime = datetime.now()  # Noncompliant\n",
            "    event_id: uuid.UUID = uuid.uuid4()  # Noncompliant\n",
            "    tags: list = []  # Noncompliant\n",
        ));
        let found = findings(&flagged, "python:S8685");
        assert_eq!(found.len(), 3);
        // The anchor covers the offending default expression.
        assert_eq!(found[0].range.start, pos(7, 26));
        assert_eq!(found[0].range.end, pos(7, 40));
        assert_eq!(
            found[0].message,
            "Use \"field(default_factory=...)\" instead of a function call as a default value."
        );
    }

    #[test]
    fn s8685_accepts_default_factory_on_sonar_example() {
        // The reference Compliant solution, verbatim.
        let clean = scan(concat!(
            "from dataclasses import dataclass, field\n",
            "from datetime import datetime\n",
            "import uuid\n",
            "\n",
            "@dataclass\n",
            "class Event:\n",
            "    timestamp: datetime = field(default_factory=datetime.now)\n",
            "    event_id: uuid.UUID = field(default_factory=uuid.uuid4)\n",
            "    tags: list = field(default_factory=list)\n",
        ));
        assert!(findings(&clean, "python:S8685").is_empty());
    }

    #[test]
    fn s8685_flags_allowlisted_factories_and_containers() {
        let flagged = scan(concat!(
            "import dataclasses\n",
            "import os\n",
            "import random\n",
            "import secrets\n",
            "import time\n",
            "from collections import deque\n",
            "from dataclasses import dataclass\n",
            "from datetime import date\n",
            "\n",
            "@dataclass\n",
            "class Event:\n",
            "    today: date = date.today()\n",
            "    started: float = time.time()\n",
            "    token: str = secrets.token_hex(16)\n",
            "    raw: bytes = os.urandom(16)\n",
            "    pick: int = random.randint(1, 100)\n",
            "    items: list = list()\n",
            "    queue: deque = deque()\n",
            "    mapping: dict = {}\n",
            "    tags: set = {1, 2}\n",
            "\n",
            "@dataclasses.dataclass(frozen=True)\n",
            "class Record:\n",
            "    stamp: float = time.monotonic()\n",
        ));
        assert_eq!(findings(&flagged, "python:S8685").len(), 10);
    }

    #[test]
    fn s8685_flags_problematic_field_default_arguments() {
        let flagged = scan(concat!(
            "import dataclasses\n",
            "import random\n",
            "from dataclasses import dataclass, field\n",
            "from datetime import datetime\n",
            "\n",
            "@dataclass\n",
            "class Event:\n",
            "    timestamp: datetime = field(default=datetime.now())\n",
            "    items: list = field(default=[])\n",
            "    more: list = dataclasses.field(default=list())\n",
            "    number: int = field(default=random.randint(1, 100))\n",
        ));
        let found = findings(&flagged, "python:S8685");
        assert_eq!(found.len(), 4);
        // The anchor is the inner `default=` argument, not the field call.
        assert_eq!(found[0].range.start, pos(8, 40));
        assert_eq!(found[0].range.end, pos(8, 54));
    }

    #[test]
    fn s8685_accepts_constants_classvars_and_unannotated_assignments() {
        let clean = scan(concat!(
            "from dataclasses import dataclass\n",
            "from datetime import datetime\n",
            "from typing import ClassVar\n",
            "\n",
            "def compute_default():\n",
            "    return 42\n",
            "\n",
            "@dataclass\n",
            "class Event:\n",
            "    integer: int = 0\n",
            "    name: str = \"hello\"\n",
            "    nothing: None = None\n",
            "    tuple_val: tuple = ()\n",
            "    shared: ClassVar[datetime] = datetime.now()\n",
            "    value: int = compute_default()\n",
            "    plain = datetime.now()\n",
            "    no_default: str\n",
            "\n",
            "class RegularClass:\n",
            "    timestamp: datetime = datetime.now()\n",
        ));
        assert!(findings(&clean, "python:S8685").is_empty());
    }

    #[test]
    fn s8685_flags_nested_dataclass_and_aliased_imports() {
        let flagged = scan(concat!(
            "from dataclasses import dataclass\n",
            "from datetime import datetime\n",
            "from time import time as now_ts\n",
            "\n",
            "@dataclass\n",
            "class Outer:\n",
            "    name: str = \"foo\"\n",
            "\n",
            "    @dataclass\n",
            "    class Inner:\n",
            "        timestamp: datetime = datetime.now()\n",
            "\n",
            "@dataclass\n",
            "class WithAliasedTime:\n",
            "    started: float = now_ts()\n",
        ));
        assert_eq!(findings(&flagged, "python:S8685").len(), 2);
    }
}
