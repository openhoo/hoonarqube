# Native rule research

This inventory records the adoption boundary for independently implemented
rules. Official rule documentation defines intent; Hoonarqube implements only
behavior it can prove with its own syntax, scope, control-flow, and import
models. It does not embed upstream rule source or claim implementation parity.

## Adopted in the 47-rule catalog

| Upstream rule | Hoonarqube rule | Why it fits the current analyzer |
|---|---|---|
| [.NET CA2026](https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca2026) | `hoonarqube-csharp:CA2026` | Exact `JsonDocument.Parse(...).RootElement` chain plus namespace, alias, and local-type evidence. |
| [gosec G124](https://github.com/securego/gosec/blob/master/analyzers/insecure_cookie.go) | `hoonarqube-go:G124` | Exact `net/http.Cookie` keyed literals plus direct later field assignments in the same block; reports omitted or known-disabled `Secure`/`HttpOnly` and known-default/None `SameSite`. Positional and unresolved dynamic values stay silent because this adapter has no Go SSA/type model. |
| [Staticcheck SA1004](https://staticcheck.dev/docs/checks/#SA1004) | `hoonarqube-go:SA1004` | Exact imported `time.Sleep` call and upstream's small untyped integer-literal range. Named constants and unit expressions stay silent. |
| [ESLint `no-async-promise-executor`](https://eslint.org/docs/latest/rules/no-async-promise-executor) | JavaScript and TypeScript namespaces | Scope model proves the global `Promise` constructor; shadowed constructors stay silent. |
| [ESLint `no-promise-executor-return`](https://eslint.org/docs/latest/rules/no-promise-executor-return) | JavaScript and TypeScript namespaces | Executor-owned valued returns and concise arrow bodies are detected; returns owned by nested functions stay silent. |
| [Ruff S113](https://docs.astral.sh/ruff/rules/request-without-timeout/) | `hoonarqube-python:request-without-timeout` | Import and shadow resolution covers `requests` plus HTTPX functions/clients. Missing timeout is reported only for `requests`; explicit `timeout=None` is reported for both, while an unknown `**kwargs` stays silent. |
| [Clippy `permissions_set_readonly_false`](https://rust-lang.github.io/rust-clippy/master/index.html#permissions_set_readonly_false) | `hoonarqube-rust:permissions-set-readonly-false` | Standard `std::fs::metadata` provenance is required, including supported aliases; unrelated `permissions` methods stay silent. |
| [Clippy `suspicious_open_options`](https://rust-lang.github.io/rust-clippy/master/index.html#suspicious_open_options) | `hoonarqube-rust:suspicious-open-options` | Standard/Tokio `OpenOptions::new` and `File::options` provenance plus a complete inline builder chain prove `create(true)` without explicit truncation, appending, or exclusive creation. Unknown extension methods make the adapter stay silent. |

The JavaScript rules each produce separate JavaScript and TypeScript catalog
records, so this wave adds ten records from eight upstream behaviors.

## Researched, not approximated

| Candidate | Decision boundary |
|---|---|
| [gosec G701-G710](https://github.com/securego/gosec/blob/master/RULES.md) | SQL, command, path, SSRF, XSS, log, SMTP, template, deserialization, and redirect taint rules need source/sink summaries, sanitizers, and interprocedural propagation. Add only after those shared semantics exist. |
| [.NET CA2025](https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca2025) and [CA2000](https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca2000) | Task escape and `IDisposable` ownership require Roslyn-grade symbol, escape, and lifetime analysis. Tree shape alone would over-report. |
| [Clippy `zombie_processes`](https://rust-lang.github.io/rust-clippy/master/index.html#zombie_processes) | Correct detection needs path-complete child-process ownership across `wait`, `try_wait`, kill, returns, and drops. |
| [Clippy `read_zero_byte_vec`](https://rust-lang.github.io/rust-clippy/master/index.html#read_zero_byte_vec) | A reliable port needs both `Read` receiver type evidence and vector-length flow across assignments, resize, extend, and aliases. |
| Ruff B006/B008 and mutable-default variants | B006 overlaps existing Sonar mutation coverage; B008 needs configurable immutable-call knowledge. A second noisy namespace adds little value. |
| Clippy `ineffective_open_options` | Existing Sonar Rust `S7447` already covers the conflicting open-option contract; another native finding would duplicate it. |
| Type-aware ESLint rules | Rules requiring TypeScript program services stay deferred until the analyzer owns cross-file type information. |

## Acceptance contract

Every adopted rule must have:

- immutable upstream provenance and license metadata;
- positive, negative, alias, shadowing, and ownership-boundary tests;
- no native findings under the default `sonar-parity` profile;
- exact old-versus-new `sonar-parity` output equality on the repository corpus;
- zero native findings when Hoonarqube analyzes its own tracked sources under
  `strict`, unless an explicitly reviewed fixture requires one.
