# Quick-Fix Parity Audit

Audit of machine-applicable quick-fix capability per rule, dated 2026-08-26. Status values:
`fix shipped` (implemented in hoonarqube), `planned`, or `gap` (with reason). Fix
infrastructure now ships: findings can carry atomic multi-edit remedies and the CLI supports
dry-run planning, unified diffs, explicit `--apply`, conflict reporting, and pre-write
verification of projected content. The captured upstream-parity rows below remain planned; `python:S1721` is the
first shipped local seed fixer.

## What SonarQube actually provides

The SonarQube server exposes **no** fix data. `api/rules/show` carries only remediation-effort
fields; `sysTags` do not mark quickfix capability. Machine-applicable fixes live exclusively
inside the IDE analyzers (SonarLint): the analyzers attach fixes to issues via
`NewIssue.addQuickFix` when running with `product == SONARLINT`. The frozen catalog payloads
contain no fix fields for any rule; their schema preserves server metadata only.

## Parity definition and scope

Parity means replicating the upstream **analyzer** quick-fix surface per language — not any
server-side notion, which does not exist. Scope is the frozen catalog (`catalog/rules/*.json`,
sole rule source): every cataloged key whose upstream analyzer ships a fix is in scope;
keys without a fix upstream, and catalog-absent keys, are out of scope.

Out of parity scope:

- JS/TS Tests-scope-only fixes (not in the frozen main catalog):
  `S5906 S5914 S8785 S8959 S8968`.
- Python keys absent from the frozen `catalog/rules/python.json`
  (verified 2026-08-26): `S3415 S8412 S8492 S8502 S8513 S8516 S8519 S8900 S9081 S9083
  S9106 S9117 S9136`.

## Python

Upstream: sonar-python, 71 distinct rule keys calling `PythonQuickFix.newQuickFix` /
`addQuickFix`; emitted only through `NewIssue.addQuickFix` under SONARLINT. No ruff→S mapping
exists upstream — ruff is an optional external-report importer only. In-scope: 58 cataloged
entries (57 rule keys + legacy `BackticksUsage`).

Local seed outside that captured 58-entry parity set: `python:S1721` — **fix shipped**.
It removes redundant keyword parentheses only when strict re-parsing proves the result remains
valid Python; empty tuples, multiline continuations, and generator expressions stay fix-less.

| Rule keys | Upstream mechanism | Status |
|---|---|---|
| S139 S1110 S1131 S1186 S1244 S1481 S1720 S1854 S1940 S2710 S2772 | `PythonQuickFix` (IDE-only) | planned |
| S3626 S3923 S3984 S4144 S5708 S5712 S5713 S5714 S5717 S5719 S5754 | `PythonQuickFix` (IDE-only) | planned |
| S5795 S5796 S5799 S5806 S5905 S5915 S6326 S6353 S6395 S6397 S6538 | `PythonQuickFix` (IDE-only) | planned |
| S6545 S6552 S6553 S6725 S6727 S6729 S6730 S6735 S6741 S6929 S6969 | `PythonQuickFix` (IDE-only) | planned |
| S6971 S6974 S6978 S7486 S7488 S7489 S7491 S7498 S7500 S7501 S7504 | `PythonQuickFix` (IDE-only) | planned |
| S7508 S7517, legacy BackticksUsage | `PythonQuickFix` (IDE-only) | planned |

## JavaScript

Upstream: eslint-plugin-sonarjs 4.2.0 (SonarJS monorepo; standalone repo archived at 1.0.4).
34 keys ship fixes for JS; 28 are in the frozen javascript catalog. Catalog coverage 28/34 —
language-scoped keys absent from one repo each are expected.

| Rule keys | Upstream mechanism | Status |
|---|---|---|
| S1264 S1488 | autofix (`fixable = 'code'`) | planned |
| S125 S1110(deprecated) S1125 S1126 S1128 S1172 S1528 S1533 | suggestion (`hasSuggestions`) | planned |
| S1940 S2757 S2871 S2990 S3403 S3415 S3626 S3972 S3981 | suggestion (`hasSuggestions`) | planned |
| S3984 S4043 S4619 S4634 S5868 S6326 S6426 S6439 S6594 | suggestion (`hasSuggestions`) | planned |

## TypeScript

Same upstream plugin as JavaScript. 34 keys ship fixes for TS; 32 are in the frozen
typescript catalog (coverage 32/34).

| Rule keys | Upstream mechanism | Status |
|---|---|---|
| S1264 S1488 | autofix (`fixable = 'code'`) | planned |
| S125 S1110(deprecated) S1125 S1128 S1172 S1444 S1528 S1533 | suggestion (`hasSuggestions`) | planned |
| S1940 S2757 S2871 S2990 S3415 S3626 S3972 S3981 S3984 | suggestion (`hasSuggestions`) | planned |
| S4043 S4322 S4619 S4621 S4623 S4634 S4782 S5868 S6326 | suggestion (`hasSuggestions`) | planned |
| S6426 S6439 S6594 S6759 | suggestion (`hasSuggestions`) | planned |

TS-only upstream: S1444 S4322 S4621 S4623 S4782 S6759. JS-only upstream: S1126 S3403.
Tests-scope keys excluded above.

## C#

Upstream: SonarAnalyzer.CSharp ships CodeFix provider files covering the keys below
(58 provider files; upstream prose counts 53 unique keys, but the enumerated set verified
against the frozen catalog contains 54 distinct csharpsquid keys — all present). Consumed only
via Roslyn Workspaces hosts (VS IDE); SonarSource supports no CLI path.

| Rule keys | Upstream mechanism | Status |
|---|---|---|
| S1006 S1116 S1125 S1128 S1155 S1172 S1185 S1186 S125 S818 | Roslyn `CodeFixProvider` | planned |
| S1451 S1858 S1905 S1939 S1940 S2219 S2290 S2328 S2333 S2737 | Roslyn `CodeFixProvider` | planned |
| S2761 S2933 S2934 S2955 S3005 S3052 S3169 S3217 S3234 S3235 | Roslyn `CodeFixProvider` | planned |
| S3240 S3253 S3254 S3257 S3261 S3262 S3265 S3353 S3440 S3441 | Roslyn `CodeFixProvider` | planned |
| S3445 S3447 S3450 S3451 S3456 S3458 S3532 S3600 S3604 S4201 | Roslyn `CodeFixProvider` | planned |
| S4581 S6610 S6613 S6961 | Roslyn `CodeFixProvider` | planned |

## Gap template

Keys later demoted from `planned` to `gap` get one line here with reason, e.g.:

```
- <lang>:<KEY> — gap: <one-line reason, e.g. requires type info hoonarqube's syntax-level
  analyzers cannot derive>
```

## Verification workflow

1. Find: run analysis over a fixture that triggers a quickfix-capable rule.
2. Available fixes: run `hoonarqube fix <path>` or inspect finding JSON.
3. Preview: run `hoonarqube fix --diff <path>`; no file is written.
4. Apply: run `hoonarqube fix --apply <path>` (optionally with repeatable `--rule` prefixes).
5. Verify: apply mode tests every rule fix independently, re-runs the combined analysis,
   requires targeted rule-count reduction, rejects any increased rule count (including from
   mechanical-only rewrites), rejects symlinked or late-modified inputs, and exits nonzero for
   conflicts, warnings, or unverified fixes.
