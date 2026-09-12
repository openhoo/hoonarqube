---
name: exploratory-smoke
description: Run a bounded, evidence-first Hoonarqube exploration over pinned public projects and publish only confirmed, immediately triaged issue or coverage handoffs.
version: 1
disable-model-invocation: true
---

# Hoonarqube exploratory smoke

Use `/skill:exploratory-smoke` for a finite real-project campaign. The skill
starts from immutable public source pins, runs the native and applicable
reference analyzers under explicit resource limits, reviews discrepant behavior
at the source-semantic seam, and publishes only an actionable result. It is a
campaign workflow, not a release qualification, a full SonarQube/CodeQL parity
claim, or permission to change analyzer source.

This file is portable: it uses repository-local contracts and the standard
`git`, `gh`, `podman`, `flock`, `sha256sum`, Node, and Python tooling available
to the caller. It does not require a global skill, an unpublished helper
script, or a pre-existing temporary directory. Read the current repository
files and tool help before using a command; do not copy historical command
lines, identities, or counts as current defaults.

## Non-negotiable boundaries

- The scope is finite. Use the explicit matrix below as the default only when
  the invocation does not provide another finite matrix. An explicit invocation
  may replace or narrow it with named public projects; record that override.
  Do not add repositories, languages, rules, or follow-up scans implicitly.
- Use only public GitHub repositories and detached, immutable full-commit pins.
  Record the resolved 40-hex commit for every checkout before scanning. A
  branch, moving tag, shallow tip, or unverified archive is not a source pin.
- Scan unchanged source. Build the analyzer in an isolated worktree and do not
  rewrite a project to make a detector fire, make a parser accept input, or
  make a reference comparison look equal. Do not install or run a public
  project's arbitrary build/install scripts unless the manifest records the
  command, trust decision, network policy, and bounded result.
- Default to observation and issue/coverage handoff. Do not edit Hoonarqube
  source, mutate the pinned source checkout, apply a quick fix to its canonical
  copy, close issues, merge, release, or publish an artifact. A bounded
  quick-fix probe may use the CLI's preview/apply modes only in a disposable
  copy of the pinned source (see the counterexample procedure below); that is
  evidence, not an implementation change. Explicit fix authorization is a
  separate handoff to either [`skill://fix-issue`](../fix-issue/SKILL.md) for
  one selected issue or [`skill://work-issues`](../work-issues/SKILL.md) for a
  finite queue (which composes `fix-issue`).
- Issue creation, reopening, body/comment publication, and label/state changes
  require explicit publication authority in the campaign invocation. Without
  that authority, retain candidates and evidence maps only; do not mutate the
  live issue tracker.
- A complete result, an incomplete result, a failure, an unsupported route, and
  an unavailable reference are different outcomes. An empty report after a
  crash, timeout, parser failure, missing context, or query failure is never a
  clean negative.
- Keep all output English, except source snippets, commands, diagnostics, and
  tool output, which remain byte-for-byte as observed. Redact credentials,
  private paths, and secrets as `<REDACTED>` before a public issue or durable
  handoff.
- Suspected security vulnerabilities use the repository's private reporting
  path in [`SECURITY.md`](../../../SECURITY.md). Never infer a vulnerability
  from a hotspot, a rule name, a CodeQL definition, scan silence, or a count.

## Bounded project matrix

This is the campaign's explicit, repeatable starting matrix, derived from the
real-project closure. The repositories are examples of stable public surfaces,
not a promise that their current heads are suitable. Every row requires a new
immutable commit pin at invocation time; the placeholder is intentional and
must be replaced in the source manifest before checkout. An invocation that
supplies a different finite matrix replaces this default rather than silently
combining both matrices.

| Family | Public repository | Required source pin | Native scope seed | Reference runners |
| --- | --- | --- | --- | --- |
| Python | `psf/requests` | `<immutable commit resolved at run start>` | Entire pinned checkout; retain `.py` source and unsupported-file inventory | SonarQube Python profile; CodeQL Python database, quality, and security-and-quality suites |
| Python | `pallets/flask` | `<immutable commit resolved at run start>` | Entire pinned checkout; retain `.py` source and unsupported-file inventory | SonarQube Python profile; CodeQL Python database, quality, and security-and-quality suites |
| Python | `pallets/click` | `<immutable commit resolved at run start>` | Entire pinned checkout; retain `.py` source and unsupported-file inventory | SonarQube Python profile; CodeQL Python database, quality, and security-and-quality suites |
| Python | `yaml/pyyaml` | `<immutable commit resolved at run start>` | Entire pinned checkout; retain `.py` source and unsupported-file inventory | SonarQube Python profile; CodeQL Python database, quality, and security-and-quality suites |
| JavaScript/TypeScript | `expressjs/express` | `<immutable commit resolved at run start>` | Manifest-selected JavaScript roots, including the exact file set sent to both analyzers | SonarQube JavaScript profile; CodeQL JavaScript extractor, quality, and security-and-quality suites |
| JavaScript/TypeScript | `axios/axios` | `<immutable commit resolved at run start>` | Manifest-selected JavaScript/TypeScript roots; retain declaration and generated-file policy | SonarQube JavaScript and TypeScript profiles as applicable; CodeQL JavaScript extractor and both suites |
| JavaScript/TypeScript | `colinhacks/zod` | `<immutable commit resolved at run start>` | Manifest-selected source roots; record test, benchmark, declaration, and generated exclusions | SonarQube JavaScript and TypeScript profiles as applicable; CodeQL JavaScript extractor and both suites |
| JavaScript/TypeScript | `markdown-it/markdown-it` | `<immutable commit resolved at run start>` | Manifest-selected JavaScript roots with exact Sonar/native path mapping | SonarQube JavaScript profile; CodeQL JavaScript extractor, quality, and security-and-quality suites |
| Go | `spf13/cobra` | `<immutable commit resolved at run start>` | Tracked Go source under the declared test/generated/vendor policy | SonarQube Go profile; CodeQL Go database, quality, and security-and-quality suites |
| C# | `DapperLib/Dapper` | `<immutable commit resolved at run start>` | Complete declared C# project context plus positional source scope | SonarQube MSBuild/Roslyn route; CodeQL C# database, quality, and security-and-quality suites |
| Rust | `BurntSushi/ripgrep` | `<immutable commit resolved at run start>` | Tracked Rust source under the declared workspace scope | SonarQube Rust route when available; CodeQL Rust database, quality, and security-and-quality suites; native GitHub Code Quality is explicitly unsupported |
| Java | `google/gson` | `<immutable commit resolved at run start>` | Declared Java source roots and compiled-context policy | SonarQube Java profile; CodeQL Java database, quality, and security-and-quality suites |
| Ruby | `ruby/rake` | `<immutable commit resolved at run start>` | Declared Ruby source roots and test/generated policy | SonarQube Ruby profile; CodeQL Ruby database, quality, and security-and-quality suites |

The matrix is intentionally finite, but source availability, profile
availability, and query support are not assumed. If a row or runner cannot be
used, retain the row with `unsupported`, `failed`, or `unverified` status and an
exact reason. Never silently substitute another project or call a different
language's output equivalent.

## Language and runner contract

Run every applicable cell for the source actually present in a row. JavaScript
and TypeScript may share a checkout and CodeQL extractor, but their native
profile, Sonar profile, source suffixes, active keys, and findings remain
separate. A no-file language cell is recorded as `unsupported: no applicable
source`, not as a zero-finding pass.

| Language | Native Sonar-compatible route | Native GitHub Code Quality route | SonarQube reference | CodeQL reference |
| --- | --- | --- | --- | --- |
| Python | `analyze --profile sonar-parity --format json` | `analyze --profile github-code-quality --format sarif` | Python active profile and raw issues/hotspots | Python database plus both suites |
| JavaScript | `sonar-parity` over the manifest file set | `github-code-quality` over the same set | JavaScript active profile | JavaScript extractor plus both suites |
| TypeScript | `sonar-parity` over the manifest file set | `github-code-quality` over the same set | TypeScript active profile | JavaScript extractor; report TypeScript source separately |
| C# | `sonar-parity` with complete project context when needed | `github-code-quality` for the implemented subset | Actual MSBuild/Roslyn-integrated scanner | C# database with the declared bounded build command |
| Go | `sonar-parity` over the declared Go scope | `github-code-quality` for the implemented subset | Go profile or documented unavailable reference | Go database with a bounded build/extraction command |
| Rust | Native `sonar-parity`/Rust contract | Explicitly `unsupported` by the native profile contract | Rust route or documented unavailable reference | Rust database with the declared build/extraction command |
| Java | Native route and measurement; the frozen Sonar rule family may be absent | Implemented subset only; registry evidence required | Java profile and raw issues/hotspots | Java database plus both suites |
| Ruby | Native route and measurement; the frozen Sonar rule family may be absent | Implemented subset only; registry evidence required | Ruby profile and raw issues/hotspots | Ruby database plus both suites |

The native `github-code-quality` profile is a conservative implemented subset,
not the definitions-only catalog. Check the executable language registries and
an actual SARIF run. Rust's explicit unsupported cell is a contract result.
Java and Ruby measurement support does not create a frozen Sonar rule family.
Never turn an unavailable or unsupported cell into a coverage count or a parity
score.

For each reference runner, retain both the runner identity and execution
metadata:

- SonarQube server version, scanner image/digest or executable identity, active
  profile name/key, active-rule key list and digest, project key, source roots,
  exclusions, indexed-file result, analysis ID, raw issue/hotspot pages, and
  exit/compute status.
- CodeQL CLI/bundle identity, language extractor, database creation command,
  build command when any, database status, requested suite paths, complete query
  inventory, per-query `executed`/`unsupported`/`failed` state, result count,
  SARIF digest, and exit status. Quality and security-and-quality suites are
  separate observations.
- Any compiler, runtime, helper, project, module, or configuration snapshot
  used by a semantic route, with its digest and completeness state.

CodeQL query IDs are not Sonar rule keys. Suite result totals are not native
coverage or parity. Sonar active-rule totals are not detector implementation.

## Identity, checkout, and source manifest

At campaign start allocate two caller-owned paths:

- `CAMPAIGN_ROOT`: disposable per-run work area, chosen by the caller rather
  than assumed by this skill; and
- `PERSISTENT_EVIDENCE_ROOT`: durable storage outside any disposable scratch
  path, including `/tmp`, where redacted evidence and cleanup proof survive.

Refuse to proceed if either path is ambiguous, shared with another campaign, or
contains credentials that the campaign does not own. Keep the working checkout
and source clones below `CAMPAIGN_ROOT`; copy only redacted, hashed proof to the
persistent root before cleanup.

Create one `source-manifest.json` per project before analysis. It must include
at least:

- repository URL, resolved commit, checkout tree/object identity, clone method,
  checkout status, license/notice location, and source-archive digest if used;
- analysis root, exact included roots/files, path normalization, test/generated/
  vendor policy, exclusions, unsupported-file inventory, and the manifest's
  own digest;
- every selected file's normalized relative path, byte length, SHA-256, source
  language, and classification; preserve non-UTF-8 or unsupported inputs as
  explicit records rather than dropping them;
- native source revision, toolchain identity, executable path and SHA-256,
  command, profile, format, options, limits, exit code, completeness, and
  report digest; and
- SonarQube and CodeQL identities, active keys/query inventory, exact commands,
  environment allowlist, raw-output digests, and status for every attempted
  cell.

Use detached checkouts and `git status --porcelain`/tree identity checks before
and after scans. Do not mutate lockfiles, generated sources, package manifests,
or line endings. Preserve exact source snippets and immutable GitHub links at
`<repository>/blob/<commit>/<path>#L<start>-L<end>`; the link must resolve to the
recorded commit, not a moving branch.

### Native identity is not a release identity

Build or select the unchanged-source native executable in an isolated worktree.
Record the source commit, worktree status, Rust/toolchain identity, executable
SHA-256, `--version` output, build command, and build result as a
`native_build` identity. If the source was dirty, the executable was copied from
an unknown build, or the command cannot be reproduced, mark native provenance
`unverified`; do not infer it from a release label.

A downloaded release asset is a separate `release_asset` identity: record its
official URL, asset name, checksum/signature/attestation evidence, version,
source or tag claim, and downloaded bytes' SHA-256. Use the release binary only
when the campaign explicitly requests a release comparison. Never label a local
source build as a release asset, or use a release checksum as the source-build
identity.

## Existing repository oracle patterns

Before scanning, read the relevant sections of [`PARITY.md`](../../../PARITY.md)
and [`QUICKFIX.md`](../../../QUICKFIX.md). Reuse the repository's current
normalization and fail-closed patterns where applicable, especially:

- `tools/oracle/parity.py`, `parity_suite.py`, and `reference_matrix.py` for
  complete finding identity and reference status;
- `tools/oracle/security_evidence.py` for separate security evidence and
  explicit unverified boundaries;
- `tools/oracle/metric_oracle.py` for project-scope/denominator handling;
- `tools/oracle/csharp_direct_oracle.py` for compiler-backed C# context; and
- `tools/oracle/diff.py` for deterministic diff/evidence handling.

These are repository patterns, not blind commands. Inspect their current
schemas and flags at run time. Keep project measurement, issue exports,
Sonar-compatible findings, GitHub SARIF, quick-fix actions, and security
qualification as distinct contracts.

## Bounded execution

### 1. Prepare one immutable slice

For each matrix row, record a slice owner and a unique project key. Clone or
checkout the exact source pin into its isolated directory. Generate the source
manifest and a redacted `commands.json` before running anything. Verify that
all roots passed to native, SonarQube, and CodeQL resolve to the same manifest
scope; if a runner requires a different physical root, record the deliberate
mapping and compare only normalized manifest-relative paths.

Run the full project scope first. A per-file or partitioned run may be used to
localize a failure, but it is a `partial_isolation` supplemental result and
cannot replace the full-project status, denominator, or issue inventory.

### 2. Keep heavy scanners bounded and serialized

Declare limits in the campaign manifest before execution: per-run wall time,
CPU time, address space/RAM, worker count, CodeQL `--threads`/`--ram`, compiler
limits, output size, and retained-source byte budget. Put SonarQube, CodeQL,
large compiler-backed extraction, and other heavy scanners behind one
caller-owned `flock` lock. Independent project slices may prepare manifests and
run lightweight native work concurrently, but they acquire the shared lock for
heavy phases and release it on timeout or signal.

Use read-only source mounts where possible and unique working/database/output
folders. Capture the command, limits, start/end times, PID/process group,
stdout, stderr, exit code, signal, timeout, and report hash. Do not retry a
failed heavy scan until it becomes a pass, silently increase limits, or delete
an incomplete report.

If a full project crashes (including a stack overflow or abort), preserve the
original signal, stderr, core/diagnostic metadata when safe, and incomplete
scope. Do not raise the stack size, change recursion behavior, split the source,
or use another workaround and count that result as a full-project success. A
bounded partition can identify the triggering file only as supplemental
`partial_isolation`; the original full-project crash remains actionable
failure evidence.

### 3. Run native profiles separately

For every applicable language, run the native Sonar-compatible profile and the
native GitHub Code Quality profile as different invocations and artifacts:

```text
<native> analyze --profile sonar-parity --format json -- <manifest scope>
<native> analyze --profile github-code-quality --format sarif -- <manifest scope>
```

Use the actual CLI syntax shown by the current binary; the placeholders are
not shell commands. Never combine their findings, counts, rule registries, or
status. Record `unsupported` when a profile is outside the language contract,
`incomplete` for exit 2/incomplete scope, `failed` for a
nonzero/crash/timeout, and `complete` only after validating the report and
scope. Preserve all issue records, metrics, diagnostics, and completeness
flags.

For C#, do not call a zero-finding or helper-only scan semantic evidence. A
complete project snapshot and the required MSBuild/Roslyn/compiler context are
part of the result. Missing project files, helpers, references, compiler
facts, or generated mappings remain `unverified`/incomplete. Do not build an
untrusted public repository merely to manufacture context; use an explicit
trust decision and a bounded, offline or otherwise recorded dependency policy.

### 4. Run SonarQube and CodeQL on every applicable row

Run the pinned SonarQube scanner against the same source manifest and active
profile selected for that language. Fetch the profile's actual active keys,
not only its displayed count. Keep the raw API pages, pagination uniqueness,
analysis task status, issue/hotspot records, and indexed-file scope. If a
matching Hoonarqube profile does not exist, still retain the Sonar observation
as reference-only/unverified and say why; do not call the absence a native bug.

For every applicable CodeQL language, create a database with the declared
extractor and bounded command, then run both the quality and
security-and-quality suites. Retain the union of query definitions and every
query execution state, including no-result, unsupported, failed, timed-out,
and database-incomplete queries. If extraction requires a compiler/build,
record the exact command and context; a skipped build is not a successful empty
database. A CodeQL security result is security evidence, not a public
vulnerability ticket by itself.

A reference runner outage, unavailable licensed analyzer, missing query pack,
failed extraction, or incomplete database is an explicit non-pass. Keep its
expected denominator in the matrix and never replace it with zero.

## Comparison and semantic review

### Complete per-rule union/difference inventory

After all runner results exist, create a full inventory, not a headline count.
For each language, project, profile, and rule/query key retain:

- native and reference presence, multiplicity, exact file, message, primary
  range (line and column), flow/secondary locations, severity/category, and
  source-scope membership;
- the source commit/tree, native executable identity, reference identity,
  profile name/key, active-key or query-inventory digest, options, context,
  and completeness status; and
- a disposition such as `exact_identity`, `native_only`, `reference_only`,
  `reference_different`, `unsupported`, `failed`, `incomplete`, or
  `unverified`, with the preserved raw record and reason.

Use a multiset of complete finding identity, not just rule presence or totals.
Counts can prioritize review but never establish parity. Keep Sonar-compatible
findings separate from GitHub Code Quality SARIF and CodeQL results. Do not
map CodeQL query IDs to Sonar keys by name, infer implementation from a
catalog/help URL, or call a native empty result a security pass.
Reference false positives, parser/version compatibility changes, and
reference-only behavior remain `reference_different`, `unverified`, or
rejected dispositions unless an independent native contract and control prove a
native defect. They are never promoted to a bug merely because the reference
emits a finding.

### Source-semantic and executable counterexamples

For each high-signal discrepancy or crash candidate:

1. Read the executable rule registry, rule implementation, relevant parser/type
   or compiler path, documentation, and callers. Confirm whether the rule is
   actually registered for the profile. A definitions-only catalog row is not
   detector evidence.
2. Link the exact real-project source span at its immutable commit, preserve the
   exact snippet/command/output, and explain the expected semantics without
   rewriting the original. Keep source and diagnostics unchanged in evidence.
3. Make a smallest bounded counterexample that preserves the triggering
   ownership and a clean or near-miss control. Run the native CLI and, when
   applicable, the reference analyzer on the same declared scope. Do not call
   a reference-only result a native defect.
4. Where behavior depends on a compiler, runtime, generated context, or API,
   compile and execute the counterexample with the pinned toolchain. Retain
   warnings, errors, stdout, stderr, exit status, reflection/API observations,
   and before/after source hashes. A successful compilation alone is not a
   behavioral proof.
5. For quick-fix observations, use the boundaries in `QUICKFIX.md`: preview and
   apply are distinct, projected content must be independently reanalyzed, all
   rule regressions matter, and unsafe/refusal controls must remain unchanged.
   Run `--diff` and, when needed, `--apply` only against a disposable copy of
   the pinned source or a self-contained probe. Preserve the untouched original
   and both copies' hashes. Compile/run the projected copy when semantics
   require it, retaining diagnostics, output, and exit status. This does not
   implement a fix; an explicitly authorized fix goes to `skill://fix-issue`.

Portable lessons from prior real-project evidence include: AST ownership is
needed for Go struct tags, format-call arguments, and statement-header
boundaries rather than text heuristics; a C# quick fix can compile while
removing a public API or changing runtime behavior, so reflection/runtime
controls are needed; and a full JavaScript/TypeScript scan can abort with a
stack overflow while per-file probes succeed, which remains a full-project
failure. These examples guide review, but their old source pins, scanner
identities, counts, and scratch paths are never reused as current evidence.

Use the smallest supported conclusion:

- `Bug` only for a reproducible violation of an existing native contract,
  including a confirmed false positive, false negative, regression, crash, or
  unsafe fix.
- `Coverage request` only when the desired behavior is justified and the
  executable profile/registry lacks it. Group related future surface requests
  by a coherent rule/language/semantic boundary, retaining every occurrence.
- `Enhancement` or `Documentation` only for a concrete requested behavior or
  documentation contract, not to disguise an analyzer mismatch.
- `needs-info`/`needs-triage` for missing evidence, unresolved semantics,
  unavailable reference/context, or unsupported claims. A reference/native
  mismatch alone is rejected or recorded as `reference_different`, not filed
  as a bug.

Keep speculative candidates in `candidate-inventory.json` with their evidence
and rejection reason. Do not create bogus tickets for scan silence, metadata,
counts, unsupported language routes, or unverified security concerns.

## Deduplication and publication

Before creating or changing any issue, query the live repository and read the
complete record for every possible root match: body, every comment and event,
linked pull requests, current labels, and current state. Search by root cause,
rules/query IDs, distinctive symptom, source path, and linked evidence rather
than title alone. An existing issue owns all occurrences of the same root;
append evidence only when authorized and preserve its public discussion.

A closed issue is reopened only when current pinned evidence demonstrates a
regression against the prior resolved behavior. Preserve the old resolution,
show the comparable source/profile/context, and run the immediate triage flow
again. Do not duplicate an open issue or reinterpret a closed issue merely
because a reference analyzer changed.

### Canonical issue body

For every confirmed actionable defect or justified grouped future coverage
request, render the current repository issue form at
[`.github/ISSUE_TEMPLATE/issue.yml`](../../../.github/ISSUE_TEMPLATE/issue.yml)
and use its actual field IDs and descriptions. Before creating, updating, or
reopening an issue, and again after its live API readback, run the canonical
`validateIssueBody` check documented by [`skill://triage`](../triage/SKILL.md)
against the rendered body and actual field values. Validate the form contract,
not merely a count of headings; do not implement a duplicate validator. The
rendered English body must contain exactly these top-level headings, in this
order:

1. `### Summary`
2. `### Classification`
3. `### Version and provenance`
4. `### Reproduction`
5. `### Expected and actual behavior`
6. `### Evidence and scope`
7. `### Acceptance criteria`

Populate the form's `summary`, `classification`, `version-and-provenance`,
`reproduction`, `expected-and-actual-behavior`, `evidence-and-scope`, and
`acceptance-criteria` fields; do not invent a parallel schema or leave a
required field blank. The `classification` field's entire value must be one
plain choice—exactly `Bug`, `Coverage request`, `Enhancement`, or
`Documentation`—with no Markdown, rationale, labels, or state appended; put
rationale in the other fields and state in labels. Preserve exact fenced
snippets, commands, numbers, output, source hashes, and immutable links. If
migrating legacy evidence, demote old headings outside code fences so they do
not masquerade as new form headings. Do not publish temporary `/tmp` paths as
the only proof.

Classification is exactly one of `Bug`, `Coverage request`, `Enhancement`, or
`Documentation`. Use the live `.github/labels.json` manifest at invocation,
and apply exactly one category and one state:

- `Bug` -> `bug`; `Coverage request` -> `enhancement` plus `coverage`;
  `Enhancement` -> `enhancement`; `Documentation` -> `enhancement` plus
  `documentation`.
- State is exactly one of `needs-triage`, `needs-info`, `ready-for-agent`, or
  explicitly authorized `wontfix`. Keep unsupported, incomplete, and
  unverified cases in the appropriate state with the precise missing fact.
- Add only evidence-based symptom labels (`false-positive`, `false-negative`,
  `regression`, `unsafe-fix`, `crash`). Add language, area, and priority only
  when justified, using the canonical prefixed names `language:python`,
  `language:javascript`, `language:typescript`, `language:csharp`,
  `language:go`, `language:rust`, `language:java`, `language:ruby`,
  `area:cli`, `area:exports`, `area:metrics`, `area:ci`, and
  `priority:critical`, `priority:high`, `priority:normal`, or
  `priority:low`.
- Preserve unrelated existing labels. Never create bare language/area/priority
  aliases, `ready-for-human`, `human-review`, or another queue label. Never
  close an issue as part of exploration.

### Immediate triage is part of publication

Do not accumulate an untriaged publication backlog. After each create or
reopen, in the same bounded work item:

1. Read the live body, comments, labels, timeline, and linked PR context again.
2. Invoke [`skill://triage`](../triage/SKILL.md) for that exact issue. The
   campaign authorization includes the durable public triage brief and the
   evidence-based label/state synchronization, but never source edits, fixes,
   closure, or release. Triage must not repeat a question already answered by
   the body or comments.
3. Post at most one idempotent comment containing the marker
   `<!-- hoonarqube:triage-brief:v1 -->` and a durable brief with behavior,
   invariants, acceptance criteria, non-goals, exact evidence/reproduction,
   risks, and blockers. A `ready-for-agent` brief requires decisive confirmed
   behavior, concrete acceptance, and no unresolved semantic or dependency
   decision; it is not awarded for a native/reference mismatch alone.
4. Apply the corrected category/state/supplemental labels, then perform a live
   API readback of body, labels, and comments. If triage or readback fails,
   stop before publishing another item and retry or record the exact blocked
   state; do not leave a silent backlog or duplicate the marker comment.

Record each publication in a durable `publication-map.json` with issue number,
URL, root ID, classification, final state, exact labels, brief comment URL,
source/project evidence digests, dedup decision, and readback timestamp. Keep
reopened regressions, grouped coverage requests, rejected candidates, and
unverified records distinguishable. The map is an evidence index, not a
replacement for the issue's public discussion.

## Completion and cleanup contract

A campaign is complete only when every matrix row has a source manifest and a
recorded result for every applicable native, SonarQube, and CodeQL cell; every
failure, unsupported route, incomplete denominator, crash, context limit, and
reference-unverified state is retained; the full per-rule union/difference
inventory is written; and every candidate is either:

- published or reopened with the canonical seven-heading body and immediately
  triaged with a durable brief;
- grouped into a justified future coverage request and handled by that same
  publication/triage flow; or
- retained as a speculative/rejected/unverified candidate with exact evidence
  and a reason not to publish.

Before removing any owned checkout, container, database, server, process, or
credential:

1. Copy redacted manifests, raw-output hashes, normalized inventories,
   publication maps, issue API readbacks, and a `cleanup.json` to
   `PERSISTENT_EVIDENCE_ROOT` outside `/tmp` and other disposable paths. Keep
   crash logs and incomplete reports; do not replace them with summaries.
2. Revoke campaign-created tokens/credentials through their owning service
   while that service is still available; verify revocation, remove owned token
   files, check restrictive permissions, and record proof without retaining
   secret bytes. Search redacted artifacts for accidental credential material
   before stopping the service.
3. Stop only campaign-owned process groups and containers, wait for exit, and
   record each PID/container identity, signal, exit result, and timestamp. Do
   not kill an unverified process or delete another campaign's work.
4. Remove only disposable paths owned by this campaign after proof is copied.
   If a process, credential, or artifact cannot be cleaned safely, mark cleanup
   blocked and disclose the exact owned resource and residual risk rather than
   claiming completion.

Do not report success from a green native build, a reference count, a partial
slice, a release label, or a passing test-only fixture. The final campaign
record must name the native and release identities separately, preserve scope
and denominator limits, and link the next explicit authorization boundary.
