---
name: fix-issue
description: Safely investigate and implement one explicitly selected Hoonarqube GitHub issue, with pinned evidence, a narrow observable fix, regression controls, and honest completion status.
disable-model-invocation: true
---

# Fix one explicitly selected issue

Use this skill only after an explicit invocation with one issue URL or number, for
example `/skill:fix-issue 123` or `/skill:fix-issue https://github.com/openhoo/hoonarqube/issues/123`.
A `ready-for-agent` state, an issue label, a notification, or an existing issue
alone is not execution authorization.

This is a repository-specific adaptation of the feedback-loop and red/green
principles in [implement](https://github.com/mattpocock/skills/blob/main/skills/engineering/implement/SKILL.md),
[diagnosing-bugs](https://github.com/mattpocock/skills/blob/main/skills/engineering/diagnosing-bugs/SKILL.md),
and [tdd](https://github.com/mattpocock/skills/blob/main/skills/engineering/tdd/SKILL.md).
Those upstream files are references, not runtime dependencies. Use the local
triage contract at [`skill://triage`](skill://triage) and the local
[`skill://work-issues`](skill://work-issues) workflow instead of assuming any global
skills or tracker conventions.

## Non-negotiable safety rules

- Work on exactly the selected issue. Do not absorb nearby issues, speculative
  cleanup, or an unrelated refactor.
- The reporter's stated failure is ground truth. Do not rerun a reported failure
  merely to dispute it; run only the bounded reproduction or verification needed
  to make the fix trustworthy.
- Preserve the user's dirty files. Work in a separate branch/worktree. Never
  `git reset --hard`, `git clean`, restore, overwrite, or delete files in the
  user's checkout. Never assume an uncommitted file is disposable.
- Do not implement a fixture-only special case, suppress a finding, weaken a
  contract, hide an incomplete result, or add a compatibility alias instead of
  fixing the owning path and its callers.
- Public security reports are not ordinary bug work. Do not repeat sensitive
  details in issue comments or a public PR; use the repository's private
  vulnerability-reporting route and record only the minimum safe status.
- Use only these states: `needs-triage`, `needs-info`, `ready-for-agent`, and
  `wontfix`. No extra state or queue is allowed. Missing evidence, unavailable
  dependencies, and unresolved authority are described in the issue text and
  normally remain `needs-info`; they are not silently made agent-ready.
- Readiness is not authorization. A fix may begin only after the explicit skill
  invocation and after the issue's scope and acceptance criteria are pinned.
- Do not bypass CI, branch protection, approvals, or repository permissions.
  Never use an administrator merge, force-push, or an unrequested release.
- Do not invent tracker labels. When labels are required, use only the current
  triage/label manifest vocabulary, including the prefixed supplemental labels;
  never recreate a transient bare variant.

## 1. Pin the issue and its authority

Fetch the complete current issue before reading old local notes or forming a
hypothesis. Preserve the URL, number, title, body, current state, labels,
comments, and timestamps in a private working note. For a GitHub repository,
use commands equivalent to:

```sh
gh issue view "$ISSUE" --comments --json number,title,body,state,labels,url,author,assignees
# Replace OWNER/REPO/N with the selected repository and issue number.
gh api --paginate repos/OWNER/REPO/issues/N/comments
gh api --paginate repos/OWNER/REPO/issues/N/timeline
```

Follow every linked or cross-referenced PR from the timeline and fetch its
current body, review discussion, state, head SHA, and checks. Search for
duplicates by the issue's distinctive symptom, rule/API name, and linked PRs;
do not create duplicate work when an active PR already owns the fix. A linked
PR is evidence of work, not proof that the issue is fixed.

Inspect the current source at the pinned base and issue provenance rather than
assuming a historical checkout is current:

```sh
git rev-parse HEAD
git status --short
git show --stat --oneline HEAD
```

If the issue names a release, branch, reference implementation, compiler, or
binary, pin its commit/digest and inspect the corresponding source or artifact.
Do not silently substitute the current branch for the reported version.

Build an issue ledger with:

- one classification: `Bug`, `Coverage request`, `Enhancement`, or
  `Documentation`;
- one current state from the vocabulary above;
- version and provenance: source commit, native version/binary digest, OS and
  toolchain, fixture/input digest, and reference version/image/digest where
  applicable;
- exact reproduction, expected/actual behavior, evidence and scope;
- explicit acceptance criteria, non-goals, risks, and dependencies;
- linked issues/PRs and whether an active PR already covers the request.

The canonical issue form has seven required headings:
`Summary`, `Classification`, `Version and provenance`, `Reproduction`,
`Expected and actual behavior`, `Evidence and scope`, and `Acceptance criteria`.
Use all seven to pin the work; the `Acceptance criteria` heading is only one of
those seven, not a name for the whole form. Resolve contradictory comments
against the latest explicit scope decision from the issue's authority and
record the decision; do not infer new requirements from a linked PR, a
reference analyzer, or a casual comment. If the authority, provenance, API
evidence, or acceptance is missing, stop honestly at `needs-info` with the
exact missing fact instead of guessing.

Read the local triage brief and its evidence before implementation:

```text
skill://triage
.agents/skills/triage/SKILL.md
```

A triage brief is a bounded handoff, not permission to broaden scope. If an
active PR already covers the issue, inspect it and hand the evidence/status to
`skill://work-issues`; do not repeatedly consume the issue with a second fix.

## 2. Isolate the work

Record the source checkout's status without changing it, then create a fresh
sibling worktree and branch from the intended base. Use a clean base ref; do not
copy uncommitted files into it. Follow the branch pattern in `hoolicy.yaml`:
`fix/issue-<digits>` for a bug or `feat/issue-<digits>` for an agreed
enhancement/coverage change.

```sh
git status --short
git worktree list
git worktree add -b fix/issue-123 ../hoonarqube-issue-123 <base-ref>
cd ../hoonarqube-issue-123
```

Use `feat/issue-123` instead for an explicitly agreed enhancement or coverage
change. Choose a non-conflicting branch/worktree name and pin its starting
commit. If the base cannot be identified or is not clean, stop and report the
blocker; do not repair it with reset or cleanup. Keep the disposable worktree
until all evidence is saved. Removing that worktree, committing, pushing,
merging, or releasing requires the corresponding user authorization and must
never affect the original checkout.

## 3. Understand repository truth before editing

Read only the relevant portions of these local sources, plus `CONTEXT.md` and
nearby ADRs when they exist:

- [`CONTRIBUTING.md`](../../../CONTRIBUTING.md) for toolchain, bad/clean controls,
  provenance, and PR expectations;
- [`PARITY.md`](../../../PARITY.md) for the boundary between native behavior,
  reference evidence, semantic contexts, incomplete analysis, and unverified
  parity;
- [`QUICKFIX.md`](../../../QUICKFIX.md) for diff/apply verification and refusal
  semantics when the issue concerns fixes;
- [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml) for the actual
  protected checks and pinned tool versions.

Map the public seam, owning module, data flow, and every caller before changing
an exported symbol. Use the language server's references/definitions when
available; do not rely on a text search that can miss re-exports or shadowed
callers. Follow the existing architecture and naming. A fix is a cutover:
migrate all callers and remove obsolete paths rather than leaving shims,
aliases, or deprecated behavior behind.

Apply these Hoonarqube-specific boundaries:

- The frozen Sonar catalogs are definitions/provenance, not evidence that an
  executable detector exists. Determine implementation from the language
  executable registries and an actual profile/CLI run.
- A reference finding is a lead, not proof of a native defect. Compare the
  exact rule, file, message, range, scope, and provenance; preserve explicit
  `UNVERIFIED` distinctions.
- Incomplete, malformed, missing-context, resource-limited, or failed analysis
  is not a clean zero-finding result. Preserve fail-closed exits and incomplete
  scope, and never turn missing evidence into a pass.
- Preserve deterministic output, full-project metrics, cross-file analysis,
  duplication/cache invalidation behavior, GitLab output, and negative quickfix
  controls unless the pinned acceptance criteria explicitly change one.
- Do not claim full SonarQube or security parity from a focused fix. Enterprise,
  reference-only, and unresolved CodeQL/security evidence stays explicitly
  unverified.

## 4. Build a bounded, red-capable feedback loop

Start with the smallest public seam that can observe the reported behavior.
Use the issue's exact reproduction when it is already durable and sufficient;
otherwise build one of these, in order: a focused test, actual CLI invocation,
compiler/runtime smoke, HTTP replay, or a throwaway harness. The command must
assert the user's observable symptom, not merely avoid a panic. Redact secrets
from commands, logs, artifacts, and quoted output as `<REDACTED>`.

For a bug:

1. Run the bounded reproduction once when needed to capture the exact failure
   and exit/result. Keep the reporter's result authoritative if rerunning is
   not possible or would only dispute it.
2. Minimize one input, caller, option, or step at a time until every remaining
   part is load-bearing. Keep a clean control that must remain clean.
3. For a non-obvious root cause, record three to five ranked, falsifiable
   hypotheses and test one variable at a time. Do not implement a theory that
   has no observable prediction.

For a `Coverage request` or `Enhancement`, write the exact new semantics,
public API/CLI shape, compatibility expectations, and bounded acceptance
before editing. Confirm API and architecture evidence first; if the needed API
or semantic authority is unavailable, remain `needs-info` rather than inventing
behavior. A `Documentation` issue still needs an exact observable contract and
current-source check; do not change implementation to make documentation look
true.

For all classifications, distinguish these outcomes in the evidence:

- complete clean result;
- expected finding/output;
- incomplete or unsupported result;
- refusal/resource limit; and
- actual defect.

Never relabel an incomplete result as clean. Never treat a test-only fixture
or a reference-only output as sufficient proof of a native implementation.

## 5. Identify and implement the narrow fix

State the root cause in terms of the owning production path and the invariant
that was violated. Inspect the relevant callers and neighboring implementations
before editing. The change must:

- fix the real path, not only the fixture or symptom;
- preserve established contracts and error boundaries;
- avoid suppression, broad relaxations, speculative abstractions, and unrelated
  refactors;
- preserve source ownership, path/range semantics, deterministic serialization,
  and cache keys where those are in scope; and
- update every affected caller when an interface changes.

Every fixed issue requires durable automated regression coverage. Use an
existing test only if it exposes the actual defect; otherwise add a test at
the appropriate observable seam. Demonstrate failure before the fix and
success afterward, with relevant clean and boundary controls. Assert an
independently known result, not source-code inspection, mock forwarding, or
a tautological recomputation. If a unit seam is unsuitable, commit an automated
CLI/compiler/runtime regression instead. Missing meaningful regression
coverage blocks completion; a one-off smoke run is not a substitute.

For analyzer or quickfix work, the minimum proof is stronger than a unit test:

- actual CLI/compiler/runtime before and after on the minimized repro;
- a genuinely clean control;
- a safe positive case where applicable;
- an unsafe/refusal control where applicable, with source and diagnostics
  unchanged; and
- independent reanalysis showing the target behavior changed without introducing
  new findings or hiding an incomplete scope.

For a quickfix specifically, qualify `--diff` and `--apply` behavior, projected
content, exit status, target-rule reduction, all-rule regression checks, and
late-change/symlink/conflict refusal as relevant. Verify emitted edits by
compiling/running the projected source; compiler warnings, stdout, and exit
status are observable too. A fix that removes the target finding but introduces
another rule finding is not a successful application.

## 6. Verify once after the coordinated change

Run the exact repository checks once after all related edits are complete, not a
private substitute or an administrator-bypassed CI result. The baseline from
`CONTRIBUTING.md` is:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
python3 -m unittest discover -s tools/oracle -p 'test_*.py' -v
```

Run the narrower relevant checks and the actual CLI/compiler/runtime smoke even
when the full baseline is unnecessary; run the full baseline when the change
can affect shared behavior. Follow `.github/workflows/ci.yml` for affected
package matrices, the pinned .NET SDK, TypeScript helper, dogfood, catalog, and
Code Quality gates. Do not silently skip a check: record unavailable tools,
network dependencies, timeouts, and incomplete scope as limitations.

Check the final diff against the issue ledger. Confirm every acceptance
criterion, compatibility condition, refusal control, and non-goal. Re-run the
original bounded feedback loop after the fix; do not claim success from a
narrowed fixture alone. Preserve durable, redacted evidence with source commit,
binary/toolchain identity, commands, exit statuses, before/after outputs,
control results, and exact limitations.

## 7. Complete, stop, or hand off honestly

The issue is complete only when the observable acceptance criteria pass, the
original repro is green, relevant controls remain correct, and repository
checks are recorded. A linked PR may use `Closes #N` only when it contains the
complete actual fix. A partial fix, investigation, refusal, or `needs-info`
state must not auto-close the issue.

Commit, push, merge, and release are separate authorization boundaries:

- Without explicit authorization, leave the implementation in the isolated
  worktree and report the exact diff/evidence; do not commit or publish it.
- If authorized to commit, include only owned changes and use the repository's
  Conventional Commit rules. Never include user work or unrelated generated
  files.
- If authorized to push or open/update a PR, preserve the exact tested head,
  required checks, branch protections, and evidence. Never force-push or bypass
  a failing/pending protected gate.
- Every fixed issue commits durable automated regression tests in the same
  PR: tests that expose the original defect pre-fix and pass post-fix, with
  clean and boundary controls; quickfixes additionally prove runtime, type,
  and effect preservation and refuse unsafe inputs. Reuse valid existing
  regression tests where they already cover the defect, provide an exact
  issue-to-test-symbol mapping. Aggregate test totals, source-code inspection,
  and mock echoes are insufficient. Rule-specific presence/absence can prove
  a detector correction, but cannot establish quickfix behavior preservation.
- When opening or updating a PR, publish a complete body filled from the
  repository templates — `.github/pull_request_template.md`, or
  `.github/PULL_REQUEST_TEMPLATE/release.md` for release PRs — via
  `gh pr create --body-file`, and confirm every heading by live readback
  (`gh pr view --json body`) before requesting review. `Closes #N` only for
  fully resolved issues; never publish a template-default body or verification
  that was not executed.
- Never publish a release, tag, or artifact unless separately requested.

Hand the result to [`skill://work-issues`](skill://work-issues) with:

- issue URL/number and dedup result;
- classification and exactly one current state;
- linked PR and whether it is complete, partial, refused, or blocked;
- source/base/head identities and changed paths;
- exact acceptance results and the red/green or smoke commands;
- clean and unsafe/refusal controls;
- repository checks, artifact locations/digests, and limitations; and
- the next bounded action, if any.

Do not hand off an invented success. If evidence or authority is still missing,
use `needs-info` and name the precise missing input. If the request conflicts
with repository policy or cannot be implemented without weakening a contract,
record the evidence and use `wontfix` only with an explicit, bounded reason.
