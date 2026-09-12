---
name: work-issues
description: "Execute a finite, explicitly authorized issue backlog through isolated fix worktrees and report verified outcomes."
disable-model-invocation: true
---

# Work issues

Use this skill only when the user explicitly asks to execute issue work (for
example, fix or implement issues). It composes with the repository's sibling
`/skill:triage` and `/skill:fix-issue` skills. It is an execution coordinator,
not a replacement for triage, and it never silently expands a backlog.

This is an independent adaptation of the bounded implementation and two-axis
review ideas in:

- <https://github.com/mattpocock/skills/blob/main/skills/engineering/implement/SKILL.md>
- <https://github.com/mattpocock/skills/blob/main/skills/engineering/code-review/SKILL.md>

## Invocation and authorization

Every run has a finite scope and an explicit action contract.

- A scope may name issue numbers, a finite list, a label/category/priority
  filter, a milestone, or a finite maximum. If the user gives no scope, use
  the conservative default: **one OPEN issue carrying `ready-for-agent`**,
  selected by priority and then age (defined below).
- A request to execute/fix/implement is authorization for the source changes
  needed by that stated scope. Do not infer permission to create a pull
  request, merge it, change tracker metadata, close issues, or release from
  that wording; those actions require explicit authorization in the same
  request or an earlier still-applicable contract.
- A request that only asks to discover, list, or propose issues is read-only.
  Select and expose the candidate set and contract, but do not edit source,
  issues, labels, comments, branches, or pull requests.
- A multi-issue run must have a finite count or finite named set. Never turn a
  filter into an unbounded autonomous backlog. Stop at the stated limit and
  require a new explicit invocation to continue.

Before the first source write, expose the selected issue IDs and, for each,
the classification, evidence boundary, dependency result, intended change
surface, permitted pull-request/merge action, and stop criteria. This is a
contract disclosure, not a request for needless confirmation: proceed when the
user already granted the required permission; ask only for a permission that
is genuinely absent.

## Phase 1: read-only discovery

Discovery makes no modifications. Do not add or remove labels, edit issue
bodies, add comments, assign work, create branches or pull requests, close
issues, or write source while discovering candidates.

For every issue that could enter the selected set, read the complete current
record before deciding:

1. state, number, title, labels, creation time, and current milestone;
2. the full body and complete comment/event history (every comment/event),
   plus prior decisions or audit notes; filter only the final report, not
   discovery (never read only the first or latest comment);
3. all dependency and related-issue links, including references in linked
   pull-request bodies and comments;
4. every active pull request, its base/head, review/check state, and whether it
   is merged, closed, or still active;
5. repository truth needed to judge the claim, including the relevant
   `CONTRIBUTING.md`, `PARITY.md`, `QUICKFIX.md`, workflow protections, and
   executable implementation registries when an analyzer rule is involved.

Do not treat a search result, issue title, catalog row, green compile, or
single comment as the complete record. User-reported failures are evidence;
do not rerun them merely to dispute the report.

### Readiness contract

An executable candidate is an issue whose GitHub state is `OPEN`, whose
labels include `ready-for-agent`, whose scope and acceptance criteria are
concrete enough to delegate, and which has no unresolved blocker. `OPEN` is
the tracker state; `ready-for-agent` is a required readiness label, not a
second state. Do not invent another readiness or hand-off label. An issue
that lacks `ready-for-agent` remains unready even when it is OPEN.

The issue classification must be one of:

- **Bug**
- **Coverage request**
- **Enhancement**
- **Documentation**

The category is `bug` or `enhancement`; coverage and documentation are
supplements, not third categories. Preserve existing supplemental labels,
including verified forms such as `priority:critical`, `priority:high`,
`priority:normal`, `priority:low`, and `language:*`, plus any existing
`area:*` or symptom labels; never create or rename labels in this workflow.
Do not guess a missing priority, area, language, symptom, or readiness label.

Revalidate readiness immediately before delegation, using the completed
triage evidence rather than restarting triage:

- Read issue text and linked pull requests for an explicit `blocked by #N`.
  Resolve each referenced issue/PR and its current behavior/check state.
- An unresolved dependency, active implementation PR, missing reproduction or
  evidence, unclear acceptance criterion, or incomplete authorization makes
  the issue unready. Route it to `/skill:triage` with the exact missing fact;
  do not relabel it or place it in a replacement queue.
- A dependency being closed is not proof that its behavior is present. Require
  evidence of the behavior or an explicit verified decision before treating
  the dependent issue as ready.
- Do not duplicate an active PR unless the user explicitly named that PR or
  authorized taking it over. An active PR without verified completion is not a
  fixed issue.
- Missing evidence or dependency information is described in the report, not
  converted into `ready-for-agent` automatically.

For this repository specifically, the frozen Sonar catalogs are definitions,
not proof of executable coverage. Use language executable registries and
actual profile/runtime evidence to assess implementation. A reference or
scanner disagreement alone is not a defect claim. Incomplete analysis is not
a clean result. A quick-fix issue needs compiler/runtime before-and-after
behavior and refusal controls, not only emitted text or a successful compile.

### Deterministic selection

Filter by the explicit scope first, then retain only OPEN, ready candidates.
Order candidates by:

1. priority: `priority:critical`, `priority:high`, `priority:normal`,
   `priority:low`;
2. oldest creation timestamp;
3. lowest issue number as the final deterministic tie-breaker.

An absent priority sorts after `priority:low` and is reported as absent; it is
never silently promoted. The default scope selects only the first candidate.
If a named issue is not ready, report it as blocked/unready and do not silently
replace it with a different issue unless the user's finite scope explicitly
permits fallback selection.

## Phase 2: bounded delegation

Delegate each selected issue through `/skill:fix-issue #N`; do not implement a
selected issue directly in this coordinator. Give the sibling the complete
issue record, prior triage evidence, dependency resolution, acceptance
criteria, and the exact permitted PR/merge action. The sibling must distinguish
an actual behavior-preserving fix from unsupported scanner differences and
must return focused reproduction/test evidence.

Use one isolated worktree per issue. Independent issues may be delegated in
parallel only after their likely change surfaces are disjoint. Treat shared
core modules, registries, catalogs, lockfiles, generated artifacts, CI, and
unknown overlap as conflicting: do not parallelize them. Assign one
serialized integration owner for conflicting changes, apply them in a stable
order, preserve unrelated dirty work, and resolve conflicts explicitly rather
than overwriting another worktree.

Children may run focused tests, reproductions, compiler/runtime checks, and
other evidence needed for their issue, but they must skip full-suite
validation. After all selected work is integrated, run shared verification
once at the parent level, covering the combined change and repository gates.
Do not claim completion from a green compile, a passing narrow check, or an
open pull request alone.

The coordinator must stop dispatching when the finite limit is reached. Stop
an individual issue when its dependency, evidence, authorization, focused
verification, or integration contract fails. Stop the whole run when an
unrelated user change would be overwritten, the authorization boundary
changes, a shared integration conflict cannot be resolved safely, or the
combined verification/gate fails; preserve artifacts and report the exact
boundary. Do not start future releases or other backlog items automatically.

## Completion and tracker safety

A fix is complete only when the sibling's evidence demonstrates the requested
behavior, regression/refusal controls where relevant, and the integrated
change passes the required verification, followed by the explicitly
authorized PR/merge action. A successful local build is not completion.

Never speculate a closure, rewrite unrelated labels, discard audit notes, or
claim an issue is resolved because a PR is merely open or green. Create,
update, merge, or close tracker objects only when the user explicitly granted
that operation and repository protections allow it; never bypass CI, review,
branch, or merge protections. Do not schedule releases or claim unsupported
analyzer parity.

If a continuation is explicitly requested, revalidate only the current state,
readiness, dependencies, active PRs, and the prior completion evidence. Reuse
completed triage; do not restart it from scratch. A newly unready issue goes
to `/skill:triage`, and the run remains bounded by the new explicit scope or
limit.

## Report

End every run with separate sections named **Fixed**, **PR-open**, and
**Blocked**. For every selected issue, include:

- issue number/title, classification, priority, and final state;
- the exact integrated commit/head and, for a merge, the merged head;
- focused and shared verification commands/results, including refusal or
  runtime evidence when applicable;
- pull-request number, base/head, and exact check/gate results when one was
  authorized; and
- remaining scope, unresolved dependency, missing permission, or next
  explicitly authorized action.

`Fixed` means the tested complete behavior is integrated and the authorized
merge/closure contract has actually completed. `PR-open` means the tested
candidate and authorized PR exist, but it is **not** resolved or fixed until
its required merge/completion evidence exists. `Blocked` includes unready
issues, failed verification, unresolved dependencies, conflicting worktrees,
missing authorization, and active PRs that are not verified complete. Always
report skipped candidates and the finite remaining scope so continuation is
explicit rather than autonomous.
