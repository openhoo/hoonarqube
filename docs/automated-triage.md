# Automated issue intake with Jev

The first automation stage extends the existing Issue intake workflow. It
evaluates the content of new, edited and reopened issues and follows up when
people add, edit or delete discussion comments. It uses the existing HooLLM
`typesafe/jev-1.13` route at `https://ai.openhoo.ai/v1/decisions`.

Jev answers fixed Choice questions; it cannot execute commands or author free
text. Each answer must match the expected schema, known Jev 1.13 model identity,
complete probability distribution and a minimum 0.95 confidence and selected
probability. Unknown or less certain decisions remain for manual triage.
Model confidence is a selection threshold, not proof of factual correctness.

## What happens to an issue

1. Existing structural intake checks the seven canonical form fields. It
   retains its existing ownership rules and maps the reporter's form category.
2. For a structurally valid open issue, Jev reads the full body and discussion,
   excluding only the two bot-owned intake notes. It provisionally classifies
   the request, identifies a single explicit language/area, assesses stated
   user impact and checks for specific missing information.
3. A bounded writer adds language, area and priority labels only when supported
   by confident answers. It never replaces a human-owned label or undoes a
   human's explicit label removal. Corrected reports can update labels that
   are still provably owned by this automation.
4. High-confidence information gaps produce specific questions from reviewed
   English templates and `needs-info`, unless a maintainer state takes
   precedence. Replies are included on the next pass. Once its questions are
   answered, the bot returns its own `needs-info` to `needs-triage`.
5. One persistent AI-disclosed note records the latest result. An input hash
   avoids repeated evaluations and duplicate comments. Bot comments do not
   trigger the workflow. Label writes and the final note are read back.

The model's category is recorded as a provisional recommendation. The form's
category and maintainer decisions retain precedence. Defect qualifiers such
as `false-positive`, `false-negative`, `regression`, `crash` and `unsafe-fix`
require the existing evidence-bound triage procedure and are not inferred by
this intake stage. Multiple or protected states stop automatic processing.

This stage does not verify linked artifacts, reproduce defects, establish
runtime coverage, give an implementation brief, assign work, set
`ready-for-agent` or `wontfix`, close issues, create fixes or review PRs.
Those steps remain separate. Cube execution can be connected when actual
reproductions and implementation are introduced; metadata intake runs in the
repository's existing GitHub Actions workflow.

## Operation

The operator stores a dedicated Jev-only HooLLM virtual key as the repository
Actions secret `HOONARQUBE_JEV_KEY`. Provider keys and the HooLLM master key are
never placed in GitHub. The virtual key should have a small budget and request
limit. The existing HooLLM route determines the enabled Jev providers; this
workflow does not change provider order, credentials or fallback behavior.

Set repository Actions variable `HOONARQUBE_JEV_TRIAGE_ENABLED=true` to enable
the semantic stage. Removing it or setting it to `false` disables Jev without
disabling structural intake. The only repository permissions are
`contents: read` and `issues: write`. The job checks out the trusted default
branch, never a contributor's ref or code from an issue.

Use the Issue intake workflow's manual `verify` mode to run eight synthetic
cases against the configured key without creating or editing an issue.
The `triage` mode requires an existing open issue number. Events and manual
triage for the same issue share a concurrency group. A rerun with unchanged
input is a no-op after verified completion.

There is one bounded provider request per new input, no client-side retry,
no request-supplied endpoint/model override and no redirect following. Input
over 48,000 UTF-8 bytes is left for manual handling rather than truncated;
provider output is capped at 128 KiB and the request timeout is 45 seconds.
API failures and malformed replies fail the job without semantic label or
comment writes. A suspected vulnerability in Hoonarqube itself, or uncertain
security routing, skips semantic writes for private/manual review. An analyzer
report concerning a security rule is not itself classified as a vulnerability.

The bot stores its ownership intent before mutations. Interrupted writes keep
the note incomplete and can be retried. Current issue content, labels and
timeline are compared again before mutation; unexpected readback changes fail
the run for inspection. GitHub's comment/label operations are not atomic, so
maintainers should inspect a failed run before retrying after concurrent edits.

## Validation

```sh
node --test .github/scripts/issue-intake.test.cjs .github/scripts/issue-jev-triage.test.cjs
```

Tests cover concrete information requests, discussion replies, manual
overrides, stale inputs, interruption recovery, forged markers, malformed
model responses, API limits and unchanged-input deduplication. Synthetic live
fixtures cover documentation N/A, multiple languages, unstated impact,
prompt-injection text and private security routing. They are bounded smoke
evidence, not a claim of accuracy over unseen issues. The evaluator reports
wrong confident decisions separately from abstentions and automated coverage;
an uncertain answer is not counted as a correct classification.

Typed decisions follow the [TypeSafe Choice API](https://docs.typesafe.ai/primitives/choice).
The public HooLLM alias remains fixed; the validated reply may use OpenRouter's
`typesafe/jev-1.13` (including dated revisions), OpenCode's `jev-1.13-free`, or
TypeSafe's `jev-1.13` / `jev-1.13.0` for that route.
