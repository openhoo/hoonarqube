# Contributing

Open an issue before changing rule identity, analyzer semantics, catalog
evidence, fixes, or oracle contracts. Small fixes may go directly to a pull
request.
## Issue intake and agent workflow

Use the repository's [canonical issue form](.github/ISSUE_TEMPLATE/issue.yml)
and [label manifest](.github/labels.json). Blank issues are disabled. Every
issue created through the web form, CLI, API, or an agent must use these
English sections, in this order:

1. `Summary`
2. `Classification`
3. `Version and provenance`
4. `Reproduction`
5. `Expected and actual behavior`
6. `Evidence and scope`
7. `Acceptance criteria`

`Classification` has exactly one standalone plain value: `Bug`, `Coverage
request`, `Enhancement`, or `Documentation`. Do not bold it, append a rationale
or `— reason`, or put labels/state/metadata in the field; put rationale in
`Evidence and scope`, `Expected and actual behavior`, or the triage brief.
Triage maps `Bug` to `bug`; `Coverage request` to `enhancement` plus
`coverage`; `Enhancement` to `enhancement`; and `Documentation` to
`enhancement` plus `documentation`. Preserve verified legacy evidence rather
than rewriting it wholesale. `gh`/CLI and API issue creation cannot be blocked
by this intake contract; default-branch tooling flags incomplete forms while
preserving maintainer state and does not certify semantic truth. Validate the
canonical body before publication and after live readback; headings alone are
not sufficient.

The repository-tracked skills are [exploratory-smoke](.agents/skills/exploratory-smoke/SKILL.md),
[triage](.agents/skills/triage/SKILL.md),
[fix-issue](.agents/skills/fix-issue/SKILL.md), and
[work-issues](.agents/skills/work-issues/SKILL.md). A new OMP session
discovers them without a global installer. OMP commands are
`/skill:exploratory-smoke`, `/skill:triage`, `/skill:fix-issue`, and
`/skill:work-issues`. Agents without OMP skill commands may read
`.agents/skills/<name>/SKILL.md` directly; `skill://<name>` works only where
supported. `/triage #92` is request notation, not an OMP command.

Use `/skill:exploratory-smoke` to pin and run bounded real-project probes,
create the mandatory seven-field report, and immediately invoke
`/skill:triage` for a post-publication readiness assessment. When the
migration or publication request explicitly authorizes it, triage may publish
the durable brief and synchronize the category/state labels. Then choose
`/skill:fix-issue` for one explicitly selected ticket **or**
`/skill:work-issues` for a bounded `ready-for-agent` backlog; work-issues
composes fix-issue. Do not apply fixes automatically.

The only canonical state labels are `needs-triage`, `needs-info`,
`ready-for-agent`, and explicitly authorized `wontfix`; keep blockers and
external constraints in issue text. Every campaign-created issue requires the
immediate readiness assessment, including when the publishing agent is also
the triage author.

Keep intake bounded by the canonical form and triage skill: one observable
request, all seven required sections, immutable provenance, and a bounded
reproduction. Read the complete body, comments, and linked PR context; after
the required post-publication check, avoid repeating already-ready tickets
without new evidence; and record the campaign snapshot cutoff so later issues
can be caught up deliberately.
Report suspected vulnerabilities through the [private security policy](SECURITY.md),
never as a public issue.


## Development

Use the repository Rust toolchain and Python 3.
The full workspace test suite also requires the .NET 10 SDK (CI uses 10.0.111).
The compiler-backed C# regression restores and builds isolated fixture projects.

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
python3 -m unittest discover -s tools/oracle -p 'test_*.py' -v
```

Analyzer changes need bad and clean controls. Parity claims need normalized
rule, file, message, and range evidence from the documented oracle; test counts
alone are insufficient.

Commits use Conventional Commits. Pull requests must use a repository pull
request template (see "Pull request templates and publication" below) and
explain compatibility, false-positive, security, and oracle impact.
Maintainers squash-merge using the Conventional Commit pull request title.
Catalog and lockfile changes must accompany their provenance.

## Pull request templates and publication

Every pull request uses a repository template, whether it is opened through
the web UI, `gh`, the API, or an agent: the
[default template](.github/pull_request_template.md) for fixes, features,
refactors, documentation, and maintenance, and the
[release template](.github/PULL_REQUEST_TEMPLATE/release.md) only for
Hooversion release publication PRs. The web UI loads the default template;
CLI, API, and agent callers must explicitly supply the appropriate filled
template. This requirement is enforced by review, not by GitHub itself.

Fill every heading of the chosen template with concrete evidence from the
final integrated state and explain any not-applicable item. Author a complete
body file and publish the PR from it instead of an interactive editor:

```sh
gh pr create --body-file /path/to/filled-body.md
```

Select the release variant explicitly with `gh pr create --template
release.md` or `?template=release.md` in the web URL; the release body is
also published from a filled body file. After creation, read the live body
back with `gh pr view --json body` and confirm every heading and its content
survived publication; correct a truncated or template-default body before
requesting review.

`Closes #N` appears only for issues this PR fully resolves in its verified
scope; partial work references the issue without closing it, and direct
requests without an issue say so. Every fixed issue ships durable automated
regression tests in the same PR — tests that expose the original defect
before the fix and pass after it, with clean and boundary controls — reusing
valid existing regression tests where they already cover the defect.
Quickfix tests must additionally prove runtime, type, and effect
preservation and refuse unsafe inputs. Aggregate test totals, source-code
inspection, and mock echoes do not establish regression coverage. Assert the
observable contract; rule-specific presence or absence is valid for detector
bugs, but cannot prove quickfix safety. One-off smoke evidence supplements,
never replaces, committed tests. Provide an exact issue-to-test-symbol
mapping for every fixed issue. Verification sections
record actual commands, results, and evidence links: the original
reproduction plus bad and clean controls for analyzer changes, before/after
runtime behavior and unsafe-input refusal for quickfixes, with local
verification, pending CI, and work not executed kept separate. Do not
fabricate, paraphrase, or pre-tick verification.

Publish independently completed issue packages as their own incremental PRs
instead of one combined PR with unfinished unrelated work. Merge only when
authorized, every required protected check is green, and every fixed issue
carries its committed regression coverage; repair a red required check rather
than bypassing it, and never merge while required coverage is missing.
Release PRs use the release template:
pre-merge verification is complete at merge time, while post-publication
verification (publication run, assets, digests, Cosign bundles, attestations,
downloaded-binary qualification) stays explicitly pending until the artifacts
exist. The Hooversion-generated release commit subject and body are preserved
exactly at squash merge; templates govern the PR description, never the
generated commit message.
