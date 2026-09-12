<!-- Use for Hooversion-generated release PRs. Fill every section.
This template governs the PR description, NOT the generated release commit.
Preserve the exact generated subject and body explicitly when squash-merging.
Do not manually invent version bumps/tags or mark future artifact checks passed. -->

## Release scope

<!-- Version and intended tag; included implementation PRs/issues; release notes.
Distinguish newly resolved issues from still-open work. -->

## Source and provenance

<!-- Record the generated release commit, source/base SHA, preparation workflow
run, and exact generated subject/body location. Explain generated version,
catalog, lockfile, and dependency changes, including their provenance. -->

## Pre-merge verification

<!-- Record actual commands/results and links for this exact release candidate.
Include required CI and CodeQL status, the committed issue-to-regression-test
mapping for included fixes, relevant runtime qualification, and compatibility
checks for dependency refreshes. Pending checks remain pending.
Confirm the branch is current with main and the generated commit message will
be supplied explicitly at squash merge, rather than using this PR body. -->

## Post-publication verification

<!-- These checks normally remain PENDING until merge and publication.
After publication, update this section or link a follow-up verification comment:
- Published tag/release points to the intended merged source; publication run succeeds.
- All six expected assets exist; downloaded digests and checksum manifest match.
- All three Cosign bundles and artifact attestations verify against the exact
  repository, source, and release workflow.
- Actual downloaded CLI/service artifacts pass the applicable runtime scenarios.
Record observed results and evidence; preparation success is not publication. -->

## Limitations

<!-- State unverified scenarios, incomplete scopes, unsupported reference rules,
and recovery constraints. Do not claim complete SonarQube/security parity. -->
