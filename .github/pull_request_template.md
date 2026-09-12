<!-- Use this template for fixes, features, refactors, documentation, and maintenance.
Fill every section with concrete information; explain any not-applicable item.
Use .github/PULL_REQUEST_TEMPLATE/release.md for Hooversion release PRs.
Do not claim unexecuted verification, complete parity, or unresolved issue closure. -->

## Summary

<!-- What changes, why it is needed, and the observable outcome. -->

## Change type and scope

<!-- Fix / feature / refactor / documentation / maintenance.
Name affected languages, rules, profiles, APIs, or workflows; identify non-goals. -->

## Related issues

<!-- Use Closes #N only for issues fully resolved by this PR's verified scope.
Use Related to #N for partial work. Explain direct requests with no issue. -->

## Verification

<!-- Every fixed issue requires committed automated regression coverage.
Map each issue to its test file/symbol and show that the regression exposes the
original defect before the fix and passes afterward. Reuse an existing test only
when it demonstrably covers the defect. Include relevant clean/boundary cases.
For quickfixes, test before/after behavior and unsafe-input refusal, not just
finding counts. One-off smoke evidence supplements, never replaces, regression tests.
Record actual commands/results and evidence; distinguish pending CI and unexecuted
checks. Do not close an issue or merge while required regression coverage is missing. -->

## Compatibility and risks

<!-- Explain output/API compatibility, false-positive/false-negative impact,
security implications, and oracle/parity boundaries. Include provenance for
catalog or dependency changes; do not equate native controls with reference parity. -->

## Limitations

<!-- State remaining limitations, dependencies, or excluded acceptance criteria.
Write None only when justified. Publish independently completed issue packages;
do not include unfinished unrelated work or bypass required checks to merge. -->
