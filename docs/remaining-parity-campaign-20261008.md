# Integrated real-project continuation — 2026-10-08

This package continues the [October 7 campaign](remaining-parity-campaign-20261007.md)
from merged PR #866. It binds the five unchanged source scopes and captured
SonarQube Community Build 26.9.0.129388 observations to the current integrated
executable. The [portable receipt](../tools/oracle/integrated-real-project-qualification-20261008.json)
records source commits, executable/report/reference hashes and actual commands.

## Finding qualification

The reference's active profile filters the native comparison. Rule/path/range
multiplicity is compared independently from message equality. Native findings
from reference-inactive rules remain in the underlying report. Commander and
Zod use explicit pinned TypeScript compiler contexts; Python uses an explicit
`src` import namespace. Syntax-only runs retain their distinct observations.

| Project | Files | Matched primary identities / reference | Exact identities and messages / reference | Active native-only identities |
| --- | ---: | ---: | ---: | ---: |
| requests | 19 | 77 / 77 | 77 / 77 | 0 |
| werkzeug-python | 53 | 230 / 230 | 230 / 230 | 0 |
| commander | 7 | 36 / 36 | 35 / 36 | 15 |
| chi | 35 | 14 / 14 | 14 / 14 | 0 |
| zod | 125 | 533 / 594 | 465 / 594 | 152 |

Python matches all 398 captured active rules on Requests and Werkzeug: 307/307
primary findings including messages. Its 55 cognitive findings additionally
match 902 ordered supporting locations. Other Python flows retain explicitly
recorded differences; this result does not certify all secondary metadata.
The [Python qualification](../tools/oracle/python-current-qualification.md)
explains current detector and quickfix boundaries.

JavaScript/TypeScript repairs include logical-chain and loop-header cognitive
scoring, function-token anchors, duplicate-body ownership, construct/call
signatures, default-parameter annotations, catch exemptions, template delimiter
locations and switch clause counting. Message equality remains different for
one Commander finding and additional Zod findings despite matching identities.

## Duplication

All five pinned scopes retain matching duplicated-line/block/file counts and
one-decimal displayed density. Zod matches 5,084 duplicated lines, 1,130 blocks,
68 files and all 70 captured clone relation multisets, including every file and
inclusive line range. The matcher now preserves lexical template tails and JSX
attribute images, retains necessary contained relations and finds occurrences
inside longer maximal matches. General cross-language equivalence is not claimed.

Committed controls include
`javascript_cpd_template_heads_normalize_but_tails_remain_lexical`,
`javascript_template_tail_differences_do_not_create_clones`,
`javascript_clone_relations_include_occurrences_inside_longer_matches`, and
`js_containment_cannot_pool_unrelated_groups_or_file_sets`. Retained failing
baseline runs and fresh reference controls qualify the repaired defects.
`test_duplication_relations.py` rejects foreign paths, incomplete native reports
and altered clone relations while preserving occurrence multiplicity.

## Executed verification

The integrated checkout passes 154 core tests, 1,370 JS/TS tests, 1,295 Python
tests, 133 CLI unit tests, five CLI quickfix safety tests and two CLI semantic
integration tests. All 178 oracle tests and selected-package all-target Clippy
with warnings denied pass. The physical macOS temporary path preserves symlink
refusal semantics. The 16 current Python quickfix contracts pass against this
integrated executable, retaining original historical failures independently.
`strict_quickfix_preserves_profile_during_planning_and_reanalysis` protects the
profile repair; semantic CLI tests protect both namespace root choices.

Required hosted checks and pinned 0.3.1 self-analysis remain publication/merge
states recorded separately. No unrequested release artifact is certified by
these source tests.

## Remaining qualification

Zod retains 61 missing primary identities and 152 active native-only identities
in the explicit compiler replay. Messages, secondary locations and quickfix
contracts remain independent dimensions. The frozen historical corpus and 17
licensed C# sensor rules retain the boundaries in
[qualification boundaries](qualification-boundaries-20261007.md).
Further verified packages continue independently; this package closes no issue
by inference and makes no full SonarQube parity claim.
