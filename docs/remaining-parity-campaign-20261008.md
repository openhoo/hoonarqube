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

## Following package: frozen qualification replay

After PR #867 merged as `e0d4006b5bc333ac8b9a1f8a6d021124a0ecf1b1`,
the following package was frozen at
`9fde2de63ed3efb3d3d4581e03db1a45682d4e5e`. Its executable SHA-256 is
`a2767852b6c7e078081a108d37708f0d658e58c7c7e853aded46a7ea494d43df`.
The [package3 receipt](../tools/oracle/integrated-package3-qualification-20261008.json)
records the new integrated replay. Earlier sections describe PR #867's original
results; the table below is the following package's result.

| Project | Primary identities / reference | Exact ranges and messages / reference | Canonical flows / reference | Active native-only identities |
| --- | ---: | ---: | ---: | ---: |
| Requests | 77 / 77 | 77 / 77 | 77 / 77 | 0 |
| Werkzeug | 230 / 230 | 230 / 230 | 225 / 230 | 0 |
| Commander | 36 / 36 | 36 / 36 | 33 / 36 | 10 |
| chi | 14 / 14 | 14 / 14 | 14 / 14 | 0 |
| Zod | 569 / 594 | 543 / 594 | 410 / 594 | 124 |

All five duplication summaries remain exact; Zod retains all 70 exact clone
relation multisets. Canonical secondary comparisons treat independent flows as
a multiset, preserving duplicate multiplicity, grouping and order inside each
flow. The comparator now accepts an omitted optional reference `msg` as empty,
protected by an automated regression. The 22 TypeVar outer flow-order
differences are presentation differences and are not canonical mismatches.

The package repairs S2681 sibling layout (eight fresh positives and eight
negative controls), S3863 import grouping/ranges (14 fresh identities), and
S6353 quantifiers (all 96 captured Zod findings). It aligns S1444, S6535 and
S6959 messages and supplies Python annotation, assignment, enclosing-control,
Generic parent, return-hint, literal, exception and constant contributor flows.
C# S125 now preserves one equivalent action when reattaching context; its
committed regression captured the original duplicate-alternative panic.

Executed integrated verification: 1,375 JS/TS, 1,297 Python, 1,791 C#, 154 core,
133 CLI unit, five quickfix safety, two semantic integration and 179 oracle
tests; affected-package all-target Clippy with warnings denied; downloaded
0.3.1 self-analysis of 1,480 files with zero Rust:S3776. Current Python quickfix
contracts pass 16/16. TypeScript replay has five successful applications,
three expected no-action cases and one compiler-proof-backed native refusal,
with zero failed cases. The final frozen-binary 60-application C# replay is
still running and remains separate from these completed checks.

Five Werkzeug regex flow findings and 25 missing Zod primary identities
remain. Native-only observations, message differences, security hotspots and
secondary metadata need independent qualification. The 17 licensed C# rules
and missing historical reference artifacts remain explicit external boundaries;
no full parity or released artifact claim follows from this source package.
