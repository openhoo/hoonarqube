# Project duplication investigation — 2026-10-07

This follow-up uses the same five pinned source scopes and actual SonarQube
Community Build `26.9.0.129388` captures described in the
[real-project campaign](real-project-campaign-20261007.md). It investigates CPD
separately from finding identities and source-size metrics. The portable
[qualification receipt](../tools/oracle/project-duplication-qualification-20261007.json)
retains source pins, options, executable/capture digests, before/after values,
and the remaining mismatch.

## Configuration and comparison

Native defaults require 100 normalized tokens and ten physical lines for these
non-Java inputs. Scanner arguments explicitly set empty `sonar.cpd.exclusions`.
The live project settings API returned no persisted overrides for exclusions or
Python/JavaScript/TypeScript/Go minimum-token or minimum-line settings. This
confirms the captured configuration rather than certifying lexical equivalence.

The accepted integrated executable SHA-256 is
`ac52b0730ce61812eaf01b0999db228fc1e4a72383431ef9a873d670dce39c56`, recorded
as `acceptance` at source head `96a282c`, including fix `e2124e9`.
Native and reference duplicated line/block counts are compared exactly.
Native density uses full precision; Sonar's one-decimal display is compared
with a rounded native percentage. A rounding match is not a bitwise JSON match.
All 239 source paths and the 20 aggregate file/line/code/comment comparisons
remain aligned in this integrated replay.

| Project | Duplicated lines before → after / reference | Blocks before → after / reference | Density after / reference display | Result |
|---|---:|---:|---:|---|
| Requests | 0 → 0 / 0 | 0 → 0 / 0 | 0.0 / 0.0 | selected measures match |
| Werkzeug aligned | 59 → 32 / 32 | 6 → 2 / 2 | 0.147039 / 0.1 | counts and rounded display match |
| Commander | 0 → 0 / 0 | 0 → 0 / 0 | 0.0 / 0.0 | selected measures match |
| Chi | 56 → 56 / 56 | 2 → 2 / 2 | 1.262683 / 1.3 | counts and rounded display match |
| Zod | 7177 → 7177 / 5084 | 424 → 424 / 1130 | 18.961691 / 13.4 | different |

## Repaired physical-span threshold

The native matcher checked physical line thresholds using synthetic zero-byte
structure markers. Report projection subsequently discarded those markers.
Consequently, an eight- or nine-line reported Python clone could incorrectly
pass the configured ten-line minimum.

In Werkzeug's `datastructures/structures.py`, the reference reports only
65–80 and 856–871: two sixteen-line occurrences. The native baseline also
reported 256–264, 711–719, 713–720, and 882–889, which fall below ten lines.
The repaired integrated replay retains exactly the two reference occurrences,
reducing duplicated lines from 59 to 32 and blocks from six to two. Chi's
reference and native ranges also agree: `tree.go` 470–497 and 518–545.

Eligibility and report projection now share source-bearing endpoints. A sorted
per-file token index finds endpoints by binary search, preserving bounded work
on marker-heavy inputs. Synthetic units still contribute to the established
normalized-token threshold; Java's statement threshold is unchanged.

The new regression was observed failing before repair. Focused tests qualify
nine real rows failing a ten-row minimum, equality at the nine-row threshold,
preservation of the token threshold, and synthetic-only matches producing no
source groups. All 18 duplication tests and core all-target Clippy with
`-D warnings` passed. This is a fix to the owning matcher, without project-name
or fixture-specific exceptions.

## Why Zod remains different

The live reference's 1130 reported blocks equal 1130 distinct file/line-range
occurrences; the discrepancy is not explained by duplicate counting of the
same reported ranges. The native matcher retains 424 distinct byte spans.
Reference grouping and token normalization therefore require their own work.

Concrete captured boundaries illustrate the difference:

- `v4/classic/checks.ts` starts at line six in the reference and line five in
  the native clone; its mini counterpart starts at eight versus seven.
- `v4/locales/ar.ts` has nineteen reference groups. A reference locale clone
  starts at line five, whereas a broad native locale group starts at line one.
- `v4/classic/from-json-schema.ts` has no reference CPD groups. Native output
  includes a self-overlapping repeated-string-list clone at 35–101 versus
  36–102, plus a later clone pair.

The inspected SonarJS source at
`ab3d9f370626e3bf35fb6005962de9ce567cb845`,
`packages/analysis/src/jsts/analysis/file-artifacts.ts`, excludes import
statements and selected single-variable `require` declarations from CPD. It
normalizes string-token images with a JSX-attribute exception. Native source
facts retain import tokens, structural statement markers, and their own
interpolated-literal representation. The native matcher also deliberately
retains overlapping maximal runs under an existing tested contract.

These observations explain concrete semantic boundaries; they do not prove
that one token exclusion would close every Zod difference. Changing a minimum
threshold or hiding native groups would not establish the required lexical
and grouping equivalence. Four selected project metric comparisons now match,
while Zod remains explicitly different. Complete CPD parity is not claimed.
