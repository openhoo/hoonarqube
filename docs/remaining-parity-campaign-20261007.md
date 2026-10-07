# Remaining real-project parity work — 2026-10-07

This continuation starts from published Hoonarqube 0.11.0, release commit
`369db7aa17fb16a4358ffe81323846519009449f`. It uses the five pinned projects and
source scopes in [the first campaign](real-project-campaign-20261007.md).
Remaining detector differences, duplication, secondary locations and fixes are
qualified separately. A repair of one dimension does not establish full parity.

## Reference recovery

The original campaign container was confirmed stopped. Its Sonar data lived in
tmpfs, so restarting it created a fresh database and invalidated the previous
credentials. The continuation reinitialized this owned instance and rescanned
all five projects. The server and scanner image digests remain unchanged.
Fresh captures reproduce all 239 indexed files, all 717 file metric cells and
the original issue totals: Requests 77, Werkzeug 241, Commander 36, chi 14 and
Zod 594. Historical captures remain immutable.

## JavaScript and TypeScript CPD row units

The native matcher previously indexed raw syntax-token windows, including
synthetic statement markers and import declarations. The reference indexes
complete token-bearing rows, omits imports and selected single-variable
`require` declarations, and reduces each consecutive run of identical row
images to its first and last row. Token positions still determine the minimum
token threshold after this reduction.

The repair applies these row units to JavaScript and TypeScript. Java and other
language streams retain their existing matching path. Source metrics and
comment collection still traverse excluded module declarations. TypeScript
import-equals declarations, multiple variable declarators, ordinary calls and
nested `require` calls retain their observed distinct scope.

Fresh real-server controls establish these outcomes at default thresholds:

| Control | Reference duplicated lines / blocks | Repaired native |
|---|---:|---:|
| Two files sharing 20 import declarations and a short function | 0 / 0 | 0 / 0 |
| One list with 70 differently spelled normalized strings | 0 / 0 | 0 / 0 |
| Two identical 16-line functions | 32 / 2 | 32 / 2 |

Committed regressions map these defects to
`javascript_imports_do_not_satisfy_duplication_thresholds`,
`javascript_repeated_identical_token_lines_do_not_create_self_clones`, and
`javascript_cpd_preserves_complete_positive_line_blocks`. Source-facts controls
also qualify module exclusion boundaries and metric preservation.
The first two regressions failed against the pre-repair implementation.
All 149 core tests and focused all-target Clippy pass. The downloaded pinned
0.3.1 analyzer reports no Rust cognitive-complexity finding on the changed files.

The first row-unit replay preserves all source metrics and the four previously
matching duplication summaries. Zod improves from 7177 lines / 424 blocks to
6466 / 392, but still differs from the reference 5084 / 1130. Token images and
group containment remain separate work; these initial results are not a CPD
parity claim.

## Integrated Python and typed JavaScript fixes

Python declaration ranges now cover the reference parameter/collection spans.
Direct TypeVar annotations preserve declaration provenance and exclude aliases
and unrelated annotations. Collection conversions distinguish chained boundary
comparisons, direct constant comprehensions, mutable values, shadowed constructors
and identity comprehensions. Regressions include
`remaining_s6659_exempts_chained_boundary_comparisons` and the S7496/S7519
collection boundary controls in the Python test module.

The TypeScript helper supplies implicit string-coercion and `.at` receiver
evidence. Commander requires an explicit compiler project and TypeScript 6.0.3
module to qualify the eight S6551/S7755 identities. The qualification config
extends Commander's source config, uses its ESNext target and disables implicit
ambient `@types` discovery. Standalone syntax fallback is a distinct result.
Zod export-head S7726 ranges match all 63 observations; mutable static property
S1444 key ranges match all 35, with readonly edits attached to the new ranges.
Committed rule tests cover declaration comments, arrow tokens and property edits.

The integrated CLI replay on all five unchanged project scopes produces:

| Project | Matched identities | Native-only | Reference-only |
|---|---:|---:|---:|
| Requests | 72 | 129 | 5 |
| Werkzeug | 216 | 309 | 25 |
| Commander (syntax context) | 29 | 281 | 7 |
| chi | 14 | 21 | 0 |
| Zod (syntax context) | 352 | 5347 | 242 |

These compare rule, path and range multiplicity. Native-only totals also contain
rules inactive in the reference profile. They are not all false positives;
message/flow and compiler qualification remain separate gates. In aggregate,
matched identities improve from the published campaign's 574 to 683 and
reference-only observations fall from 388 to 279 in the syntax-context replay.
The explicit Commander compiler replay additionally closes its seven previously
missing identities.

All 149 core tests, 132 CLI unit tests, six CLI integration tests and 173 oracle
tests pass in the integrated checkout. Oracle tests honor `CARGO_TARGET_DIR`;
macOS runs use a physical temporary-directory path to preserve symlink refusal
checks. Specialist language suites qualify their committed regression controls.
The finite historical corpus, quickfix and Enterprise boundaries are recorded in
[qualification boundaries](qualification-boundaries-20261007.md).
