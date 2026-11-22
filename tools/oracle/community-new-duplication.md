# New-code duplication on five public changes

Community Build 26.9.0.129388 and HoonarQube both ignored **two actual
threshold violations** on small FastAPI changes. Both failed the gate on a
larger FastAPI change, although they counted different duplicated lines.
For Yjs, one native gate was unavailable because repeated lines made the
baseline mapping ambiguous.

Each row covers one source file, with a project-assigned gate that allows at
most 3% duplicated lines on new code. The base and candidate were analyzed
as separate revisions of the same project. Values are duplicated / new lines;
`ignored` means the measured value exceeded 3% but did not fail the gate.

| Project and file | Base → candidate | Community 26.9 | Native |
| --- | --- | --- | --- |
| Yjs `src/utils/ids.js` | `53fd0285 → 486d5677` | 65/86 (75.5814%), fail | unavailable, exit 2; no exact native count |
| Yjs `src/structs/Item.js` | `ebae7a3e → ee37f0a0` | 0/19 (0%), pass | 0/19 (0%), pass |
| FastAPI `fastapi/routing.py` | `e0f8cadf → b78c8226` | 21/35 (60%), fail | 20/35 (57.142857%), fail |
| FastAPI `fastapi/params.py` | `7cb19539 → 5d5666be` | 2/10 (20%), ignored | 2/10 (20%), ignored |
| FastAPI `fastapi/param_functions.py` | `2bb28066 → 8b0090c3` | 14/14 (100%), ignored | 14/14 (100%), ignored |

The clean 19-line Yjs change passed normally, with no ignored condition.
The two smaller FastAPI changes demonstrate suppression; the captured pairs do
not test the live reference at exactly 20 lines. This is a comparison of five
file-scoped changes, not a claim about full-repository duplication parity.

**Excluded:** the Yjs pairs `99e3e95a → 76b7d0b6` (March 5–6, 2019) and
`76b7d0b6 → 0a5753c1` (March 6–7, 2019) had no retrievable paired analysis
result. Their native observations do not establish a Community comparison.

## Reproduce

From the source root, with a built native CLI in `target/release`:

```sh
python3 tools/oracle/community_new_duplication.py target/release
```

This fetches pinned public Git objects and runs ten fresh native analyses
in temporary source checkouts. For an offline run, add
`--yjs-repository /path/to/yjs --fastapi-repository /path/to/fastapi`.
The local repositories must contain the pinned revisions and their history.
Add `--output /path/to/replay.json` for a machine-readable result.

The [captured reference and native results](community-new-duplication-20261122.json)
include the scanner image and server version, successful compute tasks, paired
analysis IDs, gate assignment, selected base, and both Git trees, blobs and
source SHA-256 digests. The replay verifies source bytes before scanning,
reconstructs changed line numbers with Git and, where native membership is
unambiguous, independently intersects them with the scanner's duplication
occurrences. It checks exit codes and individual gate decisions. An ambiguous
native result cannot pass this test as a green gate.

If the original capture directory is available, add `--capture-root /path/to/new-duplication`
to verify the saved scanner commands, logs, compute-engine responses, selected
period, gate, and measures against the compact receipt. Neither mode starts a
new Community analysis. Run the negative controls with
`python3 -m unittest discover -s tools/oracle -p test_community_new_duplication.py`.
