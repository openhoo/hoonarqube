# Read-only TypeScript replay: React Hook Form and Zod

On November 20, 2026, the executable tested in #970 completed both public
scans from clean, read-only checkouts. The replay uses the original SonarQube
Community Build `26.9.0.129388` captures and effective profiles from
[wave 2](public-corpus-wave2-20261120.md) for React Hook Form and
[wave 1](public-corpus-20261120.md) for Zod. The
[receipt](public-corpus-typescript-replay-20261120.json) records the pinned
sources, binary and report digests, and results. The original receipts and
campaign totals describe the original executions and remain unchanged.

| Project | Identical source files | Equal per-file metric values | Matching primary findings | Hoonarqube only | SonarQube only |
|---|---:|---:|---:|---:|---:|
| React Hook Form | 124 | 372 / 372 | 242 | 43 | 68 |
| Zod | 125 | 375 / 375 | 500 | 58 | 81 |

Both reference scanners exited successfully and both compute tasks succeeded
with no parser warnings. Each native report completed with exit code zero and
recorded its final checkout check. Both comparisons cover the full indexed
file lists with equal bytes; no result uses only the shared-file subset. The
finding counts are for shared active rules with equal declared parameters,
matched by rule, relative file, and UTF-16 primary range. Both native reports
marked TypeScript compiler context missing in these runs. The comparison
qualifies the source scopes and reported findings, with the differences above;
it does not qualify compiler-assisted or Enterprise behavior.

The earlier CLI (`b8411407357d1eabf8d2bce59035d7343996e6ec`) reproduced the
checkout side effect on separate writable clones using the same arguments.
It created a helper under React Hook Form's `src`, so the guard rejected the
scan even though the analyzer reported success. In Zod, the helper appeared
outside `packages/zod/src`; the guard archived the known helper and accepted
the scan. The tested #970 CLI needed no such cleanup. Both new reports were
byte-identical to the corresponding control reports. The read-only checkout
inventories, including file contents and modes, matched before and after.

## Replay the native scans against the captured references

Use Python 3.11 or newer from the repository root. Prepare separate clones
at the commit and tree in the receipt, and remove write bits from their
files and directories without following symlinks. Set `rhf`, `zod`, `native`,
`campaign`, and `out` to absolute paths. `out` must be a new private output
directory outside the source clones; `campaign` contains `wave2` and `corpus`
with their original `captures`, `profiles/effective.json`, and
`replay-projects.json`. The two campaign guides document how to collect
reference evidence if the original captures are unavailable. A fresh
collection has its own capture hashes and timestamps. The #970 commit must
also be present in this Git repository for rule registration verification.

```sh
PYTHONPATH=tools/oracle python3 - "$campaign" "$native" "$rhf" "$zod" "$out" <<'PY'
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import public_corpus_capture as capture
import public_corpus_summary as summary
import public_corpus_wave2_capture as wave2
from parity import read_json, write_json_atomic

campaign, binary, rhf, zod, out = map(lambda p: Path(p).resolve(), sys.argv[1:])
receipt = read_json(Path("tools/oracle/public-corpus-typescript-replay-20261120.json"))
assert capture.oracle.digest(binary) == receipt["native"]["sha256"]
for setting in ("HOONARQUBE_TYPESCRIPT_PACKAGE", "NODE_PATH"):
    os.environ.pop(setting, None)
os.environ["GIT_OPTIONAL_LOCKS"] = "0"
os.umask(0o077)
out.mkdir()
rules = subprocess.check_output([binary, "rules", "list", "--json"])
(out / "native-rule-catalog.json").write_bytes(rules)
catalog = {r["external_key"]: r["rule_type"] for r in read_json(out / "native-rule-catalog.json")}
infra, _, _ = summary.verified_boundaries(receipt["native"]["verified_code"])
wave2.install_capture_constraints()
for state, name, root in ((campaign / "wave2", "react-hook-form", rhf), (campaign / "corpus", "zod", zod)):
    ref = state / "captures" / name
    original = next(r for r in read_json(state / "replay-projects.json") if r["name"] == name)
    assert original == read_json(ref / "source.json")
    row = {**original, "path": str(root)}
    assert not os.access(root, os.W_OK)
    args = SimpleNamespace(output=out, binary=binary, reference_only=False,
                           native_only=True, no_shared_cache=True, state=out)
    status = capture.execute(row, args, None, "")  # checks the 5 GiB floor before each scan
    assert status["native"]["status"] == "complete" and status.get("ended_at_utc")
    result = summary.summarize_project(ref, read_json(state / "profiles/effective.json")["profiles"],
                                       catalog, infra, out / name)
    assert result["reference"]["state"] == "complete"
    assert result["comparison_state"] == "same_scope"
    assert result["files"]["shared"] == receipt["projects"][name]["comparison"]["shared"]
    write_json_atomic(out / f"{name}-comparison.json", result)
PY
```

To repeat the side-effect control, use the baseline executable from the
receipt and fresh writable clones. Check for the recorded relative helper
paths (the Zod helper moves to the capture's `generated` directory), then
compare `native.stdout` against the read-only replay. Keep a rejected
React Hook Form run's `progress-before-guard.json`; it explains why a
successful analyzer exit was insufficient to accept the original row.
