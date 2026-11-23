# Python duplication against Community Build 26.9

Hoonarqube and the independent reference report the same number of duplicated
lines and blocks on all 47 pinned public project scopes: 63,786 lines and 2,114
blocks in total. Each run verifies the exact Git tree, file inventory and SHA-256
of every regular source blob. The scopes contain 1,055 Python files and one
JavaScript file included by the original scope. The projects' code is not run.

| Independent check | Result |
|---|---|
| 39 existing project snapshots, 815 files | Before this change 25 matched on lines, 27 on blocks. After the change all 39 match on both. |
| Eight additional package directories, 241 files | Rich, boltons, pyrsistent, build, installer, Gunicorn, bcrypt and Blinker all match on both counts. Rich has 11,402 duplicated lines in 975 blocks; Gunicorn has 590 in 24. |
| File-level references for 40 of the 47 projects, 856 files | Same per-file block counts and line sets, including all 100 files with at least one duplicated line. The other seven have project totals only. |
| Three additional FastAPI changes | All duplicated line sets match in the scoped candidate files. New-code intersections are 21/35, 2/10 and 14/14. The 35-line change fails; both small changes are ignored under the assigned gate. See the [revision pairs](community-new-duplication.md). |

## Why the counts changed

The Python analyzer sends separate tokens for expressions inside formatted
strings and retains the spelling of ordinary strings. Its syntax tree omits
some punctuation in imports and assertions. In an indented suite the newline
before a dedent counts once, even when several suites end together. None of
these rules requires lowering the 100-token threshold. For example, the
same two stretches of code in Starlette's synchronous and asynchronous
authentication wrappers now qualify.

A multiline token belongs to its first source row for duplication. This avoids
counting later docstring rows in HTTPX when the match ends on the opening row.
In IDNA's generated table, copies of the same compressed rows may contain
different numbers of consecutive identical rows. A third matching copy joins
a group that already qualified on a pair of occurrences.

The source was checked against Python plugin 5.31.0.36502
(SHA-256 `3a6a5f01bfacdb55e6c29193aff84040ea41aa91fa31724c775fc3a8bd261667`),
scanner engine 13.7.0.4455 and Community Build 26.9.0.129388. Matching on these
inputs does not establish every possible Python syntax or clone relation.

## Replay

From the repository root:

```sh
cargo build --locked --release -p hoonarqube-cli
python3 tools/oracle/python_duplication.py --binary target/release/hoonarqube
```

Select individual projects with repeated `--case` flags. To work offline,
pass `--local-repositories map.json` where each case name maps to a Git
repository at the pinned HEAD. Use `--output results.json` for a per-project
receipt. The [manifest](fixtures/python-duplication-public-20261122.json.gz)
contains the immutable Git and source identities, analysis and compute IDs,
the SHA-256 of the original project measures response, expected counts, and
file ranges where available. Project counts compare unique duplicated lines
and distinct blocks; overlapping line ranges are merged for the file checks.
CI exercises Starlette, HTTPX, IDNA and Rich as well as the FastAPI gate pairs.
