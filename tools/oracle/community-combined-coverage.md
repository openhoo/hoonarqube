# Combined coverage on two public Commander.js changes

Run `python3 tools/oracle/community_combined_coverage.py target/release` after
building the CLI and service from the same checkout. To use a local copy,
pass `--repository /absolute/path/to/repository`; it must contain all three
pinned commits. The replay fetches source only, imports the two
digest-checked test coverage captures and uses a temporary SQLite database.

At Commander revision `ba6d13dd`, the seven scanned source files contain
4,201 measured lines. The smaller test suite covers 2,485 lines and 148 of
232 branch outcomes. The broader suite covers 3,907 lines and 754 of 816
branch outcomes. Each gate below requires 80% overall and 80% on new code,
rounded to one decimal; the small-change exception is disabled.

| Test suite | Baseline | Changed lines | Overall | New code | CLI |
|---|---|---:|---:|---:|---:|
| Focused | `987f2896` | 5 | 59.4% | 80.0% | 1 |
| Focused | `b51c0ea3` | 48 | 59.4% | 94.4% | 1 |
| Broad | `987f2896` | 5 | 92.9% | 100.0% | 0 |
| Broad | `b51c0ea3` | 48 | 92.9% | 100.0% | 0 |

Git supplies the changed line numbers. A second counter reads the raw LCOV
observations; HoonarQube imports and evaluates them independently. Some
unchanged lines have several possible old positions. Their membership in
the change set is still unambiguous, so the coverage gate can decide. A
gate that also depends on uncertain finding identities exits 2. Missing
coverage or a missing baseline also exits 2. Older assessment reports
without `changed_source_lines` do not establish an exact source diff.

Community Build 26.9.0.129388 returned the same overall and per-condition
verdicts and measured values for all four 80% gates. A second, project-assigned
gate required 95% on new code with the small-change exception:

| Baseline | New lines to cover | Measured | Community Build | Native CLI |
|---|---:|---:|---|---:|
| `987f2896` | 5 | 80.0% | OK, condition ignored | 0, ignored count 5 |
| `b51c0ea3` | 48 | 94.4% | ERROR, condition enforced | 1 |

On the older baseline Git and HoonarQube identify 48 physical changes.
Sonar reports 49: its file API also marks the empty line after the final
newline of `index.js` (line 22) as new. That line is not in LCOV. Both
products count the same 48 new lines to cover. These results do not establish
that duplication gates using physical line counts always agree.

Each of the six reference projects has a successful base and candidate
analysis from a full Git checkout. The main branch's selected new-code period
points to that project's base analysis ID. The [Community responses](community-commander-sonar-26.9.json)
record the project key, task and analysis IDs, revisions, LCOV digest, measured
counters, period, conditions and ignore flag. CI replays the native scanner
against these saved responses; it does not start a fresh SonarQube server.

The replay stores 15 reports, restarts the service, reads them back and retries
the uploads. Four reports omit their own gate after an administrator assigns
the 95% policy. The service still passes the small change, fails the larger
change, accepts a proven empty scope and reports missing coverage as unavailable. It also checks that six altered uploads are rejected, including a
false exception count. The service validates the supplied change inventory and
recomputes the gate. Its input is the report; it does not reconstruct Git
history. See the [native counters and results](community-combined-coverage-commander.json).
