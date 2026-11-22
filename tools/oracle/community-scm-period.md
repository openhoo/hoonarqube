# Specific-analysis periods in a Git checkout

To evaluate a Community Build branch period, scan the base with
`--write-baseline base.json`. On the candidate, keep the same paths and
profile and add `--baseline base.json --specific-analysis period.json`.
The descriptor identifies the selected base analysis. For the recorded Redux
project, its contents are:

```json
{"analysis_id":"917dc346-8e62-4dcc-87b8-0d4213b92141","revision":"0b6d794effa9da5080bfb4c6865a324357b85018","timestamp_ms":1795350978000}
```

Use the date of the selected analysis from the project's quality gate period.
The timestamp of the base commit, the time the period setting was edited, and
the current wall clock can each be different. The scanner accepts the analysis
ID and date as caller-supplied provenance; it does not contact a server to
authenticate that pair. The report records the selection and both Git revisions.

The scanner verifies that the selected revision is an ancestor of the
candidate and that every analyzed source snapshot matches its committed
regular Git blob. It uses whitespace-insensitive Git blame on the candidate.
A line is new if its commit's **committer time** is strictly after the analysis
time. A terminal empty line after LF inherits the preceding line's date.
That line counts for physical new lines and duplication but has no executable
bytes or coverage observation. Missing coverage on other changed lines
remains unavailable.

A finding already matched in the base stays existing. A newly detected finding
is dated from its most recent attributed line: the primary range and flows in
the same file are considered. If it has no located line, the newest line in
the file supplies the date. A finding with uncertain identity on recent lines
stays uncertain. Conditions that depend only on source lines can still use a
complete SCM line inventory. A finding in an empty file has no Git date.
A baseline containing future-dated code in a file with findings cannot prove
the creation dates of those findings and is unavailable.

The mode requires a full local Git history and committed source bytes. Missing
or mismatched inputs, untracked/modified source, unsupported line numbering,
failed Git commands and incomplete native analysis cannot produce a clean
zero. Git output is capped at 64 MiB per file, the inventory at 16,384 files
per revision, and changed lines at four million. The scanner does not fetch
missing Git objects. Ignore-revision lists are disabled. Plain `--baseline`
keeps the existing content comparison, including for inputs outside Git.

## Reference and replay

In SonarQube Community Build 26.9.0.129388,
[NewCodePeriodResolver](https://github.com/SonarSource/sonarqube/blob/26.9.0.129388/server/sonar-ce-task-projectanalysis/src/main/java/org/sonar/ce/task/projectanalysis/period/NewCodePeriodResolver.java)
selects the baseline snapshot's creation time.
[NewLinesRepository](https://github.com/SonarSource/sonarqube/blob/26.9.0.129388/server/sonar-ce-task-projectanalysis/src/main/java/org/sonar/ce/task/projectanalysis/source/NewLinesRepository.java)
compares each SCM changeset to the period using a strict greater-than.
[IssueCreationDateCalculator](https://github.com/SonarSource/sonarqube/blob/26.9.0.129388/server/sonar-ce-task-projectanalysis/src/main/java/org/sonar/ce/task/projectanalysis/issue/IssueCreationDateCalculator.java)
backdates a new issue using the latest changeset at its locations.
The reference scanner engine 13.7.0.4455 (SHA-256
`51110a516ea671a35bb8b5c1ae441146ba64b960d1ccf121963c95909f9ca778`)
uses native Git porcelain blame with `-w` and reads `committer-time`.

| Public change | Captured Community decision | SCM CLI |
| --- | --- | --- |
| Redux `0b6d794e → e6f6c7da` | 0 new violations, OK; no hotspot review percentage | Same; plain baseline still reports 2 new violations and fails |
| Yjs `53fd0285 → 486d5677` | 65/86 duplicated lines, fail | Same; plain baseline cannot decide |
| Yjs `ebae7a3e → ee37f0a0` | 0/19, pass | Same |
| FastAPI `e0f8cadf → b78c8226` | 21/35 duplicated lines, fail | 20/35, fail |
| FastAPI `7cb19539 → 5d5666be`; `2bb28066 → 8b0090c3` | 2/10 and 14/14, both ignored on a small change | Same |
| Commander.js `987f2896 → ba6d13dd` | 5 new lines, focused/broad new coverage 80%/100% | Same |
| Commander.js `b51c0ea3 → ba6d13dd` | 49 new lines, focused/broad new coverage 94.4%/100% | Same, including line 22 of `index.js` |

Reproduce with a built CLI and full clones of `reduxjs/redux`, `yjs/yjs`,
`fastapi/fastapi` and `tj/commander.js` containing the pinned revisions:

```sh
python3 tools/oracle/community_scm_period.py target/release/hoonarqube \
  --redux /path/to/redux --yjs /path/to/yjs --fastapi /path/to/fastapi \
  --commander /path/to/commander
```

The replay uses disposable clones and captured reference gate responses for
[Redux](community-hotspot-reference-redux.json),
[Yjs and FastAPI](community-new-duplication-20261122.json), and
[Commander.js](community-commander-sonar-26.9.json). The five duplication
[period timestamps](community-scm-duplication-periods.json) were read from each
project's captured gate. A missing baseline, wrong selected revision, dirty
source or shallow history returns exit 2. These comparisons cover selected
files and conditions. They do not cover PR/reference-branch periods, full
issue tracking, server-side blame fallbacks, or all duplication detectors.
