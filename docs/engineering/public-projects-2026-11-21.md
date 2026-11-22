# What the 120-project comparison establishes

Hoonarqube can scan these public sources, emit a report, and persist the report through its own service. For most selected sources, we can compare its findings with a real SonarQube Community Build analysis. The disagreements below matter for any team that makes merge decisions from these reports. Keep the existing gate authoritative until the team has compared its blocking rules, gate decisions and required integrations on its own repositories.

## What was measured

We rebuilt the scanner and service in release mode, then rescanned 122 source selections from 120 distinct public GitHub repositories. Two selections use different roots or exclusions within an already selected repository. The seven corpus languages are Go, Java, JavaScript, Python, Ruby, Rust and TypeScript. The separate [C# pilot](../../tools/oracle/public-csharp-pilot-20261120.md) is outside these counts.

The [per-project record](public-projects-2026-11-21.json) binds the native executable and source tree, upstream commits and trees, selected files, reference tasks, capture hashes and the disposition of every scan. The reference results are retained analyses from SonarQube Community Build **26.9.0.129388**. The native scanner completed 119 of 122 selections. The reference service produced completed results for 120; Gson and jsoup had no reference run.

| Public source wave | Compared scopes | Files | Matching primary findings | Native only | Reference only | Equal / compared file metric values |
|---|---:|---:|---:|---:|---:|---:|
| First | 28 | 1,440 | 2,189 | 407 | 237 | 3,542 / 4,320 |
| Second | 34 | 1,308 | 1,640 | 734 | 366 | 3,418 / 3,920 |
| Third | 46 | 686 | 753 | 158 | 105 | 1,723 / 2,058 |
| **Total** | **108** | **3,434** | **4,582** | **1,299** | **708** | **8,683 / 10,298** |

A matching primary finding has the same active, implemented rule with the same declared parameters, relative file and UTF-16 range. Eight additional selections had only partial file overlap, five lacked a complete native or reference result, and one had a known sensor exclusion. These 14 are outside the table. One-sided findings need review before calling them false positives or false negatives. The table does not measure agreement on explanations, secondary locations, data flow, fixes, or licensed rule sets.

## Where the comparison can mislead

- **Indexing and analysis differ.** Papa Parse had one indexed file, but the reference JavaScript analyzer processed zero. All 608 native findings from that selection are outside the table. Acorn had 26 indexed JavaScript files and a sensor count of 22; its cause is unresolved. Acorn already falls outside the table because the indexes differ.
- **A count cannot identify a file.** Across 102 selections, the reference language sensor's aggregate count matched the number of indexed files of that language. Rust logged completion in all 16 Rust selections but supplied no file count. A clean result on a file is not proof that a sensor examined it.
- **A valid source can still yield an incomplete native report.** Pinia's optional property named `abstract` and token trees in two anyhow macros triggered parser recovery, although the respective language tools accepted the source. Nine Devise files are ERB generator templates with Ruby extensions; the expanded output is distinct from the raw template. The scanner reported all three selections incomplete.
- **Missing coverage is a product decision.** On [Commander.js](../../tools/oracle/public-line-coverage-gates-20261120.md), the two tools agreed at the measured boundary with explicit one-decimal rounding. With no LCOV input, Hoonarqube returned unavailable and exit 2; the reference counted uncovered lines and failed. Both outcomes need a deliberate CI policy.

## Which differences to investigate first

The four rules below account for 545 of 2,007 one-sided primary locations. A different primary range can appear once on each side. These counts prioritize investigation; they do not establish which analyzer is correct. A repository can contribute to more than one source selection.

| Rule | Same primary | Native only | Reference only | Distinct repos with a difference | Largest contributing selection |
|---|---:|---:|---:|---:|---|
| `java:S1854` | 7 | 156 | 3 | 6 | commons-codec |
| `rust:S2208` | 0 | 153 | 0 | 7 | rayon |
| `javascript:S6861` | 0 | 63 | 73 | 2 | jquery |
| `typescript:S1874` | 0 | 0 | 97 | 6 | zod |

[All rule-level differences](public-rule-differences-2026-11-21.json) use the same population as the table above. For JavaScript S6861, all 63 native-only findings can be paired with a reference-only finding on the same file and starting line, although none match the whole primary range. Inspect range boundaries first. For Java S1854, none of the three reference-only findings shares a starting line with a native-only finding. Same-line pairing is a triage aid, not a matching finding.

### JavaScript S6861 follow-up — November 22, 2026

The historical counts above still describe the original scanner. The S6861 follow-up replays 299 files from the same two pinned JavaScript selections against their retained Community Build 26.9.0.129388 results:

| Selection | Files | Original matches / native only / reference only | After the fix |
|---|---:|---:|---:|
| jQuery `src` at `effd615f0009e927dfd1f41d04fb6073478076d4` | 138 | 0 / 50 / 56 | 56 / 0 / 0 |
| Underscore `modules` at `5c1e5f686f8500af9c9d15614ed60289d6d35d6b` | 161 | 0 / 13 / 17 | 17 / 0 / 0 |

The rule now reports the variable declaration's range, starting at `var` or `let`. It also resolves a separate named or default export to its local mutable binding, with one finding per exported name. All 73 captured primary locations match by rule, relative file and full UTF-16 range, with duplicate locations retained. The replay covers these two selections and this rule; it does not compare issue message text or change the historical corpus totals.

## What improved, and how to reproduce it

[The architecture review](foundation-review.md) explains how the scanner and service came to share a gate evaluator without linking the service to every parser. The [report service guide](../../crates/hoonarqube-service/README.md) describes project access, pagination, credential rotation, backup and restore. The scan and service share a report schema; changes to parsing, measurements and gate decisions must be qualified through that boundary.

On the historical four-project [Go pipeline comparison](../../tools/oracle/public-go-pipeline-timing-20261120.md), median scanner-start-to-readable-result times were 0.041–0.131 s for Hoonarqube and 5.961–6.161 s for the reference. There were five measured runs per project, 81 files and 25 shared primary findings on four rules. The services had different resources and the scan did not establish full rule parity. The same link documents the ongoing CI check against the four persisted-result contracts. The [multilanguage regression check](../../tools/oracle/public_contract.md) tests 25 pinned repositories in ordinary CI. It uses 309 individual file hashes, 91 project/rule pairs, and 214 captured primary locations across 58 rules. These known matches were selected as regression controls; they are not an accuracy sample. Separately, the [Rust scanner study](../../tools/oracle/rust-standard-path-performance-20261120.md) measured Hoonarqube before and after one optimization: the Clap median fell from 30.123 s to 2.001 s with identical output.

For the source manifests, pinned builds, capture commands and interpretation, use the methods for [wave one](../../tools/oracle/public-corpus-20261120.md), [wave two](../../tools/oracle/public-corpus-wave2-20261120.md) and [wave three](../../tools/oracle/public-corpus-wave3-20261120.md). Those historical reports retain their own builds and denominators. For this table, the native tree is `c9b2cd7cdcdbdcb6aae8ea70438961fc3400f0eb`, and the scanner SHA-256 is `14995f15c5559a6b2200ffe4ea9286a686949b8d945f3d9a081d71a7734ab388`.

## Decision before production use

Select one team's actual repository, target SonarQube edition and blocking gate. Pin the compiler and coverage inputs and run the two tools on the same change. The acceptance record should account for each differing blocking decision, show the result of missing input, measure time and resources on the target runners, and name the rollback owner. The public evidence does not establish compatibility with existing SonarScanner clients, commercial analyzers, enterprise identity, high availability, or migration of project history.
