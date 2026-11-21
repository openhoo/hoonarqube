# First production pilot: Community Build and CI gates

The first acceptance target is a team's existing **SonarQube Community Build gate**. Before using Hoonarqube to block merges, compare the gate actually assigned to the team, on two revisions of its repository. Keep the current gate authoritative during the comparison. Commercial analyzers, portfolios and single sign-on are outside this first acceptance decision.

## Which gate do we need to reproduce?

The [readback](community-default-gate.json) comes from the built-in, default **Sonar way** gate on our isolated Community Build **26.9.0.129388**. The server reported four conditions, all on new code, with the global small-change exception enabled. This is configuration evidence. It does not show that either analyzer evaluated these conditions on any particular change.

| Failure predicate read from the reference | What Hoonarqube can establish today |
|---|---|
| Coverage on new code below 80% | Native gates expose line and branch coverage separately. A passing whole-project line-coverage test does not prove that the combined reference measure or changed-line selection is equivalent. |
| Duplicated line density on new code above 3% | Native gates support duplication on new code when given a compatible prior report. The Picomatch and Yjs comparisons exercise **overall** duplication. |
| Reviewed hotspots on new code below 100% | The native metric gate has no reviewed-hotspot percentage. A project that requires this condition cannot switch its blocking gate yet. |
| More than zero new issues | The native gate can count new issues. Equivalence depends on the active rules, native finding identities and the selected baseline. The [public project comparison](public-projects-2026-11-21.md) records one-sided findings. |

The small-change exception is another input to verify. The [Community Build 26.1 release notes](https://docs.sonarsource.com/sonarqube-community-build/server-update-and-maintenance/release-notes) distinguish the number of new lines for duplication from new *lines to cover* for coverage. Record the project's override and test both sides of the 20-line boundary with different numbers of changed and coverable lines. Check each condition's status and the reference's `ignoredConditions` field.

A team using custom **overall** conditions has a shorter path. [Commander.js](../../tools/oracle/public-line-coverage-gates-20261120.md) exercises a passing run, a failing run, rounding at 59.2%, and missing input. [Picomatch and Yjs](../public-quality-gates-20261120.md) exercise a pass and a failure with two duplication conditions each. A missing Commander coverage input blocks both systems, with different diagnostics: Community reports failed coverage; Hoonarqube reports unavailable and exits 2.

## Pilot record and release decision

1. **Freeze inputs.** Record the repository, base and candidate SHAs, exact scanner and reference builds, source/test exclusions, effective rule keys and parameters, coverage file digest, and the assigned gate with all thresholds and overrides. Preserve the two input reports used for new-code comparison. The native baseline is an explicit prior report; verify the actual reference definition of new code for the project.
2. **Run both paths in CI.** Include a known passing change, a known failing change, and missing coverage or compiler input. Save the raw reports and exit statuses. For each reference compute task require success, read the gate by analysis ID, and record the conditions actually evaluated. A pass with zero evaluated conditions is no evidence for a blocking condition. Compare the candidate's HTTP readback with its CLI decision.
3. **Measure time to a usable gate.** Run on the same runner class with the same inputs. Record core count, memory limit, cold/warm cache state, wall time to the stored decision, and process-tree peak memory. Agree on a budget with the team before timing. The small public Go comparison supplies no general speed target.
4. **Record the call.** For every blocking condition record: reference value/status, native value/status, reason for any difference, owner, and acceptance or required fix. A missing required metric, a lost report, or an unexplained change in a blocking decision keeps the existing gate in place. To promote, name the team owner and rollback owner and rehearse restoring the existing CI check on a test change. Keep the prior scanner and service data available during the pilot.

The public corpus and CI contracts are regression evidence. Production acceptance requires a completed record for the selected team's repository.
