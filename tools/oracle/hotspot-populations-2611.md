# Which hotspots count toward a required gate?

The gate policy chooses the review population. A missing value is neutral only for a population the evaluator can identify. The scanner and the report service now return `unavailable` for the unqualified name `security_hotspots_reviewed`, even when the native scan reports zero findings. A CI job using the scanner exit code or `scripts/check_project_gate.py` stops with exit 2.

Use a `new_code` condition with `operator: gte` and `threshold: 100`. Set its `metric` to one of these values:

| Policy metric | What it asks |
| --- | --- |
| `native_reported_security_hotspots_reviewed` | What share of new findings **reported by this native scan** and typed as hotspots in its embedded catalog have authorized reviews? This is useful for native rules such as `javascript:S2245`. It does not measure another scanner's profile. |
| `community_26_9_security_hotspots_reviewed` | Use the captured Community 26.9.0.129388 Sonar way types for the supported languages. |
| `community_26_11_core_security_hotspots_reviewed` | Use the captured Community 26.11.0.134175 Sonar way core profile for Java and Python. The complete inventories contain 263 and 232 active rules respectively, with no hotspot rules. A different language, unknown declared rule set, absent parity record or unusable baseline cannot establish this population. |

The two reference metrics require an identified native `--profile sonar-parity` report, its complete declared rule membership, source inventory and compatible baseline. The 26.11 table contains all active rules returned by the reference API, including types that have no native detector. The gate checks that none of these active reference rules is a hotspot. It fails closed if an unqualified hotspot enters the table. A team with a different build or profile must keep the unbound condition unavailable until that population is qualified. Select the core metric only when the assigned external profile matches the reference.

## One change, two assigned profiles

We scanned the public [Commons Lang change](https://github.com/apache/commons-lang/commit/6a4979ba028a257401b9fdfcc23f42d9419fff6f) and its direct parent. Both private reference projects indexed the same Java bytes. Each had the same nondefault gate requiring 100% reviewed, overall and on new code. Each had its own selected baseline analysis. The benchmark was not executed.

| Community 26.11.0.134175 profile | Observed result | HoonarQube CI |
| --- | --- | --- |
| Java Sonar way core | Zero active hotspot rules, zero hotspots. Project and historical gates were OK and omitted both conditions. `ignoredConditions` was false. | Named core condition: `no_value`, aggregate pass, exit 0. |
| Custom Java profile: one active constructor rule for `java.util.Random` | One hotspot at line 643. Project gate: 0%/ERROR → 100%/OK after SAFE → 0%/ERROR after reopening. The candidate analysis retained the original failure. | Custom detector unsupported. Unqualified required condition: unavailable, exit 2. No percentage or review for this external hotspot is inferred. |

The [fixture](fixtures/hotspot-populations-2611.json) records the four CE task/analysis pairs, Git revisions and blob hashes, rules, profile assignments, gate responses and review states. Its Python profile is joined to the independently captured [FastAPI default-gate reference](fixtures/fastapi-default-gate-26.11.json.gz). The native service replay assigns both policies, verifies its enforced receipt with the CI checker, then reopens its database. An edited green legacy receipt, an invalid baseline, missing/changed rule inventory, and an unqualified language all block. A separate Yjs run exercises the native metric, reviewer roles, optimistic concurrency and immutable history.

## Upgrade an existing policy

1. Inspect the project's assigned profile. For native-only review workflows, assign a new gate policy version with the native metric. For a qualified Community profile, assign its versioned metric. If the population is unknown, keep the required check blocked.
2. Deploy the matching scanner, service and CI receipt checker. Start a fresh analysis under the new policy. Do not relabel an old receipt: a new service rejects historical green scanner claims submitted as new measurements.
3. On an existing database, the live endpoint recomputes old unbound policies as unavailable. The original scanner result and authorized review history remain readable. Logical restore can validate historical scanner claims against their original native semantics when the catalog and report are compatible. The backup format stores assigned policies separately and re-evaluates them on import; an export is not an archival copy of every assigned receipt.

Run `community_custom_hotspot_native.py` as shown in [the 26.9 capture](community-custom-hotspot.md#reproduce). Add `--previous-binaries /path/to/before/bin` to test a real process upgrade and a logical restore. That directory must contain the pre-binding scanner and service built against a compatible native catalog. The replay reads local Git objects and starts disposable loopback services.
