# A reviewed hotspot in Community Build 26.9

Community Build 26.9.0.129388 accepted a Java rule created from its bundled constructor template and explicitly typed as `SECURITY_HOTSPOT`. It reported the rule once on an unmodified public change. Reviewing the hotspot changed the live quality gate; the decision saved with the analysis stayed unchanged.

This is a custom profile. Before the rule was created, the reference returned 4,446 installed rules: 2,786 code smells, 1,011 bugs, 649 vulnerabilities and **zero hotspots**. Searches without an activation filter returned zero hotspots both globally and for each of the eight native languages. As a positive query control, `javascript:S2245` returned one vulnerability. The Java Sonar way profile retained its key, its 599 active rules and its rules-update timestamp; it never activated the custom rule.

## Apache Commons Lang: one actual reference hotspot

[Apache Commons Lang](https://github.com/apache/commons-lang/commit/6a4979ba028a257401b9fdfcc23f42d9419fff6f) added `src/test/java/org/apache/commons/lang3/StringUtilsJoinBenchmark.java`. Line 643 creates a seeded random generator to populate benchmark inputs. The qualification indexed this file as source. It did not run the benchmark.

| | Base | Candidate |
| --- | --- | --- |
| Commit | `8eff0a40639a3c010b2bf720ccf89f49844de067` | `6a4979ba028a257401b9fdfcc23f42d9419fff6f` |
| Analysis ID | `398f6b00-2e1d-414c-adc2-2deea634faf4` | `4a72bdcb-4a89-415b-965d-baa666c1c82e` |
| CE task | `bd74bef9-9ef5-4f68-a2d2-7b1f18fb76c6` | `6359d83c-0140-493f-b19d-bf4d583f3378` |
| Scope | Unchanged control: `CharSetTest.java` | Same control and the new benchmark |
| Findings for the custom rule | 0 | 1 overall, 1 in the new-code period |

The project used one custom Java profile with one active rule, `java:hqunitrngreview20261122`, based on `java:S4011`. Its parameters were `className=java.util.Random` and `allOverloads=true`. Its private quality gate required 100% of hotspots reviewed, both overall and on new code. The base evaluated zero conditions. The candidate counted 645 new lines and produced hotspot `5be2ca7d-05a3-4415-98cb-3e35933fad06`.

| Review operation | Hotspots still to review | Reviewed, overall / new code | Current project gate | Gate fetched by candidate analysis ID |
| --- | ---: | --- | --- | --- |
| After scan | 1 | 0% / 0% | ERROR | ERROR, 0% |
| Mark SAFE | 0 | 100% / 100% | OK | ERROR, 0% |
| Reopen | 1 | 0% / 0% | ERROR | ERROR, 0% |

The reference server stayed up throughout this review. We tested restart persistence on the native service below.

The search API continued to return the **same** hotspot after review, with status `REVIEWED` and resolution `SAFE`. In this example the `security_hotspots` and `new_security_hotspots` measures count items still to review. The reviewed-share denominator remained one.

## Native comparison and its limit

In the original 26.9 capture, Hoonarqube reported no custom Java hotspot on the same Apache revisions, bytes, scope and analysis date. Before population binding, the native gate returned `no_value` and aggregate `pass`. Its CLI rejected the reference profile and reported the custom rule as unknown. The current replay requires the unbound condition to return `unavailable` (exit 2); see [the 26.11 two-profile comparison](hotspot-populations-2611.md). The historical result differs from the reference's initial 0% and failing gate. A Java rule in the frozen catalog does not implement a newly created rule or profile.

We verified the native review service independently on a real [Yjs change](https://github.com/yjs/yjs/commit/20913920310f4b1f4dbbd088f3a29b00f1592fe7). Against its direct parent `3dc67e075bad9760c178f51e0a40083e3aabcf85`, the native scanner reported one new `javascript:S2245` in `src/SpecHelper.js:35`. It is a random seed in a test helper. The three other native S2245 findings, on lines 84, 95 and 114, were classified as existing. The Yjs period is a declared test input one second after the parent commit time; it does not represent an observed Community analysis.

The native scanner's original gate was 0% and failed. A reader's attempted review returned HTTP 403 and did not change the gate. An authorized reviewer marked the finding safe; replaying a stale review version returned HTTP 409. The live gate reached 100%, stayed there after restarting the service with its existing database, and fell to 0% after the reviewer reopened the finding. The stored scan decision stayed at 0% throughout. This exercises a real native detector and real service writes without inserting or relabeling findings. It does not establish detector parity between the two projects.

## Reproduce

Verify the captured Community responses offline. The fixture excludes blame author fields; no token or source checkout is included. It also contains results from the first native run. A fresh native replay computes its own results:

```sh
python3 tools/oracle/community_custom_hotspot.py
python3 tools/oracle/community_custom_hotspot_native.py \
  --scanner target/release/hoonarqube --service target/release/hoonarqube-service \
  --apache /path/to/full/commons-lang --yjs /path/to/full/yjs
```

The native replay creates disposable local clones and a private report-service database. No upstream project code is executed. The reference used server image `sha256:c0f1160bccfa435db4168c2d7df69af3c3ea7bfeb87395613014048fb33a68c1` and scanner image `sha256:23ca0f137965d9dff2198074043fd48d386280bc5d0ccac8c8349cea4cf096a9`. To repeat its writes on a disposable instance of that release:

1. Use `POST api/rules/create` with the Java template, type and parameters above and a fresh custom key. The fixture member `create-hotspot.json` contains the original form parameters, including the required name and description. Read the result back with `api/rules/show`. Create an empty nondefault Java profile, activate only that custom rule, and assign the profile to a fresh private project.
2. Create and assign a separate quality gate. Keep exactly `security_hotspots_reviewed LT 100` and `new_security_hotspots_reviewed LT 100`. A new gate on this release already contains the second condition.
3. Use a full Git checkout and index only the two named files as main source. Under the common `src/test/java/org/apache/commons/lang3` source directory, use both full paths as `sonar.inclusions`. The base has only the control. Use the full Git SHA for `sonar.scm.revision` and project version. Mount the sources read-only, set `sonar.scm.provider=git`, and point `sonar.java.binaries` at an empty directory. The scanner warned about missing Java libraries; it resolved this JDK constructor.
4. Scan the base with `sonar.projectDate=2025-12-24T13:48:37+0000`. Wait for its CE task, set the project's `SPECIFIC_ANALYSIS` period to that task's **analysis ID**, then scan the candidate with `sonar.projectDate=2025-12-25T16:00:35+0000`. Verify both analysis IDs in project history.
5. Read `api/hotspots/search` both overall and with `inNewCodePeriod=true`. Verify the rule, file and line via `api/hotspots/show`. Read `api/measures/component` and `api/qualitygates/project_status` by project key and separately by candidate analysis ID before and after each review.
6. Submit `api/hotspots/change_status` for that actual hotspot as `REVIEWED/SAFE`, then as `TO_REVIEW`. Check that the three states match the table and that the built-in Java profile still does not activate the custom rule.
