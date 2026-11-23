# What a default Community installation can ask the scanner to run

On November 23, 2026 we read every default language profile from an isolated SonarQube Community Build 26.11.0.134175 installation. We compared its active rule keys with the HoonarQube catalog at `91e1d64a`. A shared key is a prerequisite for using that profile. It does **not** establish a working detector, effective parameter support, matching findings or gate equivalence.

| Reference language also in the native catalog | Active by default | Identical catalog keys | Missing keys |
| --- | ---: | ---: | ---: |
| C# | 121 | 120 | 1 |
| Go | 6 | 6 | 0 |
| Java | 263 | 231 | 32 |
| JavaScript | 200 | 164 | 36 |
| Python | 232 | 224 | 8 |
| TypeScript | 199 | 153 | 46 |
| **Six languages** | **1,021** | **898** | **123** |

The installation exposed 24 languages. The six above account for 1,021 of 1,702 activations; 681 activations belong to the other 18 languages, including 230 in Jupyter notebooks. Notebook rules are keyed separately from Python rules. Three of the 18 (JSON, JSP and YAML) had zero default activations. A zero here is not an analysis of those formats. Ruby and Rust are in the native catalog, but were absent from this reference installation. Other installed profiles and user-defined profiles can differ.

## Recheck the catalog

Run `python3 tools/oracle/community_default_inventory.py` at the repository root. It lists every default language, missing keys and newly matching keys. Removing a previously shared key fails the check. Adding a catalog entry updates the inventory without claiming detector support. The [public profile replay](community-profiles-26.11.md) tests actual findings separately.

The fixture records the reference image digest, all 24 default profile names and identifiers, each activated key with its effective parameters and severity, and each catalog file's SHA-256 at capture. To refresh the observation, read the server version, languages and default profile assignments from `system/status`, `languages/list` and `qualityprofiles/search`. Page through `rules/search` with each assigned profile key, `activation=true` and `f=actives`. Check the returned activation belongs to that profile, count unique keys, and re-read the assignments, rule counts and update timestamps before accepting the capture. Verify the native CLI's `rules list --json` keys against the tracked catalog at the named commit.
