# Overall Web duplication in Community 26.11

Use `hoonarqube analyze . --profile community-26.11-web-duplication --format json --quality-gate policy.json` for a project whose indexed sources are HTML, XHTML or ERB. The profile measures overall `duplicated_lines_density` at the reference defaults: 100 tokens and ten token-bearing lines. A Ruby file does not contribute to this Web measurement. Existing rule profiles still analyze Ruby.

The original whole-tree holdout used **sonar-parity** on the signed series `cd0b4ffb`. Haml at `4a89a4639a5bb4e6e28e1763227cabfb106e5d8b` had 118 complete native rows and 1,393 marked lines; CI stopped at 10.2%. Community Build 26.11.0.134175 indexed 18 XHTML and seven ERB files and passed with 0.0%. The opt-in Web profile measures those same 25 files, their 970 physical lines and no duplicated lines.

| Captured inputs | Files | Duplicated / physical lines | Reference | CI exit |
| --- | ---: | ---: | ---: | ---: |
| Complete Haml tree (213 tracked files) | 25 | 0 / 970 | 0.0% | 0 |
| Same tree, excluding all XHTML | 7 | 0 / 174 | 0.0% | 0 |
| One ERB plus an explicitly named Ruby source | 1 | 0 / 56 | 0.0% | 0 |
| Two copies each of public Haml XHTML and ERB templates | 4 | 428 / 432 | 99.1% | 1 |
| One XHTML containing the same public template twice | 1 | 318 / 320 | 99.4% | 1 |

The [reference](../../tools/oracle/fixtures/haml-web-duplication-2611.json) binds the 213 Git blobs, Git tree, scanner and server image pins, independent analysis IDs, physical file lines and reference duplicate line ranges. The [replay](../../tools/oracle/community_web_duplication.py) verifies the complete tree, analyzes source bytes without executing package code, compares each marked line, then submits the raw scanner report to a separately assigned policy and checks the CI helper after ingest and the stored decision after restart. To run offline, pass `--source /path/to/full/tracked/extract`. Run with `--one-decimal` on a build that includes the separate overall-density precision and CI policy-version contracts. The #1043 base alone uses full precision, which gives the same decisions here.

## Boundaries

The scanner reads bounded ASCII source and preserves tag names, assignments and template expressions in its token stream. Comment and whitespace tokens do not contribute. A syntax or resource limit, non-ASCII text, known additional source language, test scope, CPD-only exclusion or custom thresholds yields an unavailable decision. Ordinary explicit analysis exclusions are honored. This profile does not implement Web rules. The project inventory is subject to the existing walker and scope settings; this is not a general Community language inventory.

Only an overall density condition can pass or fail. Other conditions, including an issue-count or new-code condition, are unavailable even if the scanner produced an empty issue list. Policy assignment evaluates the serialized measurement scope. A version 2 analysis report carries this restriction; earlier services reject it. Other profiles retain report version 1. A source-only Ruby scan under the Web profile is unavailable; Community supplied no density condition for that scope.
