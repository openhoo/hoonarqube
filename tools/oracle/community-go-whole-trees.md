# Overall duplication in 32 complete public Go repositories

The reference ran SonarQube Community Build 26.11.0.134175 with an assigned gate that rejects overall duplicated-line density above 3.0%, at one decimal place. It analyzed a fresh project for each pinned revision. The manifest records the analysis ID, project and file measurements, the individual duplicated lines returned by the reference, and a digest covering every tracked file. The 32 Git trees contain 1,701 regular files (18,464,062 bytes), including tests, configuration and other languages. No project code is executed.

Run from the repository root after building the release CLI:

```sh
python3 -m unittest discover -s tools/oracle -p test_community_go_whole_trees.py
python3 tools/oracle/community_go_whole_trees.py --binary target/release/hoonarqube
```

The default command compares the measured density and duplicate lines with Community. Add `--enforce-gate` for a binary supporting the assigned one-decimal policy. This also checks the CLI's actual gate and exit code. `--project go-logr/logr` selects one tree; `--mirrors DIR` reads previously fetched objects. Incomplete input fails the replay. The CLI replay alone does not test assignment on a running service.

On the comparison build, using complete token-bearing lines instead of token fragments, retaining the exact spelling of Go backtick literals and ending multiline matches at the final token's opening row removes false rejections of `go-logr/logr`, `muesli/termenv`, `robfig/cron` and `segmentio/ksuid`. Interpreted strings still normalize. The 3% decisions match in all 32 cases on the series through #1040 with this change (16 pass, 16 fail). The earlier result was four false rejections. The first correction matched 30 line sets and 29 densities. Accounting for short companion copies recovers all 18 missing lines in each of `mitchellh/mapstructure` and `spf13/pflag`. All 32 marked line sets (9,633 lines) and 31 densities now match on the PR base.

The reference distinguishes a related copy from a marked line. Across files, only a file with a qualifying first local copy contributes to the metric. Within one file, both copies are marked when the long copy comes first. The opposite ordering yields no marked lines for the same two copies. Using every range from the reference's clone-relations endpoint as marked would overcount; use the source-line endpoint for that comparison.

| Project | Candidate | Community | Difference |
| --- | ---: | ---: | --- |
| sony/sonyflake | 7.9% | 7.8% | Same duplicate lines; the reference indexed two additional Dockerfiles. |

These are per-project regression limits. An improvement toward Community is allowed; a newly missing or extra line is reported. There are four reference-indexed files outside the candidate's complete file inventory: the two Sonyflake Dockerfiles, one Dockerfile in go-toml and one JSON file in afero. This matters for composition: the separate unsupported-language change in #1043 makes go-toml and Sonyflake explicitly unavailable until Dockerfile measurements are supported. An unavailable result is not a matching gate decision. None of these measurements qualifies other rule profiles or thresholds.
