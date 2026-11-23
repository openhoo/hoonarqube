# Overall duplication in 32 complete public Go repositories

The reference ran SonarQube Community Build 26.11.0.134175 with an assigned gate that rejects overall duplicated-line density above 3.0%, at one decimal place. It analyzed a fresh project for each pinned revision. The manifest records the analysis ID, project and file measurements, the individual duplicated lines returned by the reference, and a digest covering every tracked file. The 32 Git trees contain 1,701 regular files (18,464,062 bytes), including tests, configuration and other languages. No project code is executed.

Run from the repository root after building the release CLI:

```sh
python3 -m unittest discover -s tools/oracle -p 'test_community_go_*.py'
python3 tools/oracle/community_go_whole_trees.py --binary target/release/hoonarqube
```

The default command compares the measured density and duplicate lines with Community. Add `--enforce-gate` for a binary supporting the assigned one-decimal policy. This also checks the CLI's actual gate and exit code. `--project go-logr/logr` selects one tree; `--mirrors DIR` reads previously fetched objects. Without the flag, a partial Go/Docker report still requires the actual gate and exit code on the original tree. Missing evidence fails the replay. The CLI replay alone does not test assignment on a running service.

On the comparison build, using complete token-bearing lines instead of token fragments, retaining the exact spelling of Go backtick literals and ending multiline matches at the final token's opening row removes false rejections of `go-logr/logr`, `muesli/termenv`, `robfig/cron` and `segmentio/ksuid`. Interpreted strings still normalize. The 3% decisions match in all 32 cases on the series through #1040 with this change (16 pass, 16 fail). The earlier result was four false rejections. The first correction matched 30 line sets and 29 densities. Accounting for short companion copies recovers all 18 missing lines in each of `mitchellh/mapstructure` and `spf13/pflag`. All 32 marked line sets (9,633 lines) and 31 densities match on the Go-only measurement baseline (#1048).

The reference distinguishes a related copy from a marked line. Across files, only a file with a qualifying first local copy contributes to the metric. Within one file, both copies are marked when the long copy comes first. The opposite ordering yields no marked lines for the same two copies. Using every range from the reference's clone-relations endpoint as marked would overcount; use the source-line endpoint for that comparison.

| Project | Candidate | Community | Difference |
| --- | ---: | ---: | --- |
| sony/sonyflake | 7.9% | 7.8% | Same duplicate lines; the reference indexed two additional Dockerfiles. |

These are per-project regression limits for complete reports. The older build omits three Dockerfiles and one reference-indexed JSON file in afero. The unsupported-language inventory in #1043 makes go-toml and Sonyflake unavailable until the CLI supplies the specific overall Dockerfile measure (#1046).

When that measure is present, the replay first evaluates the assigned gate on the unchanged Git tree. It checks every Go counter and the original bytes and physical lines of each Dockerfile. If the gate, exit code, inventory or evidence disagrees, the replay fails. Only after these checks does it analyze the explicit Go paths from the reference inventory to recover individual duplicated lines. The output records both origins (`gate_source`, `line_map_source`), each supplemental path and the Dockerfile line counts. The separate scan supplies no gate decision.

With both changes, the 32 reference densities and all 9,633 marked Go lines match. In go-toml, 1,284/34,628 lines round to 3.7%; in Sonyflake, 136/1,752 round to 7.8%. Both unchanged repositories exit 1 under the assigned 3% gate. This does not qualify other metrics, thresholds or rule profiles.
