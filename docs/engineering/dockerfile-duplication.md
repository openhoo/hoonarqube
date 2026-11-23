# Overall duplication density in Go projects containing Dockerfiles

Community Build 26.11.0.134175 includes physical Dockerfile lines in the denominator of overall duplication density. It produced no duplicate blocks from two byte-identical copies of the Redis Dockerfile. This is a measured distinction: Dockerfile issue analysis remains unsupported in Hoonarqube.

The scanner emits `project.docker_duplication` only when it can measure every eligible Dockerfile and finish native Go duplication analysis. The report keeps `project.complete = false`, records each Dockerfile as unsupported for issues, and leaves general duplication fields unavailable. An assigned **overall `duplicated_lines_density`** gate can compute its own result from the measured denominator and the native Go counters. Plain analysis still exits 2. An explicit density-only gate exits 0 on pass or 1 on fail. A combined gate with an unavailable condition exits 2.

The store validates the evidence against the inventory, retained Go reports, per-file sizes, project totals and warnings before ingest. The authorized scanner attests to the measured bytes; the server has no independent repository checkout. A missing row, inconsistent count, unrelated warning or unknown input invalidates the evidence. New-code density, other duplication counters, issues and coverage do not use it. This implementation supports regular UTF-8 files named exactly `Dockerfile`, the default duplication settings and otherwise fully measured Go sources. Aliases, symlinks, inputs beyond the source bound, Dockerfiles in test scope, mixed native languages, and partially measured eligible sources are outside the contract. Whole-source exclusions continue to apply before measurement.

## Reference and replay

The [reference](../../tools/oracle/fixtures/dockerfile-duplication-2611.json) records byte digests, upstream commits, server task and analysis IDs, Dockerfile lines, and measured decisions of a project-assigned 3% gate. Identical Go inputs yielded 42 duplicate lines with and without Dockerfiles. Total physical lines changed from 130 to 272 with Redis, 259 with Golang, 209 with nginx, 480 with all three, and 414 with two copies of Redis. Redis alone produced 0/142. A separate capture covers empty input, LF, CRLF, CR, a final line without a terminator, comments and a UTF-8 BOM. These are static scans; no Dockerfile is built and no public project code is executed.

The two complete repository references are `pelletier/go-toml` (122 tracked files, Community 3.7%) and `sony/sonyflake` (28 files, 7.8%). Both fail the assigned gate. The replay checks the actual native numerator and denominator separately from the Community verdict; matching the decision does not establish exact Go duplicate-line parity.

After building the CLI and service, run:

```sh
cargo build --locked --release -p hoonarqube-cli -p hoonarqube-service
python3 tools/oracle/public_dockerfile_density.py target/release
```

The default run downloads five pinned public source blobs, checks their hashes and verifies the eight small references, including service readback and restart. For offline use, supply those blobs in `--source-cache DIR` under their SHA-256 names. To add the two full-tree decisions, export every tracked regular file at the two pinned commits into `DIR/pelletier--go-toml/files` and `DIR/sony--sonyflake/files` (no Git metadata) and pass `--trees DIR`. The replay verifies a checksum over every path and byte digest before analysis.
