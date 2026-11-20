# Public source comparison with SonarQube, third wave

On November 20, 2026, SonarQube Community Build `26.9.0.129388` completed
52 scans of pinned public GitHub projects. Hoonarqube completed 48 scans
and returned four partial reports. Neither engine was missing a run.

The [manifest](public-corpus-wave3-projects-20261120.json) records all
repository, commit, tree, source root and exclusion pins. The
[receipt](public-corpus-wave3-qualification-20261120.json) records each
disposition, source file set hashes, reference analysis IDs and native exits.
All 52 checkouts passed source preflight and matched their manifest after
the scans. None repeats a repository slug, commit or tree from the full
first or second wave manifests. Those waves selected 27 and 42 distinct
repositories respectively; the three waves selected 121 in total.

### Findings and file metrics on identical scopes

Both engines completed **45** comparable scopes with the same **658** file
paths and bytes. Only these scopes contribute to the following totals.

| Observation | Matches | Hoonarqube only | SonarQube only |
| --- | ---: | ---: | ---: |
| Primary findings on implemented rules active in both with the same declared parameters | 749 | 405 | 109 |
| Equal file size metric values | 1,667 / 1,974 | — | — |

Primary identities use rule key, path and full UTF-16 range, with repeated
identities counted by occurrence. The comparison excludes hotspots, findings
without a shared file, and documented unimplemented rules. It tests neither
messages nor secondary locations. The filter for matching declared parameters
does not establish analyzer equivalence.

File metrics are lines, code lines (`ncloc` in Sonar), and comment lines.
All 658 comparable files returned all three values. These totals do not
cover aggregate duplication, coverage, gates, or commercial sensors.
Language in the table refers to project selection; the index within an
individual scope may include more than one language.

| Selection language | Selected | Sonar complete | Native complete | Identical scopes | Identical files | Primary matches / native only / Sonar only |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Python | 12 | 12 | 12 | 12 | 219 | 514 / 83 / 93 |
| Go | 12 | 12 | 12 | 12 | 115 | 83 / 4 / 2 |
| JavaScript | 7 | 7 | 6 | 4 | 18 | 83 / 270 / 10 |
| TypeScript | 3 | 3 | 2 | 1 | 8 | 19 / 5 / 2 |
| Ruby | 9 | 9 | 7 | 7 | 150 | 34 / 0 / 2 |
| Rust | 9 | 9 | 9 | 9 | 148 | 16 / 43 / 0 |

The largest rule difference on comparable scopes in this capture was
`javascript:S3504`: 222 native findings in Express and 21 in minimist, versus
zero in Sonar. Sonar analyzed all seven files with S3504 active. The pinned
[SonarJS implementation](https://github.com/SonarSource/SonarJS/blob/1eea9253f87b448684d1089dc7160eca388b21b6/packages/analysis/src/jsts/rules/S3504/decorator.ts)
suppresses the rule when a file has at least three runtime `var` declarations
and they make up more than half of its runtime variable declarations. A
separate live control confirmed the threshold and the exclusion of ambient
TypeScript declarations. These are historical totals for the recorded native
binary.

### Scopes outside the totals

Sonar indexed `papaparse.js` and its compute task succeeded. Its JavaScript
sensor reported a generated code exclusion, zero analyzed files, and no cache
hits. Sonar returned only `lines` for the file. Its 226 native findings on
implemented rules active in both with the same declared parameters (including
146 S3504 findings) are outside the common analyzer scope. The qualification
receipt keeps the excluded counts and the successful compute task visible.

A fresh reference project scanned the same file bytes with
`sonar.javascript.detectBundles=false`. The sensor analyzed the file,
returned all three file metrics and 66 JavaScript findings, and still
returned zero S3504 findings. The control did not change the original
scan settings or replace its results.

Two pairs finished with different file sets. Both engines had 30 indexed
PostCSS files in common; Hoonarqube also analyzed 22 declaration files.
Both had 14 Valtio files in common; Hoonarqube also analyzed
`src/types.d.ts`. Neither pair contributes to the totals.

The four partial Hoonarqube reports exited 2 and identified failed files.
Sonar's compute task succeeded in each case.

| Repository | Native failed files |
| --- | --- |
| `pillarjs/router` | `lib/route.d.ts` |
| `immerjs/immer` | `src/types/types-external.ts` |
| `rubocop/rubocop-ast` | `lib/rubocop/ast/builder_extensions.rb`, `lib/rubocop/ast/node_layout.rb` |
| `dry-rb/dry-core` | `lib/dry/core/container/mixin.rb` |

### Provenance

The native executable was a release build from
`1884c8bca3f62fa83964914ce972392ad21af383`. The receipt includes its digest,
Git tree and toolchain. The reference used the same pinned server and
scanner images as Wave 2 and a separate private instance. The HTTPX pilot
provided live profile identities. Across all 27 profile configurations,
3,544 active rule entries, types, scopes, severities and parameters agreed
before and after the run and with Wave 2.

Both scans used static sources. No dependency installs, project scripts or
Clippy ran. Compiler-assisted TypeScript analysis had no project compiler
package available. The two image platforms and the native target are in the
receipt. The sample covers six selection languages and is not a
representative survey of all public repositories or engines.

## Replay the pinned inputs

From this repository checkout, use Python 3.11 or newer and Docker with
support for the ARM64 server and AMD64 scanner images. Create a private
state directory outside the repository and build the native executable
from a separate clean checkout of the measured commit:

```sh
umask 077
state=$(mktemp -d "${TMPDIR:-/tmp}/hq-wave3-replay.XXXXXXXX")
native_checkout="$state/native-source"
git worktree add --detach "$native_checkout" 1884c8bca3f62fa83964914ce972392ad21af383
(cd "$native_checkout" && cargo +1.96.0 build --locked --release -p hoonarqube-cli \
  --bin hoonarqube --target-dir "$native_checkout/target")
```

Leave at least 5 GiB of host disk free during checkout and capture. This
example uses an internal network and temporary `tmpfs` mounts for the
reference server data, extensions, logs and temporary files. These mounts
use the server's memory budget and lose their contents when the server
stops. The named volume is only for the scanner cache. Allocate enough VM
memory for both engines; use `--jobs 1` to reduce peak scanner use. Use
unused network, container and cache volume names.

```sh
mkdir "$state/docker"
manifest=tools/oracle/public-corpus-wave3-projects-20261120.json
replay=tools/oracle/public_corpus_wave3_replay.py
image() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$manifest" "$1"; }
server_image=$(image reference_server_image)
scanner_image=$(image reference_scanner_image)
server=hq-wave3-replay-reference
network=hq-wave3-replay-network
cache=hq-wave3-replay-cache
docker pull --platform linux/arm64 "$server_image"
docker pull --platform linux/amd64 "$scanner_image"
docker network create --internal "$network"
docker volume create "$cache"
docker run --detach --pull=never --platform linux/arm64 --name "$server" \
  --network "$network" --network-alias reference \
  --memory 5g --cpus 4 -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true \
  --tmpfs /opt/sonarqube/data:rw,size=8g,uid=1000,gid=0,mode=0770 \
  --tmpfs /opt/sonarqube/extensions:rw,size=256m,uid=1000,gid=0,mode=0770 \
  --tmpfs /opt/sonarqube/logs:rw,size=128m,uid=1000,gid=0,mode=0770 \
  --tmpfs /opt/sonarqube/temp:rw,size=1g,uid=1000,gid=0,mode=0770 \
  "$server_image" > "$state/docker/server.id"
```

Wait for SonarQube to report that it is operational in the container logs.
Keep its built-in default quality profiles. The replay verifies the
container and internal network, rotates its initial local admin password,
and keeps generated credentials and raw reports under `state`. It checks
the analyzer versions and hashes, image platforms, and effective profile
configuration against the historical receipt.

```sh
python3 "$replay" prepare --state "$state" &&
python3 "$replay" reference --state "$state" --jobs 2 \
  --server "$server" --network "$network" --cache "$cache" &&
python3 "$replay" native --state "$state" --jobs 2 \
  --binary "$native_checkout/target/release/hoonarqube" \
  --native-checkout "$native_checkout" &&
python3 "$replay" summary --state "$state"
```

The summary emits the exact-scope counts and metrics as JSON. The receipt
contains the expected results from the original release binary. Another
build's binary hash, and fresh Sonar task and analysis IDs, can differ. The
summary phase was checked against all 52 completed capture pairs without
rerunning the scans.
