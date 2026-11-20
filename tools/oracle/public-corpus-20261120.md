# Public source comparison with SonarQube, November 20, 2026

We ran 29 local SonarQube Community Build analyses: 27 pinned public GitHub
projects in seven languages, plus narrower Chalk and Redux scopes. The
[project manifest](public-corpus-projects-20261120.json) binds each source
commit and tree, roots, exclusions, and analysis key. The
[current receipt](public-corpus-qualification-20261120.json) binds the
observations to Hoonarqube Foundation commit
`9084eeca7eb9350f028fa9a791b1f0f0ca395968`, version 0.11.1, and executable SHA-256
`e719261d0fe6db1f53d362da0ec55b3da152d4a9ec7034474b56018124552021`.

## Results

All 27 original Sonar analyses and API captures completed. Hoonarqube completed
26. Both tools measured identical files and bytes on 25 original projects
(1,404 files). These 25 form the totals below; the two narrower analyses
are separate observations.

| Comparison on 25 identical scopes | Result |
|---|---:|
| Primary matches on shared active rules with matching declared parameters | 1,782 |
| Hoonarqube-only findings in that subset | 707 |
| SonarQube-only findings in that subset | 515 |
| Primary matches across all valid ordinary file findings | 1,804 |
| Hoonarqube-only findings across all valid ordinary file findings | 15,988 |
| SonarQube-only findings across all valid ordinary file findings | 1,486 |
| Project size metrics equal (files, lines, code lines, comment lines) | 84 / 100 |
| Individual file metric values equal (lines, code lines, comment lines) | 3,434 / 4,212 |
| Duplication metrics equal (lines, blocks, density) | 45 / 75 |

Of the 15,988 broad Hoonarqube-only findings, 15,221 are on keys absent from
the active Sonar profiles. Of the 1,486 SonarQube-only findings, 916 are on
documented Hoonarqube implementation gaps. On the shared parameter subset,
Chi, CORS, pflag, Commons CLI, Rack, Sinatra, Rails Active Support and Rake
had no observed primary location differences. This claim is limited to that
subset, which includes only two to four qualifying keys in the Java/Ruby
examples. Other differences remain: FastAPI has 200 native-only and 193
reference-only findings in the subset, Jinja has seven and 131, and Zod has
58 and 81.

- **Chalk:** Sonar indexed three files while Hoonarqube measured ten. The
  shorter scope excludes `source/vendor/**` and `source/index.d.ts` on both
  sides. Both tools then measure the same three files; five matching, two
  native-only, and two reference-only findings remain on the shared parameter
  subset.
- **Redux:** Hoonarqube exited 2 after its parser recovered syntax in
  `src/types/store.ts`. Sonar indexed the full requested scope. The original
  row remains incomplete. The separate narrower scan excludes that file on
  both sides and compares 16 files, with 24 matching, three native-only, and
  five reference-only findings in the subset.
- **Java and Ruby:** the comparator reads the registered rule keys at the
  pinned native source revision. It uses those lists to account for the
  implemented detectors where the catalog's infrastructure inventory still
  lists a gap. Java's reference scanner received bytecode from direct
  OpenJDK 25.0.4.1 compilation targeting Java 8. The compiler ran on explicit
  source paths with annotation processing and network access disabled.
  Hoonarqube did not consume the bytecode.
- **Rust:** the native rules run from source. Sonar was explicitly set to
  `sonar.rust.clippy.enabled=false`; both reference scopes used its ordinary
  Rust sensor without imported Clippy reports. The pinned scanner image
  contains neither Cargo nor rustc.

The [separate first-pass receipt](public-corpus-qualification-df61eb8-20261120.json.gz)
uses code `df61eb877cac218108a297384ff118de9c20f5b6` and executable SHA-256
`1e5c6cf442f8dd4cf833da6140560a9d609e1978ee25812dbd0ad9d2e67f5e16` against the
same reference. Foundation adds 17 exact matches for Ruby S1134 and S1135;
the aggregate file and duplication metric totals are unchanged.

## What each count means

The Sonar server identified itself as Community Build `26.9.0.129388`
with its embedded development database. Its active profiles, rules, and
effective parameters were read from the running server. The receipt records
the server and scanner image digests, installed plugin builds, raw capture
digests, and timings. The native profile was `sonar-parity`, with its
separately frozen rule catalog. All live API pages were captured and checked
for completeness. Signed artifact provenance, Enterprise sensor execution,
C# project analysis, and production server behavior are outside this
campaign.

The summary matches a multiset of ordinary findings by rule key, project
relative path, and complete primary range. It converts native scalar columns
to Sonar UTF-16 offsets and preserves file-level findings and duplicate
records. Each tool's extra records remain visible. Message matches are counted
separately, and no claim is made about severity, flows, fixes, or duplication
group equivalence. Hotspots are counted separately from ordinary findings.
Sonar reported no hotspots in these runs; 61 native findings on hotspot keys
were outside the ordinary-issue comparison on the 25 identical original scopes.

The shared parameter subset intersects the active key lists and compares
Sonar's effective values with the native report's declared default values.
This controls for known parameter differences and does not prove that every
detector applied these values identically. The native report marked compiler
context missing for its TypeScript scans. The original Zod scan wrote an
embedded TypeScript helper after Sonar finished. The helper sits outside the
analyzed roots; all 125 files in both reports matched by path and SHA-256.
Replaying both binaries from a clean checkout reproduced their native
reports byte for byte. Five primary matches in Axios and Zod use keys emitted
by native but absent from its reported active set; they count toward the
broad totals only. A complete report therefore establishes
completion of a chosen scan, while equality applies only to explicitly
compared observations.

Tool wall times are diagnostics. The scanner ran as Linux amd64 under
emulation on an ARM host, with an ARM server in a VM and varying concurrency
and startup cache state. Native scans ran directly on macOS ARM. The figures
do not establish a throughput or speedup comparison.

## Reproduce

Use Python 3.11 or newer and a new private state directory outside the
repository. The scripts use local Docker and a dedicated internal network.
No project scripts, package installers, or build tools run; Java uses only the
isolated compiler described above. Leave several GiB available for images and
container data. The receipt records the two official OCI digests and their
architectures.

```sh
umask 077
state=/absolute/private/corpus
native=/absolute/path/to/pinned/hoonarqube
oracle=tools/oracle
server='sonarqube@sha256:c0f1160bccfa435db4168c2d7df69af3c3ea7bfeb87395613014048fb33a68c1'
scanner='sonarsource/sonar-scanner-cli:12.1.0.3233_8.0.1@sha256:23ca0f137965d9dff2198074043fd48d386280bc5d0ccac8c8349cea4cf096a9'
mkdir -p "$state/docker"
docker pull "$server"
docker pull --platform linux/amd64 "$scanner"
docker network create --internal hq-corpus-20261120
docker volume create hq-corpus-scanner-cache-20261120
docker run --detach --name hq-corpus-reference-20261120 \
  --network hq-corpus-20261120 --network-alias reference \
  --memory=5g --cpus=5 -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true \
  "$server" > "$state/docker/server.id"
docker exec hq-corpus-reference-20261120 curl -fsS http://127.0.0.1:9000/api/system/status
# Continue when the status is UP.

python3 "$oracle/public_corpus_prepare.py" --state "$state"
"$native" rules list --json > "$state/native-rule-catalog.json"
capture() {
  python3 "$oracle/public_corpus_capture.py" --state "$state" --binary "$native" \
    --manifest "$state/$1" --output "$state/$2" --jobs "$3"
}
capture pilot-projects.json pilot 1
python3 "$oracle/public_corpus_profiles.py" --state "$state"
capture projects.json captures 3
# Expected exit 2 above on the known Redux native parser failure.
capture projects-additional-ready.json additional 1
capture projects-aligned.json aligned 2

python3 "$oracle/public_corpus_summary.py" --state "$state" \
  --native-verified-commit 9084eeca7eb9350f028fa9a791b1f0f0ca395968 \
  --output "$state/summary.json"
```

The capture tool rotates the new server's default password and creates a local
token. Both files stay inside the private state directory. Each capture checks
that its checkout is clean before and after analysis. For Zod, it saves the
newly generated helper alongside the raw evidence after verifying its digest.
During a replay against an existing reference, preserve those captures and
run the native analysis independently into a new directory:

```sh
replay=/absolute/private/native-replay
mkdir -p "$replay"
"$native" rules list --json > "$replay/native-rule-catalog.json"
python3 "$oracle/public_corpus_capture.py" --state "$state" --binary "$native" \
  --manifest "$state/replay-projects.json" --output "$replay" --jobs 3 --native-only
python3 "$oracle/public_corpus_summary.py" --state "$state" --native-replay "$replay" \
  --native-verified-commit 9084eeca7eb9350f028fa9a791b1f0f0ca395968 \
  --output "$state/replay-summary.json"
```

Check that the manifest and binary SHA in the raw capture match the desired
inputs. Once captures are retained, dispose of the dedicated local reference
with `docker rm -f -v hq-corpus-reference-20261120`,
`docker volume rm hq-corpus-scanner-cache-20261120`, and
`docker network rm hq-corpus-20261120`. These names are unique to this recipe.
