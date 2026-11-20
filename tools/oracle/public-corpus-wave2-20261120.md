# Public source comparison with SonarQube, second wave

November 20, 2026. This extends the first public corpus by selecting 42
different GitHub repositories across the same seven languages. The
[manifest](public-corpus-wave2-projects-20261120.json) records exact commits,
trees, source roots, exclusions, and the analysis keys. The
[receipt](public-corpus-wave2-qualification-20261120.json) records every outcome.

Hoonarqube completed **35** scans and SonarQube Community
Build `26.9.0.129388` completed **39**.
Both tools measured **1,142** identical files across
**32** identical project scopes. The remaining rows
are visible below and excluded from the whole-scope totals.

| Observation on identical scopes | Matches or equal | Hoonarqube only | SonarQube only |
| --- | ---: | ---: | ---: |
| Primary findings on shared rules with matching declared parameters | 1,314 | 1,163 | 286 |
| All valid ordinary primary findings | 1,314 | 12,873 | 1,003 |
| Project size metric values | 108 / 128 |  |  |
| File size metric values | 2,912 / 3,422 |  |  |
| Duplication metric values | 56 / 96 |  |  |

The comparator matches primary findings by rule, relative path and full
UTF-16 range. Supplementary evidence, message or severity equivalence, fixes,
and duplication group equality are outside these totals. A filter for matching
declared rule parameters does not establish detector equivalence.

## Results by language

| Language | Selected | Native complete | Reference complete | Identical scopes | Identical files | Matches / native-only / reference-only on shared parameters |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Python | 6 | 6 | 6 | 6 | 137 | 496 / 46 / 55 |
| Go | 6 | 6 | 6 | 6 | 82 | 69 / 8 / 7 |
| JavaScript | 6 | 6 | 6 | 5 | 357 | 643 / 640 / 179 |
| TypeScript | 6 | 2 | 6 | 2 | 38 | 53 / 6 / 38 |
| Rust | 6 | 4 | 5 | 4 | 147 | 12 / 140 / 0 |
| Java | 6 | 6 | 4 | 4 | 148 | 8 / 131 / 3 |
| Ruby | 6 | 5 | 6 | 5 | 233 | 33 / 192 / 4 |

## Project outcomes

| Repository | Commit | Native | SonarQube | Comparison | Files in common |
| --- | --- | --- | --- | --- | ---: |
| pallets/itsdangerous | `672971d66a2e` | complete | complete | Identical files | 8 |
| pypa/packaging | `cf2cdf099375` | complete | complete | Identical files | 22 |
| python-trio/trio | `c327959a7175` | complete | complete | Identical files | 78 |
| psf/black | `a12e95913f51` | complete | complete | Identical files | 25 |
| aio-libs/async-lru | `c43b72733ec6` | complete | complete | Identical files | 1 |
| more-itertools/more-itertools | `e3f79f4fde5f` | complete | complete | Identical files | 3 |
| spf13/cobra | `adbc8813901b` | complete | complete | Identical files | 14 |
| gorilla/websocket | `e064f32e3674` | complete | complete | Identical files | 12 |
| robfig/cron | `bc59245fe10e` | complete | complete | Identical files | 8 |
| stretchr/testify | `87a7b9d57689` | complete | complete | Identical files | 18 |
| gofrs/uuid | `e77e0425f797` | complete | complete | Identical files | 5 |
| alecthomas/kong | `af6c65142cbc` | complete | complete | Identical files | 25 |
| acornjs/acorn | `e4516ce0f49a` | complete | complete | Different file scope | 26 |
| jquery/jquery | `effd615f0009` | complete | complete | Identical files | 138 |
| eslint/eslint | `e0148e30da66` | complete | complete | Identical files | 20 |
| jashkenas/underscore | `5c1e5f686f85` | complete | complete | Identical files | 161 |
| yjs/yjs | `ee37f0a0e23a` | complete | complete | Identical files | 32 |
| micromatch/picomatch | `9fab7bf61913` | complete | complete | Identical files | 6 |
| vercel/swr | `8148ef012fd5` | incomplete | complete | Incomplete or unavailable | — |
| floating-ui/floating-ui | `c3042f1f37d9` | complete | complete | Identical files | 15 |
| pmndrs/zustand | `9fed2eb2f3af` | incomplete | complete | Incomplete or unavailable | — |
| react-hook-form/react-hook-form | `265ecb970fda` | failed | complete | Incomplete or unavailable | — |
| TanStack/query | `8b2e8af0768c` | complete | complete | Identical files | 23 |
| vuejs/pinia | `4023d1233724` | incomplete | complete | Incomplete or unavailable | — |
| BurntSushi/ripgrep | `43fc97d43a4c` | complete | complete | Identical files | 20 |
| tokio-rs/bytes | `67edc2b999d6` | complete | complete | Identical files | 19 |
| crossbeam-rs/crossbeam | `a28f40fdddb7` | Not run | Not run | Source scope rejected | — |
| rayon-rs/rayon | `599425d4a4c6` | complete | complete | Identical files | 99 |
| rust-lang/log | `75fcb86da1cc` | complete | complete | Identical files | 9 |
| dtolnay/anyhow | `dd0c0a655a21` | incomplete | complete | Incomplete or unavailable | — |
| google/gson | `6a368d89da37` | complete | not_run | Incomplete or unavailable | — |
| stleary/JSON-java | `324090a87609` | complete | complete | Identical files | 26 |
| jhy/jsoup | `db6dc74ccd31` | complete | not_run | Incomplete or unavailable | — |
| apache/commons-csv | `660f7c9f8530` | complete | complete | Identical files | 12 |
| apache/commons-codec | `e59fc7653114` | complete | complete | Identical files | 80 |
| java-diff-utils/java-diff-utils | `71981d8faaff` | complete | complete | Identical files | 30 |
| jnunemaker/httparty | `591b9f68d1cd` | complete | complete | Identical files | 24 |
| heartcombo/devise | `05811fb8366e` | incomplete | complete | Incomplete or unavailable | — |
| bkeepers/dotenv | `34156bf400cd` | complete | complete | Identical files | 18 |
| varvet/pundit | `ea9e31a2d799` | complete | complete | Identical files | 16 |
| redis/redis-rb | `9d3a2625ccbb` | complete | complete | Identical files | 48 |
| teamcapybara/capybara | `265d2d175f4b` | complete | complete | Identical files | 127 |

### Boundaries and failures

- **crossbeam-channel:** Tracked symlink crossbeam-channel/src/alloc_helper.rs inside the selected root. Neither analyzer ran on that scope.
- **gson:** The Java 8 bridge rejected module-info.java. The project also expects Maven-filtered Java sources. The native source analysis remains in the receipt.
- **jsoup:** The isolated compiler could not resolve javax.annotation.Nullable (JSR 305). The native source analysis remains in the receipt.
- **react-hook-form:** A hash-verified native TypeScript helper appeared under the selected src root after the scan. The checkout guard rejected the row; its completed SonarQube scan remains in the receipt.
- **acorn:** 1 native-only and 0 SonarQube-only files. Only the intersection is compared.
- **anyhow:** Native analysis reported incomplete files: `src/ensure.rs`, `src/macros.rs`.
- **devise:** Native analysis reported incomplete files: `lib/generators/active_record/templates/migration.rb`, `lib/generators/active_record/templates/migration_existing.rb`, `lib/generators/templates/controllers/confirmations_controller.rb`, `lib/generators/templates/controllers/omniauth_callbacks_controller.rb`, `lib/generators/templates/controllers/passwords_controller.rb`, `lib/generators/templates/controllers/registrations_controller.rb`, `lib/generators/templates/controllers/sessions_controller.rb`, `lib/generators/templates/controllers/unlocks_controller.rb`, `lib/generators/templates/devise.rb`.
- **pinia:** Native analysis reported incomplete files: `packages/pinia/src/devtools/formatting.ts`.
- **swr:** Native analysis reported incomplete files: `src/_internal/types.ts`, `src/infinite/types.ts`, `src/mutation/types.ts`.
- **zustand:** Native analysis reported incomplete files: `src/middleware/subscribeWithSelector.ts`, `src/react.ts`, `src/traditional.ts`, `src/vanilla.ts`.

## Provenance and method

The executable SHA-256 was `e719261d0fe6db1f53d362da0ec55b3da152d4a9ec7034474b56018124552021`. It was built at
`9084eeca7eb9350f028fa9a791b1f0f0ca395968`. The fetched `main` commit
`e43dc65805fdba7c4cd27c1cbfc6f285c717f87d` had the identical Git tree
`5d9ccd5cc837d3fb2105172bcbeccb7cfc0866bc`.

The reference used the same pinned SonarQube and scanner images as the first
wave, a fresh embedded database and a dedicated internal Docker network.
No package manager, Maven, Gradle, Cargo, or project script ran. Java bridge
classes came from isolated javac invocations with annotation processing disabled.
Rust ran without Clippy. The quality profiles were read live before and after
the corpus; effective values and active keys matched. Per-project quality
profile IDs, rule counts and update markers matched the live pilot. The
scanner ran on an emulated architecture, so the timings do not compare
production throughput. C# project analysis and Enterprise sensors are outside
this qualification.

## Reproduce

Use Python 3.11 or newer, a private state directory, and the exact binary.
Set `PYTHONPATH` to the first wave's oracle scripts. Use the image digest
recorded in the receipt to start the reference with the following names:

- Container: `hq-public-wave2-reference-20261120`.
- Internal network with alias `reference`: `hq-public-wave2-local-20261120`.
- Scanner cache volume: `hq-public-wave2-scanner-cache-20261120`.
- Record the returned container ID in `$state/docker/server.id`.

Then prepare the pinned sources and isolated Java inputs:

```sh
python3 public_corpus_wave2_prepare.py --state "$state" --manifest public-corpus-wave2-projects-20261120.json
python3 public_corpus_wave2_prepare.py --state "$state" --java
"$native" rules list --json > "$state/native-rule-catalog.json"
python3 public_corpus_wave2_capture.py --state "$state" --binary "$native" --jobs 1 pilot
python3 public_corpus_wave2_capture.py --state "$state" profiles
python3 public_corpus_wave2_capture.py --state "$state" --binary "$native" --jobs 2 captures
# Record a nonzero capture result and continue with the received rows.
python3 public_corpus_wave2_capture.py --state "$state" profiles-end
python3 "$PYTHONPATH/public_corpus_summary.py" --state "$state" --native-verified-commit e43dc65805fdba7c4cd27c1cbfc6f285c717f87d --output "$state/raw-summary.json"
python3 public_corpus_wave2_report.py --state "$state" --summary "$state/raw-summary.json" --out "$state/portable"
```

The runner refuses new checkouts and scans when fewer than 5 GiB are free.
It retains raw captures in the private state directory.
