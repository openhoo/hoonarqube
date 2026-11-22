# Rust S2208: wildcard import locations, November 22, 2026

Across seven pinned public Rust projects (293 source files), the native scanner now
matches all 101 wildcard imports reported by Community Build 26.9 with Clippy
enabled, at the same file and UTF-16 range. Previously none of the 153 native
ranges matched. The new scanner still reports 52 additional sites on this scope.

| Project | Files | Previous native | Reference | New exact matches | New native only |
| --- | ---: | ---: | ---: | ---: | ---: |
| Rayon | 99 | 104 | 98 | 98 | 6 |
| clap | 56 | 3 | 2 | 2 | 1 |
| memchr | 37 | 4 | 1 | 1 | 3 |
| serde-json | 37 | 31 | 0 | 0 | 31 |
| log | 9 | 8 | 0 | 0 | 8 |
| hashbrown | 28 | 1 | 0 | 0 | 1 |
| indexmap | 27 | 2 | 0 | 0 | 2 |
| **Total** | **293** | **153** | **101** | **101** | **52** |

For example, on line 8 of Rayon's `src/array.rs`, all three tools now highlight
`crate::iter::plumbing::*` at zero-based UTF-16 offsets `4..28`. The previous
native range was `27..28`. Each member of a grouped import gets its own range.
The fixture includes a separate Clippy compiler control for grouped, spaced and
bare-star imports; the native regression is
`wildcard_import_ranges_identify_each_imported_path`.

## What was compared

Each revision was analyzed in two separate Community Build projects. In one,
the built-in Sonar way Rust profile ran the Clippy sensor, which maps
`clippy::wildcard_imports` to `rust:S2208`. In the other, the integrated sensor
was disabled and the external report importer read the first run's unchanged
Cargo JSONL. It reported `external_clippy:wildcard_imports`. After mapping these
two keys, both result sets and the independent offline Clippy run agreed at
every in-scope primary location, including multiplicity. One Rayon dependency
warning outside the indexed files was excluded. The original public-corpus
measurements with the integrated sensor disabled remain separate.

The reference was Community Build 26.9.0.129388, scanner CLI 8.0.1.6346 and Rust
plugin 1.8.1.3395. The scanner's own Cargo invocation ran in a Linux ARM64
container with Rust 1.96.0 and Clippy 0.1.96. Project sources and dependency cache
were mounted read-only and compilation ran offline with a fresh target directory.
The [receipt](rust-wildcard-imports-20261122.json) records tool and image digests,
the plugin mapping, source and lockfile hashes, all 14 successful compute task and
analysis IDs, both inventories, and all remaining native-only ranges.

## What explains some of the differences

- serde-json explicitly allows this lint in `src/lib.rs:326–343`. With the
  `float_roundtrip` feature, ordinary Clippy emitted zero warnings; forcing
  the same lint emitted 31, all at native locations.
- log with `kv_std` emitted five in-scope warnings, all exact native matches;
  the default build emitted none. The default memchr build reached the AArch64
  implementation; other architecture paths were not compiled.
- Adding `--lib --tests` produced four findings for clap, two matched by native.
  Indexmap's corresponding run succeeded with zero. Its separate `--all-targets`
  probe failed on the nightly-only benchmark (`E0554`) and is excluded from
  the counts. These measurements do not establish parity on other features,
  targets or platforms, or classify every remaining difference as an error.

## Replay the captured comparison

The [evidence archive](fixtures/rust-wildcard-imports-20261122.tar.gz) contains
the native outputs, raw Community results, restricted scanner settings read back
from the compute tasks, scanner logs, Cargo diagnostics, arguments and exit codes.
Only the local qualification root in logs and import paths was replaced.
Its SHA-256 is `195a042bddc94dc831a9b4a185d5be000bd614f336079c035457a2a0552a20b6`.
Public project sources are fetched separately by exact revision. From the
repository root, with Git, jq and Python 3.11 or newer:

```sh
replay=$(mktemp -d)
tar -xzf tools/oracle/fixtures/rust-wildcard-imports-20261122.tar.gz -C "$replay"
for project in clap hashbrown indexmap log memchr rayon serde-json; do
  case_dir="$replay/cases/$project"
  repo=$(jq -r --arg p "$project" '.waves[].cases[] | select(.name == $p) | .repository' docs/engineering/public-projects-2026-11-21.json)
  rev=$(jq -r .commit "$case_dir/revision.json")
  git init -q "$case_dir/source"
  git -C "$case_dir/source" fetch -q --depth=1 "https://github.com/$repo.git" "$rev" || exit 1
  git -C "$case_dir/source" checkout -q --detach FETCH_HEAD || exit 1
  if [ "$project" != clap ]; then
    cp "tools/oracle/rust-wildcard-locks/$project.lock" "$case_dir/source/Cargo.lock"
  fi
done
python3 tools/oracle/rust_wildcard_qualification.py --captures "$replay/cases" --output "$replay/receipt.json"
cmp "$replay/receipt.json" tools/oracle/rust-wildcard-imports-20261122.json
```

This recomputes the finding comparison without a running reference server.
Adding `--run-candidate --candidate /absolute/path/to/hoonarqube` reruns native
analysis on precisely the same files and records the supplied executable's hash.
Use a disposable extraction for a fresh run: it replaces the native after-reports.
