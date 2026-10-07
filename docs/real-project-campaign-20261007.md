# Real-project SonarQube campaign — 2026-10-07

This campaign compares actual containerized SonarQube scans with Hoonarqube on
pinned public project sources. It improves measured defects without claiming
complete SonarQube equivalence. The frozen catalog provenance remains separate
from this newer behavioral reference.

## Reference environment and source scope

The reference server reported Community Build `26.9.0.129388` and `UP`.
Installed analyzer versions were Go `1.43.0.7704`, JavaScript/TypeScript
`13.8 (build 44569)`, and Python `5.31 (build 36502)`. The scanner image is
`sonarsource/sonar-scanner-cli:12.1.0.3233_8.0.1`, pinned to digest
`sha256:23ca0f137965d9dff2198074043fd48d386280bc5d0ccac8c8349cea4cf096a9`.
Python scans explicitly set `sonar.python.version=3.13`.

| Project | Source commit | Included roots | Exclusions |
|---|---|---|---|
| Requests | `611c6162cbc4ac2020a2f91c7cfa4f3abf9bbb60` | `src/requests` | none |
| Werkzeug | `6389612fd1ee1bd93579eed5026e8fd471d04abd` | `src/werkzeug` | `**/*.css` in aligned replay |
| Commander | `ba6d13ddb4243e5913367734f8c159089ffe7834` | `index.js`, `lib` | none |
| Chi | `167e1e3bd039d060696b99c8da4e876ae04f42c1` | repository root | `**/*_test.go`, `_examples/**` |
| Zod | `0b216ef674e297ebe41d8bf902262e56f8755822` | `packages/zod/src` | `**/tests/**`, `**/benchmarks/**` |

Werkzeug includes a JavaScript source file. The Python-only metric qualification
covers its 52 Python files; the full aligned project scan also includes that
JavaScript file. Those scopes must not be combined into a single metric claim.
The initial unrestricted Werkzeug reference indexed CSS that Hoonarqube does
not analyze; the aligned replay explicitly excludes CSS on both sides.

## Method and evidence

[`real_project_suite.py`](../tools/oracle/real_project_suite.py) verifies the
source commit and clean tracked state, mounts source read-only into the scanner,
waits for successful compute-engine processing, and saves paginated issues,
hotspots, active profiles/rules, indexed files, and project measures. Native
replays bind the executable SHA-256 and source-file SHA-256 values. A replay
rejects changed reference scope or changed captured source content. Failures and
timeouts remain failures in the summary.

The finding comparator uses a multiset of rule key, normalized relative path,
and complete primary range. It preserves duplicate findings and file-level
reference findings. A native report must be complete before it can be compared.
`./file` and `file` denote the same relative source path. Path traversal and
absolute finding paths are rejected.

The server's effective Sonar way profile and Hoonarqube's frozen compatibility
profile have different active rules. Raw finding totals therefore include
profile differences. Matching the captured active rule subset is a distinct
comparison; disabling a native rule does not repair that rule's detector.
Hotspots are captured separately from ordinary issues and must not be silently
counted as missing issue findings. The basic identity comparator does not certify
message text, secondary locations, flows, fixes, or duplication equivalence.

Detailed raw captures, logs, protected tokens, and absolute workstation paths
remain outside Git. Portable summaries identify source and executable digests
and preserve non-pass results without publishing credentials or vendoring the
scanned project sources.

## Baseline metrics and qualified corrections

The pre-campaign executable SHA-256 is
`5a00bf4df6796a5bf2222001fa59baf9ae888065cc76952ef72af3e8c72d58ce`.
Its replay uses normalized finding paths and captured source manifests.
The following values compare that project's native measurements with the
reference for identical listed source scopes. The Python helper qualification
below uses Python-only subsets and must not be substituted for the full
Werkzeug project row.

| Project | Physical lines: baseline/reference | Code lines: baseline/reference | Comment lines: baseline/reference |
|---|---:|---:|---:|
| Requests | 6394 / 6413 | 4743 / 3564 | 443 / 1869 |
| Commander | 4201 / 4208 | 2345 / 2345 | 1433 / 1485 |
| Chi | 4400 / 4435 | 2841 / 2841 | 967 / 888 |
| Zod | 37725 / 37850 | 30332 / 30336 | 3705 / 4057 |

These baseline differences motivated shared physical-line and language-owned
code/comment fixes. Exact integrated results are recorded by a subsequent
executable-bound replay; helper equality alone does not certify the CLI.

## Repairs qualified during the campaign

### Go and shared project metrics

- Explicit test scope now suppresses MAIN rules while preserving conventional
  `_test.go` scope. Go 1.26 expression-form `new` uses the same compatible parse
  for analysis and source facts, preserving original token bytes and malformed
  source failures.
- Physical file lines include the terminal empty row; empty source reports one
  physical line. Parser resource accounting remains bounded independently.
- Go comments count meaningful header and inline comments, exclude blank
  decoration and NOSONAR markers, and share one helper across report paths.
- `select` contributes neither cognitive score nor cognitive nesting. Error
  nil-guards without `else` receive the observed exemption only when conservative
  lexical facts prove an error type. Pointer variables named `err`, shadowed
  bindings/imports/types, and unknown call results do not qualify by name.

For Chi, the 35-file source scope measures `lines=4435`, `ncloc=2841`, and
`comment_lines=888`, matching the captured reference. All ten S3776 primary
findings and messages match after the fixes, including `addChild` score 16 and
`walk` score 19. This does not certify cognitive secondary flows or CPD.

### Python

- Cookie flags resolve actual framework receivers and bindings; Requests
  `CookieJar.set_cookie` no longer produces framework-cookie false positives.
  Explicit `False` flags remain findings for the qualified framework controls.
- Weak-hash analysis resolves aliases, keyword algorithms, callable references,
  and rebinding. The bounded SHA1 digest exemption observed in Werkzeug is
  qualified alongside full-digest positive controls.
- A production module named `test.py` retains MAIN scope. Basename alone does
  not establish a test source.
- Python measurements use Ruff syntax facts for actual docstrings, import
  delimiters/trivia, inline comments, and trailing comments. Invalid native
  syntax remains incomplete even where a tolerant Tree-sitter parse succeeds.

The Python metric helper matches every captured file's physical/code/comment
metrics in Requests (19 files: 6413/3564/1869) and Werkzeug's Python subset
(52 files: 21418/11882/6635). These helper qualifications are distinct from a
final integrated CLI replay and from duplication metrics.

### JavaScript and TypeScript

- S4158 follows scoped empty-collection bindings, invalidates facts on mutations,
  escapes and unknown uses, and keeps construction/mutation negative controls.
- Exported declarations correctly mark module scope for S3798. S3800 ignores
  null/undefined as independent inconsistent return categories.
- S6959 selects the method token and S7721 selects the declaration head, matching
  the observed primary ranges.
- Comment measurement excludes file headers before actual code, counts meaningful
  inline comments, ignores empty decoration/NOSONAR, and handles comment-only
  sources. Shebangs do not count as code or start the body-comment region.
- Multiline literal spans include interior blank code rows in project metrics.

The comment helper matches all seven Commander files (`comment_lines=1485`)
and all 125 Zod files (`comment_lines=4057`). The independently checked token
measurement gives reference ncloc 2345 and 30336 respectively. Integrated
project metrics and findings require their own executable-bound acceptance.

## Remaining limits

This campaign covers five projects and focused positive/negative controls. It
is not the full rule corpus or an Enterprise analyzer qualification. The
repository's historical full-corpus non-pass evidence remains valid for its
recorded source and reference versions.

Unresolved differences include compiler-type-dependent Commander S6551 and
S7755 cases, broader Python/JS/TS detector differences, and project duplication
metrics/grouping. Go error-type inference remains conservative for unknown
imported signatures and cross-file callbacks. S4158 retains observed upstream
name-based constructor recognition and its limited indexed-assignment treatment;
those limits are documented rather than hidden behind exact-parity language.

Coverage counts describe registered implementations and direct tests. They do
not convert any of these remaining differences into reference parity. A source
commit, successful CI, merged PR, and published artifact are separate states;
release claims must be tied to the tested/published executable.

## Reproduce

Provide a manifest with the pinned rows above, local clean checkout paths, and
dedicated Sonar project keys. Use a protected token file and an existing local
containerized server. The harness does not provision or reset a server.

```sh
python3 tools/oracle/real_project_suite.py \
  --manifest /path/to/projects.json \
  --output /path/to/campaign-evidence \
  --binary /path/to/hoonarqube \
  --token-file /path/to/protected-sonar-token \
  --label acceptance

python3 tools/oracle/real_project_suite.py \
  --manifest /path/to/projects.json \
  --output /path/to/campaign-evidence \
  --binary /path/to/updated-hoonarqube \
  --native-only --label replay

CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo run --locked -q -j 2 -p xtask -- \
  catalog coverage --strict --allow-infra
```

Default server/scanner endpoints are loopback and `host.docker.internal`,
respectively; configure them when the container runtime uses different routing.
Raw issue/source captures are evidence for this campaign's selected scopes,
not a replacement for the frozen catalog provenance.
