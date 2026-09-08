# Hoonarqube actions

Use immutable action revisions in consuming repositories. Pin both the
checkout action and each Hoonarqube action to a full commit SHA.

## SonarQube Generic Issue Import

```yaml
- uses: openhoo/hoonarqube/actions/analyze@03b34bc8957995959d43531e82130a2c95bf01fa # pinned revision
  with:
    version: 0.7.0
    paths: |
      src
      tests
    output: hoonarqube.json
    fail-on: none
```

`actions/setup` verifies the Linux X64 release archive checksum and installed
binary version. `actions/analyze` writes SonarQube Generic Issue Import JSON.

Its `profile` input accepts `sonar-parity` (default), `recommended`, `extended`,
or `strict`; native rules remain disabled unless a native profile is selected.
Non-default profiles require a release containing the native catalog, or the
`executable` input pointing at a compatible local build.
`cache-dir` is optional on both analysis actions. When it is nonempty, the
action passes the value as one literal `--cache-dir` argument; paths containing
spaces or shell metacharacters are not re-parsed. Set it only when the selected
`executable` or release supports that CLI flag. Leave it empty for older
releases to preserve their uncached behavior.

## GitHub Code Quality SARIF

```yaml
- id: hoonarqube
  uses: openhoo/hoonarqube/actions/code-quality@03b34bc8957995959d43531e82130a2c95bf01fa # pinned revision
  with:
    version: 0.7.0
    paths: |
      src
      tests
    output: hoonarqube.sarif
    upload: false
```

`actions/code-quality` validates SARIF 2.1.0 and exposes `report`,
`result-count`, and `blocking-findings` outputs. Upload is opt-in; set
`upload: true` only for trusted pushes or same-repository pull requests and
grant `security-events: write`. The action's profile is the isolated
`github-code-quality` profile.

Adoption is report-only by default because Hoonarqube does not yet have a
reviewed baseline contract. `fail-on` accepts `none` (default), `findings`,
`note`, `warning`, or `error`. A validated report is uploaded before a
configured threshold fails the job. Directory analysis honors repository
ignore files. Repository self-tests may set `executable` to a freshly built
local binary; normal consumers should omit it so the verified release installer
runs.

## GitLab Code Quality

GitLab consumes a native Code Quality report from a CI artifact rather than
the GitHub SARIF action. On a Linux x86_64 runner, install and verify the
released `hoonarqube` binary using the repository's [release installer checks](setup/install.sh),
then invoke the CLI directly:

```yaml
stages: [quality]

gitlab-code-quality:
  stage: quality
  script:
    - hoonarqube --version
    - set +e
    - hoonarqube analyze --format gitlab-codequality -- src tests > gl-code-quality-report.json
    - status=$?
    - set -e
    - test -s gl-code-quality-report.json
    - exit "$status"
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality-report.json
```

The report is one deterministic JSON array. It contains `description`,
`check_name`, and a stable SHA-256 `fingerprint` over the normalized primary
path, rule, message, and primary range; nested flow/fix metadata is excluded.
It also contains lowercase GitLab severity and raw repository-relative POSIX
paths with positive inclusive line ranges. Ordinary colon filename components
are retained, while drive/URI-like prefixes, backslashes, control characters,
and invalid ranges fail closed. File-level findings are anchored at line 1; an
empty report is `[]`. Incomplete scans still emit the report and exit 2, while
serialization or path errors exit 1.

## Optional caller-managed analysis cache

The actions do not restore or save cache state themselves. A consuming workflow
can opt in at its boundary when it runs a release or locally built CLI that
supports `--cache-dir`. Keep the cache path outside the analyzed tree to avoid
traversing cache artifacts. The CLI reserves an owned
`.hoonarqube-cache-v1` child under that path; `--cache-dir .` does not exclude
arbitrary source files. Cache failures are fail-open. Use a stable restore
prefix plus a commit-specific key, and save only from the protected primary
branch. Pull requests, including fork pull requests, should restore only; never
let an untrusted branch save into the namespace used by primary-branch jobs.
The cache actions below use the officially resolved `actions/cache` v6.1.0
commit.

```yaml
permissions:
  contents: read

jobs:
  code-quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-checkout-sha>

      # Use a release and action revision that both support --cache-dir.
      - uses: openhoo/hoonarqube/actions/setup@<full-action-sha>
        with:
          version: <release-with-cache-dir-support>

      - name: Restore Hoonarqube analysis cache
        id: hoonarqube-cache
        uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
        with:
          path: ${{ github.workspace }}/.cache/hoonarqube
          key: hoonarqube-code-quality-v1-${{ runner.os }}-${{ runner.arch }}-${{ github.sha }}
          restore-keys: |
            hoonarqube-code-quality-v1-${{ runner.os }}-${{ runner.arch }}-

      # Reuse exactly the CLI installed by setup; do not mix cache formats.
      - id: hoonarqube
        uses: openhoo/hoonarqube/actions/code-quality@<full-action-sha>
        with:
          executable: hoonarqube
          cache-dir: ${{ github.workspace }}/.cache/hoonarqube
          paths: |
            src
          upload: false

      - name: Save Hoonarqube analysis cache
        if: >-
          github.event_name == 'push' &&
          github.ref == 'refs/heads/main' &&
          steps.hoonarqube-cache.outputs.cache-hit != 'true'
        uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
        with:
          path: ${{ github.workspace }}/.cache/hoonarqube
          key: hoonarqube-code-quality-v1-${{ runner.os }}-${{ runner.arch }}-${{ github.sha }}
```

This repository's small `crates/hoonarqube-cli/src` self-analysis fixture
exercises the cache wiring but is not expected to produce a material CI speedup
because the corpus is tiny and cache contents change with binary and source
revisions. Larger consuming repositories with repeated per-file analysis get
the practical benefit; the caller should still treat a cache miss as normal and
avoid granting extra permissions.
