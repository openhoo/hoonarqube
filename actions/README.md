# Hoonarqube actions

Use immutable action revisions in consuming repositories. Pin both the
checkout action and each Hoonarqube action to a full commit SHA.

## SonarQube Generic Issue Import

```yaml
- uses: openhoo/hoonarqube/actions/analyze@03b34bc8957995959d43531e82130a2c95bf01fa # pinned revision
  with:
    version: 0.4.0
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

## GitHub Code Quality SARIF

```yaml
- id: hoonarqube
  uses: openhoo/hoonarqube/actions/code-quality@03b34bc8957995959d43531e82130a2c95bf01fa # pinned revision
  with:
    version: 0.3.1
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
