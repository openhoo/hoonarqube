# Hoonarqube actions

Use immutable action revisions in consuming repositories.

```yaml
- uses: openhoo/hoonarqube/actions/analyze@<full-commit-sha>
  with:
    version: 0.3.1
    paths: |
      src
      tests
```

`actions/setup` verifies the Linux X64 release archive checksum and installed
binary version. `actions/analyze` writes SonarQube Generic Issue Import JSON.
Its `profile` input accepts `sonar-parity` (default), `recommended`, `extended`,
or `strict`; native rules remain disabled unless a native profile is selected.
Non-default profiles require a release containing the native catalog, or the
`executable` input pointing at a compatible local build.
Adoption is report-only by default because Hoonarqube does not yet have a
reviewed baseline contract; set `fail-on` explicitly only after repository
findings have been reviewed. Directory analysis honors repository ignore files.
Repository self-tests may set `executable` to a freshly built local binary;
normal consumers should omit it so the verified release installer runs.
