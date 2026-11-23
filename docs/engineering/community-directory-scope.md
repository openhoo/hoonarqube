# Which Community source files can block a directory gate?

A project gate must not pass on the measured part of its declared sources. HoonarQube checks native dispatch first. When no analyzer supports a file that Community demonstrably indexes, directory scans retain it as unmeasured source. For the overall file-count gate below, CI exits 2 until the file is measured or the configured scope explicitly excludes it.

## Measured scope

Two private Community Build 26.11.0.134175 projects used the same scanner image, the same twenty unmodified files from [GitHub Linguist](https://github.com/github-linguist/linguist/tree/cfd7a0113aa1efab99faeff38756f0ed4d48add8), and a project-assigned gate allowing at most one file. The unrestricted analysis indexed fifteen files and failed. The second analysis explicitly excluded the nineteen files other than the JavaScript control: one file, pass. The [capture](../../tools/oracle/fixtures/linguist-community-scope-2611.json) pins the source commit, tree and original file bytes, scanner and server images, task and analysis IDs, indexed paths and language keys, and the assigned decisions.

| Observed Community language | Observed paths or extensions | Native directory behavior |
| --- | --- | --- |
| JavaScript, HTML | `.js`, `.html` | Existing native analyzer wins |
| CSS | `.css`, `.less`, `.scss`, `.sass` | Unmeasured source |
| Docker | Exact filename `Dockerfile` | Unmeasured source |
| Flex, notebooks, PHP | `.as`, `.ipynb`, `.php` | Unmeasured source |
| Kotlin, Terraform, VB.NET, XML | `.kt`, `.kts`, `.tf`, `.vb`, `.xml` | Unmeasured source |
| Not indexed for these particular bytes | `.hcl`, `.json`, `.md`, `.yaml`, `.yml` | No new recognition |

HoonarQube keeps its existing case-insensitive extension matching. Only the exact Docker basename was verified; other Docker names retain their previous informational inventory behavior. Unknown extensions, native analyzers, explicit scope exclusions, and separately classified generated or vendor files keep their existing precedence. An installed plugin or an extension listed in a setting alone does not qualify a new mapping. JSON and YAML may have content- or configuration-specific handling; this capture cannot establish a general rule for them.

## Repeat the native acceptance

```sh
cargo build --locked --release -p hoonarqube-cli -p hoonarqube-service
python3 tools/oracle/public_community_directory_scope.py target/release
```

The public replay verifies the checked-out Git tree, blob identity, SHA-256 and ordinary file mode. It checks the complete and expressly restricted scopes, overlapping arguments, and each candidate paired separately with the native JavaScript control. Every indexed pair also has an explicit-exclusion control. Each case checks the inventory, CLI decision, separately assigned service policy, CI exit and persisted verdict after restart. The reference measures the two complete scopes. The per-file pairings are native regression checks, not additional Community analyses.

This covers directory inventory and the assigned overall file-count policy. It does not provide new language parsers, findings, rule parity, or a replacement for a team's own acceptance run.
