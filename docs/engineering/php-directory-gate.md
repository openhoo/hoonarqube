# Mixed PHP directories and assigned gates

The server assigned the same gate to two private Community Build 26.11.0.134175 projects. It fails when the overall file count exceeds one. Both analyses used the same two unmodified files from [Laravel](https://github.com/laravel/laravel/tree/c1fc3a0e69be0a453cfce6bbb105b2b839b55bdb): `resources/js/app.js` and `routes/web.php`. The [reference fixture](../../tools/oracle/fixtures/laravel-php-gate-2611.json) records the source tree and SHA-256 hashes, scanner and server images, profiles, analysis IDs, indexed files and decisions.

| Scope | Community reference | HoonarQube assigned gate | CI exit |
| --- | --- | --- | --- |
| Both files | 2 files, error | PHP unmeasured, unavailable | 2 |
| Exclude `**/*.php` | 1 file, OK | 1 file, pass | 0 |

HoonarQube previously passed the mixed directory because it visited only the JavaScript file. Naming both files explicitly already reported the incomplete measurement. Directory scans now preserve the same PHP inventory entry, including when directory and explicit arguments overlap. The public replay submits raw assessments to an independent service, checks the assigned policy and CI exit, restarts the service, and reads each stored decision again.

```sh
cargo build --locked --release -p hoonarqube-cli -p hoonarqube-service
python3 tools/oracle/public_php_gate.py target/release
```

The check validates the `.php` extension, the documented scope exclusion, and the assigned file-count gate on these sources. It does not implement PHP analysis or establish equivalent PHP metrics or findings.
