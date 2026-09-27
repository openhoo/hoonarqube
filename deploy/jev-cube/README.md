# Hoonarqube Jev Cube service

This service runs the fixed Jev request in disposable Cube sandboxes on
`openhoo-cube-01`. GitHub Actions owns event delivery, concurrency, issue
readback and writes. The service has no GitHub credential.

## Deploy

Use an authenticated Tailscale SSH operator session. Confirm the hostname and
healthy Cube API before deploying. Generate `contract.json` from the same
trusted checkout as the broker and workflow:

```sh
node -e 'const p=require("./.github/scripts/jev-triage-policy.cjs");console.log(JSON.stringify({model:p.MODEL,questions:p.QUESTIONS}));'
```

Install `broker.py` and the generated contract in a revision-named directory
under `/opt/hoonarqube-jev-cube/releases/`, and point `current` at that release.
Install the included systemd unit. The existing runtime is
`/opt/drachen-agent-venv/bin/python` with `e2b==2.29.5` and
`e2b-code-interpreter==2.8.1`.

Copy the existing public Cube CA to `/etc/hoonarqube-jev-cube/cube-ca.pem`.
Deliver the host's existing Cube API key directly from its protected source
to `systemd-creds encrypt --name=cube-api-key - <credential path>`; do not
print it or write a plaintext copy. The credential path is
`/etc/hoonarqube-jev-cube/cube-api-key.cred`, mode 0600. The dynamic service
user receives it through `LoadCredentialEncrypted`; it does not read the
host bootstrap environment. Keep the directory root-owned and non-writable
by the service.

The broker accepts only the generated model and questions contract. Deploy
both broker and workflow from matching source whenever that contract changes.
The `/health` response includes the contract SHA-256. Restart the service,
read back its active state and release target, and verify a real request
through the broker with the dedicated Jev key before enabling GitHub.

## Tailscale trust

Use the exact federated identity and repository variables specified in
[`docs/automated-triage.md`](../../docs/automated-triage.md). The network delta
is one admin-owned `tag:hoonarqube-triage` tag, one grant to
`100.114.173.91` on `tcp:9138`, and accept/deny tests for that principal.
Validate before applying, use the current ETag, and read back the exact delta.
Do not grant SSH or access to the Cube dashboard/API.

## Verify and activate

Run the default-branch `Issue intake` workflow in `verify` mode. It uses the
real OIDC trust, private broker, fresh Cube sandboxes, dedicated Jev key and
eight synthetic cases. Inspect the GitHub run and the service journal, which
contains only sandbox IDs and input hashes. A provider failure, malformed
response or wrong confident fixture decision fails verification.

Only after that run succeeds, set `HOONARQUBE_JEV_TRIAGE_ENABLED=true` and
read it back. Removing the variable disables semantic triage while retaining
structural intake. No synthetic public issue is required. If no open issues
exist, report that an actual public issue write remains unobserved.

## Recovery

Failed requests do not publish semantic issue changes. Inspect the GitHub run
and `journalctl -u hoonarqube-jev-cube`; never dump credential or process
environments. Sandbox context cleanup deletes the VM; the 120-second lifetime
is the fallback if the broker dies. Restarting the service is safe after
in-flight requests have finished. Repoint `current` to the previous matching
release to roll back the broker. Keep the activation variable disabled during
a contract mismatch or rollback. Never retry an ambiguous GitHub write without
reading the issue and its ownership note first.
