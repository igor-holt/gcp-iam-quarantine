# Security Policy

## Reporting a vulnerability

Do not open a public issue for anything that could let an attacker disable a
service account or reach the remediation path. Report privately to the
maintainer instead.

## What this project deliberately does not do

- **No automated re-enable.** `iam.serviceAccounts.enable` is intentionally
  absent from the custom role. Containment is not self-reversing; a human
  decides.
- **No quarantine of Google-managed agents.** Service agents such as
  `@gcp-sa-*.iam.gserviceaccount.com` are rejected by domain validation.
  Disabling one can break unrelated Google-managed workloads.
- **No trust in alert payloads.** Every value used to make a destructive
  decision originates from an untrusted message. See the threat model in
  `README.md`.