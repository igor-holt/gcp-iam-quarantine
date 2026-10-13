# GCP IAM Auto-Quarantine

Automated containment for Google Cloud service accounts: on a
`ACCESS_FREQUENCY_SPIKE` anomaly alert, a Pub/Sub-triggered Cloud Function
revokes every user-managed key on the offending service account, disables the
account, and posts a summary to Slack.

`projects.serviceAccounts.disable` takes effect immediately. Outstanding OAuth2
access tokens are rejected and further token minting or refresh is blocked
across all Google APIs. Disabling the keys as well means external JSON key
files stop working if the account is re-enabled during forensic investigation.

## Threat model

**The Pub/Sub payload is untrusted input.** `caller_identity` is a string that
any principal holding publish rights on the alert topic chooses freely. Acting
on it directly turns this function into a project-wide denial-of-service
primitive: a single forged message disables an arbitrary service account.

Two independent controls bound what that string can do:

| Control | Where | What it stops |
|---|---|---|
| Authoritative topic IAM binding | `pubsub_slack_dispatch.tf` | Revokes `roles/pubsub.publisher` on the topic for every principal except the anomaly scanner |
| `QUARANTINE_TARGET_SAS` allowlist | `src/policy.py` | Remediation only ever touches an account already nominated for monitoring |
| `PROTECTED_SERVICE_ACCOUNTS` | `src/policy.py` | Control-plane accounts, including the dispatcher itself |
| CloudEvent `source` check | `src/main.py` | Rejects replays from any topic other than our own |

The allowlist is what makes the function safe **even if the topic IAM is
misconfigured**, so the two controls are treated as redundant rather than
belt-and-braces. An empty allowlist is a valid alert-only configuration.

### Why the custom role is tight

`securityAnomalyQuarantineOperator` grants exactly four permissions and
deliberately omits `iam.serviceAccounts.enable`. Recovery is a manual,
human decision — see the runbook below. The module never grants itself the
ability to undo its own actions.

## Deploy

```bash
cp terraform.tfvars.example terraform.tfvars   # then edit
terraform init
terraform plan
terraform apply
```

Then add the Slack webhook **out of band**, so it never lands in Terraform
state:

```bash
gcloud secrets versions add alert-webhook-url \
  --project=<project-id> --data-file=- <<< 'https://hooks.slack.com/...'
```

The function binds `version = "latest"`, so it picks the value up on the next
cold start with no redeploy.

> Use a dedicated security project. Do not apply this into a project running
> production services: the apply binds a role with `iam.serviceAccounts.disable`
> into that project.

### Pre-apply check for over-broad publisher grants

The topic IAM binding is authoritative and will revoke publisher access on the
topic. Check what a project-level grant would be overridden by:

```bash
gcloud projects get-iam-policy <project-id> \
  --flatten="bindings[].members[roles/pubsub.publisher]" \
  --format="value(bindings.members)"
```

## Runbook

**Quarantine.** The Slack alert states the outcome. `PARTIAL` means keys were
revoked but the account is still enabled — an unusual state that warrants
manual follow-up rather than assuming containment.

**Restore** after an incident is audited and cleared:

```bash
gcloud iam service-accounts enable <SA>@<project-id>.iam.gserviceaccount.com
```

**Known operational caveats.**

- Editing the `permissions` list forces replacement of the custom role, which
  re-creates the dispatcher's binding. IAM propagation to the token service is
  asynchronous, so the first invocation after a permission change can fail with
  `PERMISSION_DENIED`.
- `RETRY_POLICY_RETRY` is set. The function acknowledges and drops malformed
  messages rather than raising, so a poison message cannot wedge the
  subscription — but it also means genuinely transient Slack failures retry the
  whole remediation path.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest tests/ -q
```

`src/policy.py` is stdlib-only by design, so the entire security decision
surface is unit-testable with nothing installed.

## Scope

This module builds the alerting and containment function. It does **not** build
the anomaly detector that publishes to the topic — that is a separate
component and is the principal you want to keep least-privileged.