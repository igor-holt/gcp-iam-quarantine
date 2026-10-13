"""Cloud Function entry point: alert dispatch and gated IAM quarantine.

Invoked by a Pub/Sub topic. Dispatches a Slack alert for every message and
executes automated IAM quarantine only when the alert type, the reporter, and
the allowlist all agree. See :mod:`policy` for the threat model.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

import functions_framework
from cloudevents.http import CloudEvent

import policy
from remediation import quarantine_service_account

QUARANTINE_ALERT_TYPE = "ACCESS_FREQUENCY_SPIKE"
WEBHOOK_TIMEOUT_SECONDS = 10


def _post_slack(webhook_url: str, payload: dict) -> None:
    """POST to the Slack webhook, surfacing HTTP failures distinctly.

    ``urlopen`` raises ``HTTPError`` for any 4xx/5xx, so the status has to be
    read from the exception rather than from the response object.
    """
    request = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=WEBHOOK_TIMEOUT_SECONDS) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            "Slack webhook rejected the alert with HTTP {}.".format(exc.code)
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            "Slack webhook was unreachable: {}".format(exc.reason)
        ) from exc

    if not 200 <= status < 300:
        raise RuntimeError("Slack webhook returned unexpected HTTP {}.".format(status))


@functions_framework.cloud_event
def dispatch_slack_alert(cloud_event: CloudEvent) -> None:
    """Handle one anomaly alert from Pub/Sub."""
    project_id = os.environ.get("GCP_PROJECT_ID", "")
    protected_sas = policy.parse_sa_csv(os.environ.get("PROTECTED_SERVICE_ACCOUNTS"))
    monitored_sas = policy.parse_sa_csv(os.environ.get("QUARANTINE_TARGET_SAS"))
    expected_source = os.environ.get("PUBSUB_EXPECTED_SOURCE", "")

    # Fail closed before doing anything destructive if the function is
    # misconfigured such that it could disable itself.
    policy.assert_dispatcher_not_monitored(
        os.environ.get("SERVICE_ACCOUNT_EMAIL", ""), monitored_sas, protected_sas
    )

    # Fail closed if remediation is marked required but allowlist is empty.
    require_remediation = (
        os.environ.get("REQUIRE_REMEDIATION", "").strip().lower()
        in ("true", "1", "yes")
    )
    policy.assert_remediation_configured(require_remediation, monitored_sas)

    # Reject replays of a message from any topic other than our own. Combined
    # with topic-level publisher IAM this narrows forgery to the scanner SA.
    source = cloud_event.get("source", "")
    if expected_source and source != expected_source:
        print("[WARN] Rejecting event from unexpected source: {!r}".format(source))
        return

    webhook_url = os.environ.get("ALERT_WEBHOOK_URL")
    if not webhook_url:
        raise RuntimeError("ALERT_WEBHOOK_URL secret is not bound.")

    record, poison_reason = policy.decode_pubsub_data(cloud_event.data)
    if record is None:
        # Acknowledge and drop. Raising here would redeliver a poison message
        # indefinitely under RETRY_POLICY_RETRY.
        print("[WARN] Dropping unusable Pub/Sub message: {}".format(poison_reason))
        return

    severity = record.get("severity", "HIGH")
    alert_type = record.get("alert_type", "UNKNOWN_ANOMALY")
    caller = record.get("caller_identity", "")
    count = record.get("event_count", 0)

    remediation_status = "NONE (alert type does not trigger auto-quarantine)"
    if alert_type == QUARANTINE_ALERT_TYPE:
        eligible, reason = policy.is_eligible_for_quarantine(
            caller, project_id, protected_sas, monitored_sas
        )
        if eligible:
            remediation_status = quarantine_service_account(project_id, caller)
        else:
            remediation_status = reason

    text = "\n".join(
        [
            ":rotating_light: *[{}] GCP Cryptographic Security Anomaly Detected*".format(
                policy.slack_escape(severity)
            ),
            "*Alert Type:* `{}`".format(policy.slack_escape(alert_type)),
            "*Service:* `{}`".format(policy.slack_escape(record.get("service_name", "unknown"))),
            "*Principal:* `{}` (`{}`)".format(
                policy.slack_escape(caller), policy.slack_escape(record.get("caller_ip", "unknown"))
            ),
            "*Method:* `{}`".format(policy.slack_escape(record.get("method_invoked", "unknown"))),
            "*Target Resource:* `{}`".format(policy.slack_escape(record.get("resource_target", "unknown"))),
            "*Event Count (15m Window):* `{}`".format(policy.slack_escape(count)),
            "*Detection Timestamp:* `{}`".format(policy.slack_escape(record.get("detection_time", "unknown"))),
            "*Automated Remediation:* *{}*".format(policy.slack_escape(remediation_status)),
            "*Context Details:* `{}`".format(policy.slack_escape(record.get("details", ""))),
        ]
    )

    _post_slack(webhook_url, {"text": text})

    print(
        "[OK] processed {} for {!r} | remediation: {}".format(
            policy.slack_escape(alert_type), caller, policy.slack_escape(remediation_status)
        )
    )
