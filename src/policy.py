"""Pure remediation policy decisions.

This module deliberately has no third-party imports so that every security
decision in the dispatcher can be unit tested with nothing installed.

Threat model
------------
The Pub/Sub payload is untrusted input. `caller_identity` is a string that
anybody holding publish rights on the alert topic can choose. Two
independent controls bound what that string can cause:

1. Topic-level IAM in Terraform restricts ``roles/pubsub.publisher`` to the
   anomaly scanner. See ``pubsub_slack_dispatch.tf``.
2. The allowlist here. Remediation only ever applies to an account in
   ``QUARANTINE_TARGET_SAS``. A forged ``caller_identity`` cannot widen that
   scope; it can only name an account already nominated for monitoring.

Control 2 is what makes the function safe even if control 1 is misconfigured,
and it is why an empty allowlist means "alert only, never remediate".
"""

from __future__ import annotations

SA_DOMAIN_SUFFIX = ".iam.gserviceaccount.com"


def parse_sa_csv(raw: str | None) -> set[str]:
    """Parse a comma-separated SA list into a normalised, lowercase set.

    Email addresses are compared case-insensitively so that a capitalised
    entry in a config file cannot silently fail to protect an account.
    """
    if not raw:
        return set()
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def is_protected_service_account(caller: str, protected_sas: set[str]) -> bool:
    """Return True if the caller is on the do-not-touch list."""
    return caller.strip().lower() in protected_sas


def is_customer_managed(caller: str, project_id: str) -> bool:
    """Return True if the caller is a customer-managed SA in this project.

    Rejects external principals and Google-managed service agents such as
    ``@gcp-sa-*.iam.gserviceaccount.com`` and ``@cloudservices...``, which
    must never be auto-disabled.
    """
    expected_domain = f"@{project_id}{SA_DOMAIN_SUFFIX}"
    return caller.strip().lower().endswith(expected_domain)


def _is_email_shaped(value: str) -> bool:
    """Structural check: exactly one @, non-empty local part, dotted domain."""
    if value.count("@") != 1:
        return False
    local, _, domain = value.partition("@")
    return (
        bool(local)
        and "." in domain
        and not domain.startswith(".")
        and not domain.endswith(".")
    )


def is_eligible_for_quarantine(
    caller: str,
    project_id: str,
    protected_sas: set[str],
    monitored_sas: set[str],
) -> tuple[bool, str]:
    """Decide whether a reported principal may be automatically suspended.

    Checks run in order of blast radius: cheapest and most absolute first,
    so that a protected account is never even domain-parsed.
    """
    if not caller or not _is_email_shaped(caller.strip()):
        return False, "SKIPPED (not a valid email principal)"

    normalised = caller.strip().lower()

    if normalised in protected_sas:
        return False, "BYPASSED (protected control-plane Service Account)"

    if not is_customer_managed(normalised, project_id):
        return False, "SKIPPED (external user or Google-managed service agent)"

    if normalised not in monitored_sas:
        return False, "SKIPPED (principal not in QUARANTINE_TARGET_SAS allowlist)"

    return True, "ELIGIBLE"


def assert_dispatcher_not_monitored(
    own_email: str, monitored_sas: set[str], protected_sas: set[str]
) -> None:
    """Fail closed if this function could quarantine itself.

    Guards the recursive self-lockout case where a config error places the
    dispatcher's own service account on the remediation allowlist. An empty
    allowlist is a legitimate alert-only configuration and is a no-op here.
    """
    if not own_email:
        return

    normalised = own_email.strip().lower()

    if normalised in monitored_sas:
        raise RuntimeError(
            "Refusing to start: this dispatcher ({}) is present in "
            "QUARANTINE_TARGET_SAS. Remove it or move it to the protected "
            "list, otherwise it can disable itself mid-incident.".format(normalised)
        )

    if normalised not in protected_sas:
        raise RuntimeError(
            "Refusing to start: this dispatcher ({}) is missing from "
            "PROTECTED_SERVICE_ACCOUNTS. The env var likely failed to bind; "
            "self-protection would silently fail open.".format(normalised)
        )


def decode_pubsub_data(cloud_event_data: object) -> tuple[dict | None, str]:
    """Decode a Pub/Sub CloudEvent payload into a dict.

    Returns ``(record, "")`` on success or ``(None, reason)`` when the
    message is unusable. Callers must treat a reason as "ack and drop" and
    return normally: under ``RETRY_POLICY_RETRY`` an uncaught exception
    redelivers a poison message forever and wedges the subscription.
    """
    import base64
    import json

    if not isinstance(cloud_event_data, dict):
        return None, "event data is not a mapping"

    message = cloud_event_data.get("message")
    if not isinstance(message, dict):
        return None, "event data has no 'message' mapping"

    raw = message.get("data")
    if not raw:
        return None, "message has no data field"

    try:
        decoded = base64.b64decode(raw, validate=True).decode("utf-8")
    except Exception as exc:  # noqa: BLE001 - any decode failure is poison
        return None, "data field is not valid base64 UTF-8 ({})".format(
            type(exc).__name__
        )

    try:
        record = json.loads(decoded)
    except Exception as exc:  # noqa: BLE001 - malformed JSON is poison
        return None, "decoded payload is not valid JSON ({})".format(
            type(exc).__name__
        )

    if not isinstance(record, dict):
        return None, "decoded payload is a {}, expected object".format(
            type(record).__name__
        )

    return record, ""


def slack_escape(value: object) -> str:
    """Escape Slack control characters in attacker-influenceable text.

    Alert fields come from an untrusted payload; unescaped ``<`` can be used
    to inject Slack link markup into a channel that trusts these alerts.
    """
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("`", "'")
    )