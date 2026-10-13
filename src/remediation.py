"""IAM remediation actions.

Kept separate from :mod:`policy` so the decision logic stays free of cloud
SDK imports. Each remediation step is attempted independently and its
outcome is reported separately: a partial failure leaves the account
enabled with its keys revoked, which is a materially different forensic
state from a clean success and should not be reported as one.
"""

from __future__ import annotations


def quarantine_service_account(project_id: str, sa_email: str) -> str:
    """Revoke all user-managed keys, then disable the service account.

    ``projects.serviceAccounts.disable`` takes effect immediately: it rejects
    outstanding OAuth2 access tokens and blocks minting and refresh for every
    Google API. Disabling the keys additionally means external JSON key files
    stop working if the account is re-enabled during forensic investigation.
    """
    from google.cloud import iam_admin_v1
    from google.cloud.iam_admin_v1 import types

    client = iam_admin_v1.IAMClient()
    sa_resource_name = "projects/{}/serviceAccounts/{}".format(project_id, sa_email)

    steps: list[str] = []
    revoked = 0

    # Step 1: revoke every active user-managed key.
    try:
        list_request = types.ListServiceAccountKeysRequest(
            name=sa_resource_name,
            key_types=[types.ListServiceAccountKeysRequest.KeyType.USER_MANAGED],
        )
        for key in client.list_service_account_keys(request=list_request).keys:
            if not key.disabled:
                client.disable_service_account_key(
                    request=types.DisableServiceAccountKeyRequest(name=key.name)
                )
                revoked += 1
        steps.append("{} user-managed key(s) revoked".format(revoked))
    except Exception as exc:  # noqa: BLE001 - report and still try the strong control
        steps.append("KEY REVOCATION ERROR {}: {}".format(type(exc).__name__, exc))

    # Step 2: disable the account. This is the authoritative control and is
    # attempted even if key enumeration failed.
    try:
        client.disable_service_account(
            request=types.DisableServiceAccountRequest(name=sa_resource_name)
        )
        steps.append("account disabled")
        status = "QUARANTINED"
    except Exception as exc:  # noqa: BLE001 - surfaced to the operator verbatim
        steps.append("ACCOUNT DISABLE ERROR {}: {}".format(type(exc).__name__, exc))
        status = "PARTIAL" if revoked else "FAILED"

    return "{} ({})".format(status, "; ".join(steps))