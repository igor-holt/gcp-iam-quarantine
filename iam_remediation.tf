# ---------------------------------------------------------------------------
# Least-Privilege IAM Role: Automated Service Account Quarantine
# ---------------------------------------------------------------------------
#
# Operational caveat: editing `permissions` forces replacement of this role,
# which in turn re-creates `dispatcher_quarantine_binding` below. IAM
# propagation to the token service is asynchronous, so the first invocation
# after a permission change can fail with PERMISSION_DENIED. See the runbook.
resource "google_project_iam_custom_role" "sa_quarantine_operator" {
  project     = var.project_id
  role_id     = "securityAnomalyQuarantineOperator"
  title       = "Security Anomaly Quarantine Operator"
  description = "Least-privilege role allowing automated disabling of compromised service accounts and user-managed keys."

  permissions = [
    "iam.serviceAccounts.get",
    "iam.serviceAccounts.disable",
    "iam.serviceAccountKeys.list",
    "iam.serviceAccountKeys.disable",
  ]
}

resource "google_project_iam_member" "dispatcher_quarantine_binding" {
  project = var.project_id
  role    = google_project_iam_custom_role.sa_quarantine_operator.id
  member  = "serviceAccount:${google_service_account.alert_dispatcher_sa.email}"
}

locals {
  # Core control-plane service accounts that must never be self-disabled
  core_protected_sas = [
    google_service_account.job_runner.email,
    google_service_account.scheduler_invoker.email,
    google_service_account.bq_query_runner.email,
    google_service_account.alert_dispatcher_sa.email,
  ]

  protected_sa_csv = join(",", distinct(concat(
    local.core_protected_sas,
    var.additional_protected_service_accounts,
  )))

  quarantine_target_sa_csv = join(",", distinct([
    for sa in var.quarantine_target_service_accounts : lower(sa)
  ]))
}