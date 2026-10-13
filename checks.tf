# ---------------------------------------------------------------------------
# Cross-variable safety checks
# ---------------------------------------------------------------------------
#
# Terraform 1.5 forbids one variable's `validation` block from referencing
# another variable, so the protected/quarantine-target overlap check lives
# here as a precondition on `terraform_data`.
#
# `terraform_data` is a built-in resource type (Terraform 1.4+), so this
# needs no external provider. The precondition hard-fails `terraform plan`,
# unlike a `check` block which only emits a warning.
resource "terraform_data" "sa_set_safety" {
  input = local.quarantine_target_sa_csv

  lifecycle {
    precondition {
      condition = length(setintersection(
        toset([for sa in var.quarantine_target_service_accounts : lower(sa)]),
        toset([for sa in var.additional_protected_service_accounts : lower(sa)]),
      )) == 0

      error_message = "A service account cannot be both protected and a quarantine target. Protected wins at runtime, so the target entry would be a silent no-op."
    }

    precondition {
      condition = !contains(
        toset([for sa in var.quarantine_target_service_accounts : lower(sa)]),
        lower(google_service_account.alert_dispatcher_sa.email),
      )

      error_message = "The dispatcher service account cannot be its own quarantine target."
    }

    precondition {
      condition = length(distinct(var.quarantine_target_service_accounts)) == length(var.quarantine_target_service_accounts)

      error_message = "quarantine_target_service_accounts contains duplicate entries."
    }
  }
}