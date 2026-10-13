variable "project_id" {
  type        = string
  description = "Target GCP project. Use a dedicated security project, never a production services project."
}

variable "region" {
  type        = string
  description = "Region for the Cloud Function and its trigger."
  default     = "us-central1"
}

variable "additional_protected_service_accounts" {
  type        = list(string)
  description = "Additional service account emails exempt from automated quarantine."
  default     = []

  validation {
    condition = length(var.additional_protected_service_accounts) == 0 || alltrue([
      for sa in var.additional_protected_service_accounts :
      can(regex("^[a-z0-9-]{6,30}@[a-z0-9-]+\\.iam\\.gserviceaccount\\.com$", sa))
    ])
    error_message = "Each entry must be a bare lowercase service account email like 'my-sa@my-project.iam.gserviceaccount.com'. A malformed entry would silently fail to protect an account."
  }
}

variable "quarantine_target_service_accounts" {
  type        = list(string)
  description = <<-EOT
    Service accounts eligible for automated quarantine. This is the blast-radius
    control: remediation only ever touches an account in this list, so a forged
    alert cannot disable an arbitrary principal. Leave empty for alert-only mode.
  EOT
  default     = []

  validation {
    condition = length(var.quarantine_target_service_accounts) == 0 || alltrue([
      for sa in var.quarantine_target_service_accounts :
      can(regex("^[a-z0-9-]{6,30}@[a-z0-9-]+\\.iam\\.gserviceaccount\\.com$", sa))
    ])
    error_message = "Each entry must be a bare lowercase service account email. An invalid entry silently narrows or widens the remediation scope."
  }
}

# The protected/quarantine-target overlap check cannot live in a `validation`
# block here: Terraform 1.5 forbids referencing another variable from inside
# one. It is a precondition in checks.tf instead.

variable "alert_topic_name" {
  type        = string
  description = "Name of the Pub/Sub topic carrying anomaly alerts."
  default     = "security-anomaly-alerts"
}

variable "alert_webhook_secret_id" {
  type        = string
  description = "Secret Manager secret ID holding the Slack webhook URL. The secret version is added out of band so the webhook never enters Terraform state."
  default     = "alert-webhook-url"
}