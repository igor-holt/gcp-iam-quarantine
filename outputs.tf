output "quarantine_custom_role_id" {
  description = "Custom IAM role ID assigned to the remediation function."
  value       = google_project_iam_custom_role.sa_quarantine_operator.id
}

output "protected_service_accounts" {
  description = "Service accounts protected from automated quarantine."
  value       = local.protected_sa_csv
}

output "quarantine_target_service_accounts" {
  description = "Service accounts eligible for automated quarantine. Empty means alert-only mode."
  value       = local.quarantine_target_sa_csv
}

output "alert_topic_name" {
  description = "Pub/Sub topic the dispatcher is triggered by."
  value       = google_pubsub_topic.security_alerts.name
}

output "dispatcher_service_account" {
  description = "Runtime identity of the dispatcher."
  value       = google_service_account.alert_dispatcher_sa.email
}

output "secret_add_version_command" {
  description = "Run this after the first apply to populate the Slack webhook secret."
  value       = "gcloud secrets versions add ${var.alert_webhook_secret_id} --project=${var.project_id} --data-file=-"
}