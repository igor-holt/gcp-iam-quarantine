# The secret CONTAINER is managed here; the secret VERSION is deliberately not.
# Passing the Slack webhook through a Terraform variable would persist it in
# plaintext in state and in any state backup.
#
# After the first apply, add the version out of band:
#
#   gcloud secrets versions add alert-webhook-url \
#     --project=<project-id> --data-file=-
#
# The function binds version = "latest", so it picks the value up on next
# cold start without a redeploy.
resource "google_secret_manager_secret" "alert_webhook_url" {
  project   = var.project_id
  secret_id = var.alert_webhook_secret_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}

# Only the dispatcher runtime identity may read the webhook.
resource "google_secret_manager_secret_iam_member" "dispatcher_webhook_accessor" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.alert_webhook_url.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.alert_dispatcher_sa.email}"
}