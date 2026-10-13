resource "google_pubsub_topic" "security_alerts" {
  project = var.project_id
  name    = var.alert_topic_name

  message_storage_policy {
    allowed_persistence_regions = [var.region]
  }

  depends_on = [google_project_service.required]
}

# ---------------------------------------------------------------------------
# Publisher restriction — this is the primary control against alert forgery.
# ---------------------------------------------------------------------------
#
# `_binding` (authoritative) is deliberate, NOT `_member` (additive). An
# additive member would leave any project-level roles/pubsub.publisher grant
# in place, which is exactly the condition that let a forged alert reach the
# remediation path. The authoritative binding revokes publisher on this topic
# for every principal except the anomaly scanner.
#
# Check for pre-existing project-level grants before applying:
#   gcloud projects get-iam-policy <project-id> \
#     --flatten="bindings[].members[roles/pubsub.publisher]" \
#     --format="value(bindings.members)"
resource "google_pubsub_topic_iam_binding" "anomaly_scanner_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.security_alerts.name
  role    = "roles/pubsub.publisher"

  members = [
    "serviceAccount:${google_service_account.bq_query_runner.email}",
  ]
}

resource "google_cloudfunctions2_function" "slack_alert_dispatcher" {
  project     = var.project_id
  name        = "security-anomaly-slack-dispatcher"
  location    = var.region
  description = "Quarantines compromised service accounts on ACCESS_FREQUENCY_SPIKE and dispatches Slack alerts."

  build_config {
    runtime     = "python311"
    entry_point = "dispatch_slack_alert"

    source {
      storage_source {
        bucket = google_storage_bucket.function_source_bucket.name
        object = google_storage_bucket_object.dispatcher_archive.name
      }
    }
  }

  service_config {
    max_instance_count    = 10
    min_instance_count    = 0
    available_memory      = "256M"
    timeout_seconds       = 60
    service_account_email = google_service_account.alert_dispatcher_sa.email
    ingress_settings      = "ALLOW_INTERNAL_ONLY"

    environment_variables = {
      GCP_PROJECT_ID             = var.project_id
      PROTECTED_SERVICE_ACCOUNTS = local.protected_sa_csv
      QUARANTINE_TARGET_SAS      = local.quarantine_target_sa_csv
      PUBSUB_EXPECTED_SOURCE     = "//pubsub.googleapis.com/projects/${var.project_id}/topics/${google_pubsub_topic.security_alerts.name}"
    }

    secret_environment_variables {
      key        = "ALERT_WEBHOOK_URL"
      project_id = var.project_id
      secret     = google_secret_manager_secret.alert_webhook_url.secret_id
      version    = "latest"
    }
  }

  event_trigger {
    trigger_region        = var.region
    event_type            = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic          = google_pubsub_topic.security_alerts.id
    retry_policy          = "RETRY_POLICY_RETRY"
    service_account_email = google_service_account.alert_dispatcher_sa.email
  }

  depends_on = [
    google_project_service.required,
    google_secret_manager_secret_iam_member.dispatcher_webhook_accessor,
    google_project_iam_member.dispatcher_quarantine_binding,
    google_pubsub_topic_iam_binding.anomaly_scanner_publisher,
    terraform_data.sa_set_safety,
  ]
}