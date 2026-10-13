# Control-plane service accounts. These four are referenced by the anomaly
# scanner pipeline and by the dispatcher itself.
resource "google_service_account" "job_runner" {
  project      = var.project_id
  account_id   = "job-runner"
  display_name = "Job Runner"
  description  = "Executes scheduled jobs. Protected from automated quarantine."
}

resource "google_service_account" "scheduler_invoker" {
  project      = var.project_id
  account_id   = "scheduler-invoker"
  display_name = "Scheduler Invoker"
  description  = "Triggers scheduled workloads. Protected from automated quarantine."
}

resource "google_service_account" "bq_query_runner" {
  project      = var.project_id
  account_id   = "bq-query-runner"
  display_name = "BigQuery Anomaly Scanner"
  description  = "Detects cryptographic access anomalies and publishes alerts."
}

resource "google_service_account" "alert_dispatcher_sa" {
  project      = var.project_id
  account_id   = "alert-dispatcher"
  display_name = "Security Alert Dispatcher"
  description  = "Runs the quarantine dispatcher. Protected from automated quarantine."
}