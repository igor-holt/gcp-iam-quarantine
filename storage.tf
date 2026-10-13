resource "google_storage_bucket" "function_source_bucket" {
  project  = var.project_id
  name     = "${var.project_id}-sa-quarantine-src"
  location = var.region

  uniform_bucket_level_access = true
  force_destroy               = false

  versioning {
    enabled = false
  }
}

# Packages src/ into the zip layout Cloud Functions gen2 expects. Deploying
# from a bucket avoids requiring Cloud Build inside the module.
data "archive_file" "dispatcher_source" {
  type        = "zip"
  source_dir  = "${path.module}/src"
  output_path = "${path.module}/.terraform-build/dispatcher.zip"
}

resource "google_storage_bucket_object" "dispatcher_archive" {
  # Project is inherited from the provider; this resource does not accept it.
  bucket = google_storage_bucket.function_source_bucket.name
  # Content-addressed name so a code change yields a new object, which is
  # what makes Cloud Functions pick up a new revision.
  name           = "dispatcher-${data.archive_file.dispatcher_source.output_base64sha256}.zip"
  source         = data.archive_file.dispatcher_source.output_path
  source_md5hash = filemd5(data.archive_file.dispatcher_source.output_path)
}