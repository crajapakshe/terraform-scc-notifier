# Google Cloud Security Command Center Enabling real-time email and chat notifications
# https://cloud.google.com/security-command-center/docs/how-to-enable-real-time-notifications#overview

# Pubsub Subscription 
resource "google_pubsub_topic" "scc_critical_and_high_severity_findings_topic" {
  project = var.project_id
  name    = "scc-critical-and-high-severity-findings-topic"
}

resource "google_pubsub_subscription" "scc_critical_and_high_severity_findings_sub" {
  project = var.project_id
  name    = "scc-critical-and-high-severity-findings-sub"
  topic   = google_pubsub_topic.scc_critical_and_high_severity_findings_topic.name
  
  message_retention_duration = "1200s"
  retain_acked_messages      = true

  ack_deadline_seconds = 20

  expiration_policy {
    ttl = "" // never expires
  }
  retry_policy {
    minimum_backoff = "10s"
  }

  enable_message_ordering    = false
}

# Security Center Notifications Configurations
resource "google_scc_notification_config" "scc_critical_and_high_severity_findings_notify" {
  config_id    = "scc-critical-and-high-severity-findings-notify"
  organization = var.org_id
  description  = "Cloud Security Command Center Critical and High Severity Finding Notification Configuration"
  pubsub_topic = google_pubsub_topic.scc_critical_and_high_severity_findings_topic.id

  streaming_config {
    filter = "(severity=\"HIGH\" OR severity=\"CRITICAL\") AND -category=\"OS_VULNERABILITY\" AND state=\"ACTIVE\""
    }
}

# Create Storage bucket
resource "google_storage_bucket" "slack_function_bucket" {
  name                        = "${var.project_id}-slack-function"
  location                    = var.region
  project                     = var.project_id
  requester_pays              = "false"
  storage_class               = "STANDARD"
  uniform_bucket_level_access = "true"
  default_event_based_hold    = "false"
  force_destroy               = "false"
}

# Generates an archive of the source code compressed as a .zip file.
data "archive_file" "scc_slack_cloud_function" {
  type        = "zip"
  source_dir  = "src/scc-slack-cloud-function"
  output_path = "/tmp/function.zip"
}

# Add source code zip to the Cloud Function's bucket
resource "google_storage_bucket_object" "scc_slack_cloud_function_src_zip" {
  source       = data.archive_file.scc_slack_cloud_function.output_path
  content_type = "application/zip"

  # Append to the MD5 checksum of the files's content
  # to force the zip to be updated as soon as a change occurs
  name         = "src-${data.archive_file.scc_slack_cloud_function.output_md5}.zip"
  bucket       = google_storage_bucket.slack_function_bucket.name

  depends_on   = [
    google_storage_bucket.slack_function_bucket,  
    data.archive_file.scc_slack_cloud_function
  ]
}

# Service account for Cloud Function
resource "google_service_account" "scc_finding_slack_notifier_service_account" {
  account_id   = "scc-finding-slack-notifier"
  display_name = "Service Account used for Slack Finding Notifier Function"
}

# Pull Slack token from secret server
data "google_secret_manager_secret_version" "scc_finding_notifier_slack_token" {
  secret    = "scc-finding-notifier-slack-token"
  project   = var.project_id
}

# Create the Cloud function triggered by a pubsub events
resource "google_cloudfunctions_function" "scc_finding_slack_notifier" {
  name                  = "scc-finding-slack-notifier"
  description           = "Cloud Security Command Center Critical and High Severity Finding Notifier Function"
  project               = var.project_id
  region                = var.region

  runtime               = "python39"
  available_memory_mb   = 256
  timeout               = 60
  ingress_settings      = "ALLOW_INTERNAL_ONLY"

  # Get the source code of the cloud function as a Zip compression
  source_archive_bucket = google_storage_bucket.slack_function_bucket.name
  source_archive_object = google_storage_bucket_object.scc_slack_cloud_function_src_zip.name

  # Must match the function name in the cloud function `main.py` in `src/scc-slack-cloud-function/`
  entry_point           = "scc_finding_slack_notifier"
  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.scc_critical_and_high_severity_findings_topic.name
  }

  # Pull Slack token from Secret Manager
  environment_variables = {
    SLACK_CHANNEL = "#scc-monitoring"
    SECRET_PROJECT_ID = "${data.google_secret_manager_secret_version.scc_finding_notifier_slack_token.project}"
    SECRET_ID = "${data.google_secret_manager_secret_version.scc_finding_notifier_slack_token.secret}"
  }
  
  service_account_email = google_service_account.scc_finding_slack_notifier_service_account.email

  depends_on  = [
    google_service_account.scc_finding_slack_notifier_service_account,
    google_storage_bucket.slack_function_bucket,
    google_storage_bucket_object.scc_slack_cloud_function_src_zip,
  ]
}