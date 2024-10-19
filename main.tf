resource "google_storage_bucket" "peter-bucket-1" {
  name          = "peter-bucket-tf-1"
  project       = "peter-gcp"
  location      = "US"
  force_destroy = false
  public_access_prevention = "enforced"
}
