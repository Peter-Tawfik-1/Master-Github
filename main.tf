resource "google_storage_bucket" "peter-bucket-1" {
  name                     = "peter-bucket-tf-1"
  project                  = "peter-test-2024"
  location                 = "US"
  force_destroy            = false
  public_access_prevention = "enforced"
}
