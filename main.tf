/*
# Create a bucket
resource "google_storage_bucket" "peter-bucket-1" {
  name                     = "peter-bucket-tf-1"
  project                  = "peter-test-2024"
  location                 = "US"
  force_destroy            = false
  public_access_prevention = "enforced"
}
*/

# Create an instance to deploy database on it to simulate deployment

resource "google_compute_instance" "default" {
  name         = "Database instance"
  machine_type = "e2-standard-4"
  project      = "peter-test-2024"
  zone         = "europe-west2-a"

  boot_disk {
    initialize_params {
      image = "rhel-9-v20241009"
    }
  }

  network_interface {
    network = "default"
    access_config {}
  }
}