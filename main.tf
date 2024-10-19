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
  name         = "database-instance"
  machine_type = "e2-standard-4"
  project      = "peter-test-2024"
  zone         = "europe-west2-a"

  boot_disk {
    initialize_params {
      image = "rhel-9-v20241009"
      labels = {
        my_label = "database-instance"
      }
    }
  }

  network_interface {
    network = "default"
    access_config {}
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    echo "Hello, World!" > /var/www/html/index.html
    sudo yum update -y
    sudo yum install -y httpd
    sudo systemctl start httpd
  EOF
}

resource "google_dns_managed_zone" "my_zone" {
  name     = "test"
  dns_name = "petertawfik.joonix.net." # Replace with your domain
}

resource "google_dns_record_set" "my_record" {
  managed_zone = google_dns_managed_zone.my_zone.name
  name         = "test1.petertawfik.joonix.net" # Change as needed
  type         = "A"
  ttl          = 300

  rrdatas = [google_compute_instance.default.network_interface[0].access_config[0].nat_ip]

}