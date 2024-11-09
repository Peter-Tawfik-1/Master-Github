/*
# Create a bucket
resource "google_storage_bucket" "peter-bucket-1" {
  name                     = "peter-bucket-oracle-source"
  project                  = "peter-test-2024"
  location                 = "US"
  force_destroy            = false
  public_access_prevention = "enforced"
}
*/

# Create an instance to deploy database on it to simulate deployment
provider "google" {
  project = "peter-test-2024" # GCP project ID
  region  = "europe-west2"    # europe-west2 region
}

resource "google_compute_instance" "default" {
  name         = "database-instance"
  machine_type = "e2-standard-4"
  zone         = "europe-west2-a"

  boot_disk {
    initialize_params {
      image = "rhel-9-v20241009"
      labels = {
        my_label = "database-instance-test"
      }
    }
  }

  network_interface {
    network    = "default"
    network_ip = "10.154.0.4"
    access_config {
      nat_ip = "34.147.166.38"
    }
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    Sudo echo hi > /tmp/test.txt
    echo peter >> /tmp/test.txt
    EOF
}


/* DEBUG section will be added 
  metadata_startup_script = <<-EOF
    #!/bin/bash

    FLAG_FILE="/tmp/first_boot_complete"

    if [ ! -f "$FLAG_FILE" ]; then
      # Redirect both stdout and stderr to the log file
      exec > /tmp/install_log.txt 2>&1 

      #sudo yum update -y #save time for first run
      sudo yum install wget -y
      sudo mkdir sw
      sudo mkdir log
      chmod 777 sw
      chmod 777 log
      cd sw
      wget https://yum.oracle.com/repo/OracleLinux/OL9/appstream/x86_64/getPackage/oracle-database-preinstall-23ai-1.0-2.el9.x86_64.rpm
      wget https://download.oracle.com/otn-pub/otn_software/db-free/oracle-database-free-23ai-1.0-1.el9.x86_64.rpm
      sudo dnf -y install oracle-database-preinstall-23ai-1.0-2.el9.x86_64.rpm > /home/peter/log/install_log.txt
      sudo dnf install -y oracle-database-free* >> /home/peter/log/install_log.txt
      #export DB_PASSWORD=sys
      (echo sys; echo sys;) | sudo /etc/init.d/oracle-free-23ai configure >> /home/peter/log/config_log.txt
      # Create the flag file
      touch "$FLAG_FILE"
    fi 
  EOF
}

/*
resource "google_dns_managed_zone" "my_zone" {
  name     = "test"
  dns_name = "petertawfik.joonix.net."
}

resource "google_dns_record_set" "my_record" {
  managed_zone = google_dns_managed_zone.my_zone.name
  name         = "test1.petertawfik.joonix.net."
  type         = "A"
  ttl          = 300

  rrdatas = [google_compute_instance.default.network_interface[0].access_config[0].nat_ip]

}
*/