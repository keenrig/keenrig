# Keenrig — 1-click marketplace images for Vultr and DigitalOcean.
#
#   cd keenrig-node-installer/marketplace
#   packer init .
#   VULTR_API_KEY=... DIGITALOCEAN_TOKEN=... packer build -var version=0.4.0 .
#   packer build -only='vultr.keenrig' -var version=0.4.0 .        # one vendor
#
# Each build: fresh Ubuntu 24.04 → get.sh from the release channel → firstboot
# script → cleanup.sh → (DO) DigitalOcean's own cleanup + img_check → snapshot.
# Rebuild on every major release so new machines do not start far behind
# (they auto-upgrade anyway, every 5 minutes).

packer {
  required_plugins {
    digitalocean = {
      version = ">= 1.4.0"
      source  = "github.com/digitalocean/digitalocean"
    }
    vultr = {
      version = ">= 2.5.0"
      source  = "github.com/vultr/vultr"
    }
  }
}

variable "version" {
  type        = string
  description = "Keenrig release the image carries; only used in the snapshot name."
}

variable "channel" {
  type    = string
  default = "stable"
}

variable "do_token" {
  type      = string
  default   = env("DIGITALOCEAN_TOKEN")
  sensitive = true
}

variable "vultr_api_key" {
  type      = string
  default   = env("VULTR_API_KEY")
  sensitive = true
}

locals {
  name = "keenrig-${var.version}-${formatdate("YYYYMMDD-hhmm", timestamp())}"
}

source "digitalocean" "keenrig" {
  api_token     = var.do_token
  image         = "ubuntu-24-04-x64"
  region        = "nyc3"
  size          = "s-1vcpu-2gb"
  ssh_username  = "root"
  snapshot_name = local.name
}

source "vultr" "keenrig" {
  api_key              = var.vultr_api_key
  os_id                = 2284 # Ubuntu 24.04 LTS x64 — check with `vultr-cli os list`
  plan_id              = "marketplace-2c-2gb" # Vultr's recommended plan for marketplace builds
  region_id            = "ewr"
  snapshot_description = local.name
  ssh_username         = "root"
  state_timeout        = "25m"
}

build {
  sources = ["source.digitalocean.keenrig", "source.vultr.keenrig"]

  # The provider's own cloud-init must finish before apt runs, or apt is locked.
  provisioner "shell" {
    inline = [
      "cloud-init status --wait >/dev/null 2>&1 || true",
      "export DEBIAN_FRONTEND=noninteractive",
      "apt-get -qq update",
      # DO's img_check fails an image with pending security updates.
      "apt-get -qq -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade",
    ]
  }

  provisioner "shell" {
    inline = ["curl -fsSL https://get.keenrig.com | sh -s -- --channel ${var.channel} --auto-upgrade"]
  }

  provisioner "file" {
    source      = "${path.root}/../scripts/firstboot.sh"
    destination = "/tmp/keenrig-firstboot.sh"
  }

  provisioner "file" {
    source      = "${path.root}/cleanup.sh"
    destination = "/tmp/keenrig-cleanup.sh"
  }

  # ONE provisioner, and the last: cleanup.sh deletes root's authorized_keys, so
  # any provisioner after it could not reconnect.
  #
  # On DigitalOcean their own cleanup + validation must pass before review
  # (github.com/digitalocean/marketplace-partners); img_check must print no FAIL.
  # Fetched BEFORE cleanup.sh, which empties /tmp and removes the keys.
  provisioner "shell" {
    inline = [
      "set -e",
      "mkdir -p /etc/keenrig /var/lib/cloud/scripts/per-instance /root/do-mp",
      # source.type = digitalocean | vultr → the `src` of the first-boot ping.
      "echo ${source.type} > /etc/keenrig/install-source",
      "install -m 0755 -o root -g root /tmp/keenrig-firstboot.sh /var/lib/cloud/scripts/per-instance/keenrig-firstboot.sh",
      "if [ '${source.type}' = digitalocean ]; then for s in 90-cleanup.sh 99-img_check.sh; do curl -fsSL https://raw.githubusercontent.com/digitalocean/marketplace-partners/master/scripts/$s -o /root/do-mp/$s; done; fi",
      "sh /tmp/keenrig-cleanup.sh",
      "if [ '${source.type}' = digitalocean ]; then bash /root/do-mp/90-cleanup.sh && bash /root/do-mp/99-img_check.sh; fi",
      "rm -rf /root/do-mp",
    ]
  }
}
