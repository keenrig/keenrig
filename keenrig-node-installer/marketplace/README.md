# Cloud marketplace images — Vultr, DigitalOcean, Akamai/Linode

Lets someone create a server with Keenrig already installed by clicking one button in their cloud
provider's marketplace, instead of running `curl | sudo sh`.

| File | What it is |
|---|---|
| [`keenrig.pkr.hcl`](keenrig.pkr.hcl) | Packer template that builds the snapshot for **Vultr** and **DigitalOcean** |
| [`cleanup.sh`](cleanup.sh) | Cleans the build machine before the snapshot — removes everything that belongs to ONE machine |
| [`../scripts/firstboot.sh`](../scripts/firstboot.sh) | Runs on the customer's first boot: waits for the box, writes the address and setup token, adds a login banner, sends one install-source ping |
| [`linode-stackscript.sh`](linode-stackscript.sh) | StackScript for **Linode** — runs `get.sh` while the server is created, no snapshot |

## Rule one: an image must not carry an identity

Marketplace images are cloned publicly. If `instance/master.key` were left in the snapshot, **every customer
server would share one key** for wrapping secrets. `cleanup.sh` removes `instance/`, SSH host keys,
`machine-id`, `authorized_keys` and logs; `keenrig-box`, systemd and cloud-init regenerate them on the
customer's server. `cleanup.sh` refuses to run if the machine has containers — images are built only from a
clean install.

**Required check for every build:** create TWO servers from the same snapshot, then on each:

```sh
sha256sum /var/lib/keenrig/instance/master.key   # must DIFFER between the two
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub  # must differ
cat /root/keenrig-setup.txt                       # has an address and a token; tokens differ
curl -s http://127.0.0.1:8080/api/v1/auth/setup   # {"needs_setup":true}
```

Open `http://<IP>/` → create the owner → install an app → the app is Running. Submit only when both servers pass.

## Building the image

```sh
cd keenrig-node-installer/marketplace
packer init .
VULTR_API_KEY=... DIGITALOCEAN_TOKEN=... packer build -var version=0.4.0 .
packer build -only='vultr.keenrig' -var version=0.4.0 .   # one provider only
```

Packer installs from the published release channel at `get.keenrig.com/dl/stable/`, not from your machine.
Rebuild for every major release.

## Install-source ping

Each marketplace server sends exactly one
`GET https://get.keenrig.com/ping?src=<vultr|digitalocean|linode>&v=<version>` on first boot, with no other
data. It is documented at keenrig.com/privacy and can be disabled by creating `/etc/keenrig/no-ping`.

## Security note

Until the owner account is created, the first person to open `http://<IP>/` can create it. Create the owner
right after the server boots; `firstboot.sh` prints this reminder in the login banner.
