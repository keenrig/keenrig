# Keenrig

**Self-hosted app platform for your own server.** Install open-source apps (n8n, Activepieces,
Open WebUI, …) on any Linux VPS with one command, with HTTPS, backups and updates handled for you.

## Quick start

**You need:** a clean VPS running Ubuntu 22.04, 24.04 or 26.04, root access, and ports 80/443
open. Docker is installed for you.

**1. Install** (about 2 minutes):

```sh
curl -fsSL https://get.keenrig.com | sudo sh
```

Already have a domain? Point its DNS `A` record at the server, then install with it:

```sh
curl -fsSL https://get.keenrig.com | sudo sh -s -- --domain box.example.com
```

**2. Open the Admin** at the address the installer prints (`https://<server-ip>/`, or your
domain) and create the owner account on the first screen. No Keenrig account is needed.

**3. Install an app:** **Catalog** → pick an app → **Install**. Its address is shown under
**Apps**. Add your own domain to it under **Domains**.

That's it. The box updates itself automatically (turn that off with `--no-auto-upgrade`).

### Everyday commands (on the server)

```sh
curl -fsSL https://get.keenrig.com | sudo sh -s -- --upgrade     # upgrade now
sudo /var/lib/keenrig/bin/keenrig-box reset-password --user <name>   # lost password
sudo journalctl -u keenrig-box -f                                # logs
curl -fsSL https://get.keenrig.com | sh -s -- --help             # all installer options
```

### Optional: manage it from Keenrig Cloud

To get a `*.keenrig.com` address and manage several servers from one place, sign in at
[console.keenrig.com](https://console.keenrig.com), create an environment, pick
"I have my own machine", and paste the one-time token into **Admin → Cloud Link** (or run
`curl -fsSL https://get.keenrig.com | sudo sh -s -- --join <token>`). Only the connection is
added: apps and data stay as they are.

### Run it locally (development)

Requires Go 1.26+, Node.js 20+ and Docker.

```sh
git clone https://github.com/keenrig-platform/keenrig.git && cd keenrig
make ui
go run ./keenrig-node/cmd/keenrig-box serve --data ./data --secure-cookies=false
```

Open http://127.0.0.1:8080 and create the owner account. Add `--reconcile=false` to explore the
UI without Docker (apps won't start).

## What's in this repository

| Directory | What it is | License |
|---|---|---|
| [`keenrig-node/`](keenrig-node/) | The box: `keenrig-box` (API, reconciler, Admin UI), `keenrig-agent`, `keenrig-ota` | AGPL-3.0 |
| [`keenrig-node/proprietary/`](keenrig-node/proprietary/) | Paid runtimes: Docker Swarm (Pro), Kubernetes (Enterprise) | [Keenrig Commercial License](keenrig-node/proprietary/LICENSE) |
| [`keenrig-node-installer/`](keenrig-node-installer/) | `get.sh`, systemd units, sudoers, cloud-init | AGPL-3.0 |
| [`keenrig-catalog/`](keenrig-catalog/) | App manifests and icons, embedded into the binary | AGPL-3.0 |
| [`keenrig-contracts/`](keenrig-contracts/) | OpenAPI specs, JSON Schemas and shared Go types | AGPL-3.0 |

Keenrig Cloud (the Console at console.keenrig.com, managed `*.keenrig.com` domains, cloud
backup) is a hosted service and is not part of this repository. A box runs fully without it.

## Plans

The free **Starter** tier runs on the Docker runtime: 1 node, 3 apps, 3 domains, no account
needed. Paid plans raise those limits and unlock the Swarm and Kubernetes runtimes. See
[keenrig.com/pricing](https://keenrig.com/pricing).

## Building from source

Requires Go 1.26+ and Node.js 20+.

```sh
make ui        # build the Admin UI (embedded into keenrig-box)
make build     # build every Go module
make test
```

To build a binary that contains only AGPL code, without `proprietary/`:

```sh
go build -tags oss ./keenrig-node/cmd/keenrig-box
```

## License

Everything in this repository is licensed under the [GNU Affero General Public License v3.0](LICENSE),
**except** the `keenrig-node/proprietary/` directory, which is under the
[Keenrig Commercial License](keenrig-node/proprietary/LICENSE).

The apps in the catalog are separate projects under their own licenses; their names and
logos are trademarks of their respective owners.
