#!/bin/sh
# Keenrig — install a node.
#
#   curl -fsSL https://get.keenrig.com | sh
#   curl -fsSL https://get.keenrig.com | sh -s -- --domain box.example.com
#   curl -fsSL https://get.keenrig.com | sh -s -- --join <token>
#   curl -fsSL https://get.keenrig.com | sh -s -- --upgrade     (an installed node)
#
# POSIX sh, not bash: this script runs on any clean VM, including Alpine or a
# minimal image without bash. A bashism here breaks exactly where nobody can
# debug it — all the user sees is "not found".
#
# READ BEFORE EDITING: every path below must match
# keenrig-node/internal/paths/paths.go. A mismatch is a SILENT install bug —
# the box creates its directories, systemd points at different ones, and
# nothing looks wrong until the first update deletes the wrong place.

set -eu

BASE="${KEENRIG_BASE:-/var/lib/keenrig}"
# The release channel lives under the same host that serves this script:
# one name, one certificate, and the file you are reading proves the host is
# reachable before anything is downloaded from it.
RELEASES="${KEENRIG_RELEASES:-https://get.keenrig.com/dl}"
CHANNEL="${KEENRIG_CHANNEL:-stable}"
KEENRIG_USER="${KEENRIG_USER:-keenrig}"
# The control plane that --join pairs against. Override for self-hosted clouds.
CLOUD="${KEENRIG_CLOUD_URL:-https://console.keenrig.com}"
DOMAIN=""
JOIN=""
SKIP_DOCKER=0
UPGRADE=0
FORCE=0
# AUTO: "" = leave the auto-upgrade timer as it is, on | off = install | remove.
AUTO=""
# SWARM: "" = plain Docker, init = first node of a Keenrig-created cluster,
# node = any other node (Docker + pair + join, no Keenrig services).
SWARM=""
# GATEWAY decides which proxy gets installed + bootstrapped. Must match the
# driver names registered in keenrig-node/internal/proxy (caddy | nginx |
# nginx-owasp) — a mismatch means the installer sets up a gateway the box
# cannot drive.
GATEWAY="${KEENRIG_PROXY:-caddy}"

usage() {
	cat <<'USAGE'
keenrig installer

  --domain <fqdn>   domain for the Admin UI (optional; you can set it later)
  --join <token>    join a control plane (issue the token in the Console).
                    On a node that is ALREADY installed it only pairs it -
                    nothing is reinstalled, domain and gateway are kept.
  --cloud <url>     control plane URL (default https://console.keenrig.com)
  --base <dir>      root directory (default /var/lib/keenrig)
  --channel <name>  release channel (default stable)
  --gateway <name>  caddy (default) | nginx | nginx-owasp
  --skip-docker     do not install Docker automatically
  --upgrade         upgrade an INSTALLED node to the channel's release: swap the
                    binaries, restart, health-check, roll back if it fails.
                    Leaves configuration, data and the cloud pairing alone.
  --force           with --upgrade: reinstall, or go back to an older release
  --auto-upgrade    check the channel every 5 minutes and run --upgrade when
                    it has a newer release (systemd timer keenrig-upgrade).
                    ON by default for a new install and for --join.
                    Releases are checked by sha256 only, NOT signed yet.
  --no-auto-upgrade remove that timer
                    (both work alone on an installed node, or with --upgrade)
  --swarm-init      with --join: first node of a cluster Keenrig created -
                    install, create the Docker Swarm, run apps on it
  --swarm-node      with --join: another node of that cluster - install Docker,
                    pair, join the swarm (no Keenrig services on this machine)
  -h, --help
USAGE
}

# Kept for the "must run as root" message below, which reprints the command the
# user actually typed. Word-splitting is fine here: every option this script
# takes (token, domain, URL, directory name) is a single shell word.
ARGV="$*"

while [ $# -gt 0 ]; do
	case "$1" in
	--domain) DOMAIN="${2:-}"; shift 2 ;;
	--join) JOIN="${2:-}"; shift 2 ;;
	--cloud) CLOUD="${2:-}"; shift 2 ;;
	--base) BASE="${2:-}"; shift 2 ;;
	--channel) CHANNEL="${2:-}"; shift 2 ;;
	--gateway) GATEWAY="${2:-}"; shift 2 ;;
	--skip-docker) SKIP_DOCKER=1; shift ;;
	--upgrade) UPGRADE=1; shift ;;
	--force) FORCE=1; shift ;;
	--auto-upgrade) AUTO=on; shift ;;
	--no-auto-upgrade) AUTO=off; shift ;;
	--swarm-init) SWARM=init; shift ;;
	--swarm-node) SWARM=node; shift ;;
	-h | --help) usage; exit 0 ;;
	*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

# The copy of this installer that the auto-upgrade timer runs. Set AFTER the
# flags, because --base moves it.
AUTO_SCRIPT="$BASE/scripts/keenrig-upgrade.sh"

log() { echo "==> $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# --- preflight checks -----------------------------------------------------------
#
# Check EVERYTHING before touching anything: a machine that got a new user and
# new directories before hearing "systemd is missing" is a machine in a
# half-done state the user has to clean up by hand.

# "try: sudo" is not enough here, and the reason is the pipe. The user is
# running `curl … | bash`, so there is no script path to prepend sudo to, and
# the two obvious guesses are both wrong: `sudo curl … | bash` elevates curl
# and leaves the shell unprivileged, while re-execing ourselves under sudo
# would mean fetching this script a SECOND time — a different download than
# the one that was reviewed. So print the exact command, with their own
# arguments in it, and let them run it.
if [ "$(id -u)" != "0" ]; then
	echo "ERROR: must run as root." >&2
	echo >&2
	echo "  Re-run with sudo on the SHELL, not on curl:" >&2
	echo >&2
	echo "    curl -fsSL https://get.keenrig.com | sudo sh -s --${ARGV:+ $ARGV}" >&2
	echo >&2
	echo "  (\`sudo curl … | sh\` does not work: that elevates the download, while the" >&2
	echo "  shell that runs the script stays unprivileged.)" >&2
	exit 1
fi

case "$(uname -s)" in
Linux) ;;
*) die "Linux only (got $(uname -s))" ;;
esac

case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) die "unsupported architecture: $(uname -m)" ;;
esac

case "$GATEWAY" in
caddy | nginx | nginx-owasp) ;;
*) die "invalid gateway: $GATEWAY (expected caddy | nginx | nginx-owasp)" ;;
esac

command -v systemctl >/dev/null 2>&1 || die "systemd is required"
command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || die "curl or wget is required"
command -v tar >/dev/null 2>&1 || die "tar is required"

fetch() {
	# $1 = url, $2 = destination
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 3 --retry-delay 2 -o "$2" "$1"
	else
		wget -q -O "$2" "$1"
	fi
}

# fetch_text prints a small remote file on stdout (empty + non-zero on error).
fetch_text() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --max-time 20 "$1" 2>/dev/null
	else
		wget -q -T 20 -O- "$1" 2>/dev/null
	fi
}

# ver_gt A B — true when semver A is strictly newer than B. Only
# MAJOR.MINOR.PATCH counts; a pre-release suffix is dropped, so a hand-built
# "0.0.0-dev" sorts below every release. awk rather than `sort -V`: busybox
# sort (Alpine) has no -V, and this script promises to run there.
ver_gt() {
	awk -v a="$1" -v b="$2" 'BEGIN {
		sub(/-.*/, "", a); sub(/-.*/, "", b)
		split(a, x, "."); split(b, y, ".")
		for (i = 1; i <= 3; i++) {
			if ((x[i] + 0) > (y[i] + 0)) exit 0
			if ((x[i] + 0) < (y[i] + 0)) exit 1
		}
		exit 1
	}'
}

# --- ports 80/443 ---------------------------------------------------------------
#
# The gateway has to OWN 80 and 443: the Admin link printed at the end is port
# 80 of this machine. Measured on a VPS that already ran Cloudron (2026-10-10):
# Cloudron's nginx kept both ports, keenrig-caddy could not bind, the warning
# scrolled past mid-install, and "Done. Admin: http://<ip>/" opened Cloudron's
# "Not Found" page. Refuse BEFORE touching anything, and say who holds the port.

# port_owner prints the name of the process listening on TCP port $1, "" when
# the port is free or `ss` is missing (no check is better than a wrong one).
port_owner() {
	command -v ss >/dev/null 2>&1 || return 0
	ss -ltnp "sport = :$1" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -n 1
}

check_ports() {
	# Cloudron first: its nginx would pass the "nginx" allowance below when the
	# gateway is nginx, and the two platforms fight over Docker and the ports.
	if [ -d /home/yellowtent/box ] || systemctl list-unit-files box.service 2>/dev/null | grep -q '^box\.service'; then
		die "Cloudron is installed on this machine and holds ports 80/443.
  Keenrig needs a machine of its own - install on a clean VPS (Ubuntu 22.04/24.04/26.04)."
	fi
	for p in 80 443; do
		owner="$(port_owner "$p")"
		case "$owner" in
		"") continue ;;
		# Our own gateway on a re-run, or the distro's caddy.service, which
		# caddy-bootstrap.sh disables before starting keenrig-caddy.
		caddy) [ "$GATEWAY" = caddy ] && continue ;;
		nginx) [ "$GATEWAY" != caddy ] && continue ;;
		esac
		die "port $p is already in use by '$owner'.
  The Keenrig gateway ($GATEWAY) must listen on 80 and 443 - otherwise the Admin
  link opens whatever '$owner' serves. Stop and disable it, then re-run:
    ss -ltnp 'sport = :$p'        # see exactly what is listening
    systemctl disable --now <its service>"
	done
}

# --- apt lock -------------------------------------------------------------------
#
# Measured on a fresh Contabo Ubuntu 26.04 (2026-10-14): right after first boot,
# cloud-init and unattended-upgrades hold the dpkg lock for several minutes, and
# get.docker.com died on "Could not get lock /var/lib/dpkg/lock-frontend". The
# user had done nothing wrong - they just ran the command too early. So WAIT
# for the lock instead of failing, and say what is being waited on.

APT_LOCKS="/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock"

# apt_busy is true while some process holds an apt/dpkg lock. apt takes fcntl
# locks, which `flock` cannot see - fuser can. Without fuser (psmisc missing),
# fall back to looking for the processes themselves.
apt_busy() {
	if command -v fuser >/dev/null 2>&1; then
		# shellcheck disable=SC2086
		fuser $APT_LOCKS >/dev/null 2>&1
	else
		pgrep -x 'apt|apt-get|dpkg|aptitude' >/dev/null 2>&1
	fi
}

wait_for_apt() {
	command -v apt-get >/dev/null 2>&1 || return 0
	# cloud-init on first boot runs apt itself; `status --wait` blocks until it
	# is done. Bounded, so a cloud-init stuck in an error never hangs us.
	if command -v cloud-init >/dev/null 2>&1 &&
		cloud-init status 2>/dev/null | grep -q 'running'; then
		log "waiting for cloud-init to finish first-boot setup"
		timeout 600 cloud-init status --wait >/dev/null 2>&1 || true
	fi
	i=0
	while apt_busy; do
		if [ "$i" = "0" ]; then
			log "another package manager is running (usually unattended-upgrades on a new server) - waiting for it"
		fi
		i=$((i + 1))
		[ "$i" -lt 120 ] || die "apt/dpkg is still locked after 10 minutes.
  See who holds it:  ps aux | grep -E 'apt|dpkg|unattended'
  Then re-run this installer - every step is idempotent."
		sleep 5
	done
}

# --- Docker -------------------------------------------------------------------

install_docker() {
	if command -v docker >/dev/null 2>&1; then
		log "Docker already installed: $(docker --version 2>/dev/null || echo '?')"
		return
	fi
	[ "$SKIP_DOCKER" = "0" ] || die "Docker is missing and --skip-docker was given"
	wait_for_apt
	log "installing Docker via get.docker.com"
	tmp="$(mktemp)"
	fetch https://get.docker.com "$tmp"
	# get.docker.com runs apt-get without a lock timeout, so unattended-upgrades
	# can grab the lock again between our wait and its first apt-get. One retry
	# after waiting again covers that window.
	if ! sh "$tmp"; then
		log "Docker install failed - waiting for apt and trying once more"
		sleep 5
		wait_for_apt
		if ! sh "$tmp"; then
			# A brand-new Ubuntu release can land before Docker publishes a
			# repository for it. Ubuntu's own docker.io package is older but
			# runs everything Keenrig needs.
			if command -v apt-get >/dev/null 2>&1; then
				log "get.docker.com failed - falling back to Ubuntu's docker.io package"
				pkg_install docker.io || { rm -f "$tmp"; die "could not install Docker"; }
			else
				rm -f "$tmp"
				die "could not install Docker"
			fi
		fi
	fi
	rm -f "$tmp"
	systemctl enable --now docker
}

# --- user + directories ---------------------------------------------------------
#
# Run under a dedicated user, NOT root: the box only needs rights on <base> and
# the ability to talk to dockerd. Running as root turns any hole in the control
# API into root on the machine.
#
# The trade-off, stated plainly: this user is in the docker group, and the
# docker group is effectively root (anyone who can call dockerd can mount /
# into a container). It is still better than running straight root because it
# narrows the surface of EVERYTHING else (reading files, writing outside
# <base>, ptracing other processes) — just do not mistake it for real
# isolation.

setup_user() {
	if ! id "$KEENRIG_USER" >/dev/null 2>&1; then
		log "creating user $KEENRIG_USER"
		useradd --system --home-dir "$BASE" --shell /usr/sbin/nologin "$KEENRIG_USER" 2>/dev/null ||
			adduser --system --home "$BASE" --shell /usr/sbin/nologin "$KEENRIG_USER"
	fi
	if getent group docker >/dev/null 2>&1; then
		usermod -aG docker "$KEENRIG_USER" 2>/dev/null || true
	fi
}

setup_dirs() {
	log "creating the directory layout under $BASE"
	# Must match paths.go — the four planes.
	mkdir -p \
		"$BASE/bin" \
		"$BASE/instance" \
		"$BASE/node/proxy/sites" \
		"$BASE/node/proxy/cert" \
		"$BASE/node/acme" \
		"$BASE/node/addons" \
		"$BASE/node/logs" \
		"$BASE/node/backup" \
		"$BASE/node/update" \
		"$BASE/node/run" \
		"$BASE/node/agent" \
		"$BASE/apps"
	chown -R "$KEENRIG_USER":"$KEENRIG_USER" "$BASE"
	# instance holds master.key — losing it means losing every secret of the
	# instance. 0700 matches paths.PrivateDirPerm.
	chmod 0700 "$BASE/instance"
	chmod 0755 "$BASE" "$BASE/bin" "$BASE/node" "$BASE/apps"
}

# --- download + verify ----------------------------------------------------------

install_binaries() {
	url="$RELEASES/$CHANNEL/keenrig-linux-$ARCH.tar.gz"
	log "downloading $url"
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT
	fetch "$url" "$tmp/keenrig.tar.gz"

	# The checksum guards against a CORRUPT FILE, not a compromised server —
	# whoever controls the release server also sets the sha256. An Ed25519
	# signature is what guards against that, and it belongs to keenrig-ota
	# (OT-01). The checksum stays because it is cheap and catches truncated
	# downloads, and this comment states the limit instead of letting the
	# reader assume more protection than exists.
	if fetch "$url.sha256" "$tmp/keenrig.tar.gz.sha256" 2>/dev/null; then
		if command -v sha256sum >/dev/null 2>&1; then
			(cd "$tmp" && sha256sum -c keenrig.tar.gz.sha256) ||
				die "checksum mismatch - the download is corrupt"
		fi
	else
		echo "WARNING: could not fetch the .sha256 file - skipping the integrity check" >&2
	fi

	tar -xzf "$tmp/keenrig.tar.gz" -C "$tmp"
	for b in keenrig-box keenrig-agent keenrig-ota; do
		[ -f "$tmp/$b" ] || die "the archive is missing $b"
		install -m 0755 -o "$KEENRIG_USER" -g "$KEENRIG_USER" "$tmp/$b" "$BASE/bin/$b"
	done
	# node/VERSION = semver TRẦN ("0.2.0"), thứ keenrig-ota so với manifest.
	# Gói có file VERSION (build-release.sh, 2026-10-03) thì lấy nó; gói cũ
	# thì hỏi binary — trước 2026-10-03 box không có --version, nên chỗ này
	# từng ghi file rỗng mà `|| true` che mất.
	if [ -f "$tmp/VERSION" ]; then
		tr -d '\r\n' <"$tmp/VERSION" >"$BASE/node/VERSION"
	else
		"$BASE/bin/keenrig-box" --version 2>/dev/null | awk '{print $NF}' >"$BASE/node/VERSION" || true
	fi
	chown "$KEENRIG_USER":"$KEENRIG_USER" "$BASE/node/VERSION" 2>/dev/null || true
}

# --- gateway ------------------------------------------------------------------

pkg_install() {
	if command -v apt-get >/dev/null 2>&1; then
		wait_for_apt
		# Lock::Timeout as well: unattended-upgrades can wake up between
		# wait_for_apt and this line (apt >= 1.9.11; older apt ignores it).
		# apt's own message is kept and shown on failure: hiding it once turned
		# "Unable to locate package caddy" (Ubuntu 22.04) into a bare WARNING
		# that said nothing about why.
		aptlog="$(mktemp)"
		if DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 update -qq >"$aptlog" 2>&1 &&
			DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -qq "$@" >>"$aptlog" 2>&1; then
			rm -f "$aptlog"
			return 0
		fi
		grep -E '^(E|W):' "$aptlog" | tail -n 5 >&2 || true
		rm -f "$aptlog"
		return 1
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y -q "$@"
	else
		return 1
	fi
}

# add_caddy_repo adds Caddy's official apt repository (Cloudsmith, GPG-signed).
#
# Measured 2026-10-14 on a fresh Ubuntu 22.04: `apt-get install caddy` ->
# "Unable to locate package caddy". Ubuntu only ships caddy from 23.04 on, and
# 22.04 is still a supported target, so the distro archive alone is not
# enough. These are the steps from caddyserver.com/docs/install, nothing more:
# the key goes in its own keyring file and the list pins `signed-by` to it, so
# it is trusted for this one repository only.
add_caddy_repo() {
	command -v apt-get >/dev/null 2>&1 || return 1
	log "caddy is not in this distro's archive - adding Caddy's official apt repository"
	command -v gpg >/dev/null 2>&1 || pkg_install gnupg || return 1
	keyring=/usr/share/keyrings/caddy-stable-archive-keyring.gpg
	tmp="$(mktemp)"
	fetch https://dl.cloudsmith.io/public/caddy/stable/gpg.key "$tmp" || { rm -f "$tmp"; return 1; }
	gpg --batch --yes --dearmor -o "$keyring" "$tmp" || { rm -f "$tmp"; return 1; }
	chmod 0644 "$keyring"
	fetch https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt "$tmp" || { rm -f "$tmp"; return 1; }
	# Only accept what that file is supposed to be: deb lines for this repo,
	# signed by the keyring above. Anything else (an HTML error page) is refused.
	grep -q "signed-by=$keyring" "$tmp" || { rm -f "$tmp"; return 1; }
	install -m 0644 "$tmp" /etc/apt/sources.list.d/caddy-stable.list
	rm -f "$tmp"
}

install_gateway() {
	case "$GATEWAY" in
	caddy)
		if command -v caddy >/dev/null 2>&1; then log "Caddy already installed"; return; fi
		log "installing Caddy (it obtains and renews certificates on its own)"
		if ! pkg_install caddy; then
			add_caddy_repo && pkg_install caddy ||
				die "could not install Caddy - the gateway is what makes the Admin reachable.
  Install it by hand (https://caddyserver.com/docs/install) and re-run this installer."
		fi
		;;
	nginx)
		if command -v nginx >/dev/null 2>&1; then log "nginx already installed"; return; fi
		log "installing nginx"
		pkg_install nginx openssl ||
			echo "WARNING: could not install nginx automatically" >&2
		;;
	nginx-owasp)
		log "installing nginx + ModSecurity"
		# Do NOT install silently and hope: bootstrap REFUSES if the module is
		# absent, and refusing is the right answer — enabling the WAF flag
		# without the module loaded means the user believes their apps are
		# protected while they are not.
		pkg_install nginx openssl libnginx-mod-http-modsecurity modsecurity-crs ||
			echo "WARNING: could not install nginx+ModSecurity automatically" >&2
		;;
	esac
}

# --- privileged scripts + sudoers -------------------------------------------------
#
# The box runs as user `keenrig`, NOT root: a hole in the control API then does
# not become root on the machine. But a few operations still need root
# (starting the gateway, deleting app data written by containers under other
# UIDs, reading disk usage). They go through the scripts below, each of which
# validates its own arguments.
#
# sudoers CANNOT check arguments — it only checks PATHS. So every guard lives
# inside the script itself, and the paths here must match sudoers EXACTLY.
install_privops() {
	log "installing the privileged scripts"
	dst="$BASE/scripts"
	mkdir -p "$dst"
	src="$(dirname "$0")/scripts"
	for f in caddy-bootstrap.sh nginx-bootstrap.sh nginx-ctl.sh restartservice.sh appdata.sh du.sh reboot.sh pair.sh; do
		if [ -f "$src/$f" ]; then
			install -m 0755 -o root -g root "$src/$f" "$dst/$f"
		else
			fetch "$RELEASES/$CHANNEL/scripts/$f" "$dst/$f"
			chmod 0755 "$dst/$f"
			chown root:root "$dst/$f"
		fi
	done

	# Owned by root, 0755: user `keenrig` must NOT be able to write the very
	# scripts it runs via sudo. If it could, every guard inside them is
	# meaningless — whoever takes the box just edits the script and calls it.
	chown root:root "$dst"
	chmod 0755 "$dst"

	log "installing sudoers"
	# Two files, and the split is not cosmetic. `keenrig` carries the grants and
	# MUST install; `keenrig-quiet` carries one journalctl-formatting tweak and
	# is allowed to be dropped.
	#
	# Measured on a real Ubuntu 26.04: since 25.10 Ubuntu ships **sudo-rs**, which
	# rejects the whole file over one setting it does not implement —
	# "unknown setting: 'syslog'". A rejected file loses EVERY line in it, so
	# keeping that tweak next to the grants would cost the box its gateway on
	# every current Ubuntu.
	install_sudoers_file() {
		# $1 = basename under sudoers/, $2 = "required" | "optional"
		sudosrc="$(dirname "$0")/sudoers/$1"
		tmp="$(mktemp)"
		if [ -f "$sudosrc" ]; then
			cp "$sudosrc" "$tmp"
		elif ! fetch "$RELEASES/$CHANNEL/sudoers/$1" "$tmp" 2>/dev/null; then
			rm -f "$tmp"
			[ "$2" = optional ] || die "cannot fetch sudoers/$1"
			return 0
		fi
		# visudo -c BEFORE placing it in /etc/sudoers.d: a sudoers file with a
		# syntax error BREAKS SUDO FOR THE WHOLE MACHINE, including for the real
		# administrator. This is one of the few places where "install now, fix
		# later" is not an option.
		if command -v visudo >/dev/null 2>&1 && ! visudo -cf "$tmp" >/dev/null 2>&1; then
			rm -f "$tmp"
			[ "$2" = optional ] ||
				die "sudoers/$1 was rejected by visudo - NOT installing it (it would break sudo for the whole machine)"
			log "skipping the optional sudoers/$1 (this sudo does not accept it)"
			return 0
		fi
		install -m 0440 -o root -g root "$tmp" "/etc/sudoers.d/$1"
		rm -f "$tmp"
	}
	install_sudoers_file keenrig required
	install_sudoers_file keenrig-quiet optional
}

# install_unit_files writes the unit files ONLY — not the 10-local.conf drop-in,
# which holds this machine's own choices (gateway, domain). --upgrade calls this
# alone: rewriting the drop-in from the flags of an upgrade run would silently
# reset a box installed with --domain or --gateway nginx to the defaults.
install_unit_files() {
	log "installing the systemd units"
	src="$(dirname "$0")/systemd"
	for u in keenrig-box.service keenrig-agent.service keenrig-ota.service keenrig-caddy.service; do
		if [ -f "$src/$u" ]; then
			install -m 0644 "$src/$u" "/etc/systemd/system/$u"
		else
			# Run via `curl | sh` and there is no source directory next to the
			# script — fetch the unit from the release channel.
			fetch "$RELEASES/$CHANNEL/systemd/$u" "/etc/systemd/system/$u"
		fi
	done
}

install_units() {
	install_unit_files

	mkdir -p /etc/systemd/system/keenrig-box.service.d
	cat >/etc/systemd/system/keenrig-box.service.d/10-local.conf <<EOF
[Service]
Environment=KEENRIG_BASE=$BASE
Environment=KEENRIG_PROXY=$GATEWAY
Environment=KEENRIG_CLOUD_URL=$CLOUD
EOF
	# The nginx driver's DSN: `nginx -s reload` and `nginx -t` both NEED ROOT
	# (the master process runs as root), while the box runs as user keenrig.
	# The driver's default is only right when the box runs as root — exactly
	# where we chose not to stand.
	case "$GATEWAY" in
	nginx | nginx-owasp)
		printf 'Environment=KEENRIG_PROXY_CONFIG=%s\n' 			"sudo -n $BASE/scripts/nginx-ctl.sh reload ;; sudo -n $BASE/scripts/nginx-ctl.sh test" 			>>/etc/systemd/system/keenrig-box.service.d/10-local.conf
		;;
	esac
	[ -z "$DOMAIN" ] || echo "Environment=KEENRIG_DOMAIN=$DOMAIN" >>/etc/systemd/system/keenrig-box.service.d/10-local.conf

	systemctl daemon-reload
	# All three units start together, NOT in order: the call graph is a DAG
	# (agent→box, ota→box) so each process retries on its own. Forcing a start
	# order here would hide an ND-06 bug until the first real reboot.
	#
	# restart, NOT `enable --now`: --now only STARTS a unit that is stopped, so
	# re-running the installer on a machine that already runs a box swaps the
	# binary and the unit file on disk while the OLD process keeps running with
	# the OLD unit's sandbox. Measured on a VPS 2026-10-14: box process from
	# 09:00 running a `(deleted)` binary, the 16:38 fix on disk never loaded.
	# restart also starts a unit that is stopped, so a first install is the same.
	systemctl enable keenrig-box.service keenrig-agent.service keenrig-ota.service
	systemctl restart keenrig-box.service keenrig-agent.service keenrig-ota.service
}

# bootstrap_gateway writes the base configuration and starts the gateway.
#
# Runs AFTER install_units (the unit must exist) and BEFORE wait_healthy: a
# healthy box with no gateway up means the user can only reach it on loopback
# port 8080 — that is, from nowhere.
#
# A failure here does NOT stop the install: the box keeps running, and the
# operator can fix the gateway afterwards. Aborting the whole install over the
# gateway would turn a fixable incident into a half-done machine.
bootstrap_gateway() {
	log "writing the base configuration for $GATEWAY"
	env_common="KEENRIG_BASE=$BASE KEENRIG_USER=$KEENRIG_USER"
	case "$GATEWAY" in
	caddy)
		if ! env $env_common "$BASE/scripts/caddy-bootstrap.sh"; then
			echo "WARNING: Caddy did not start. The box is still running on 127.0.0.1:8080." >&2
			echo "  See: journalctl -u keenrig-caddy -n 50" >&2
		fi
		;;
	nginx | nginx-owasp)
		waf=""
		[ "$GATEWAY" = "nginx-owasp" ] && waf="--waf"
		if ! env $env_common "$BASE/scripts/nginx-bootstrap.sh" $waf; then
			echo "WARNING: nginx did not start. The box is still running on 127.0.0.1:8080." >&2
			echo "  See: journalctl -u nginx -n 50" >&2
		fi
		;;
	esac
}

wait_healthy() {
	# Probes 127.0.0.1 because the box listens on LOOPBACK (SEC-01) — which is
	# also why this step runs ON the machine and cannot be checked remotely.
	log "waiting for keenrig-box to become ready"
	i=0
	while [ "$i" -lt 60 ]; do
		if command -v curl >/dev/null 2>&1 &&
			curl -fsS --max-time 2 http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
			log "keenrig-box is up"
			return 0
		fi
		i=$((i + 1))
		sleep 1
	done
	echo "WARNING: /healthz did not answer within 60s. See: journalctl -u keenrig-box -n 50" >&2
	return 1
}

# check_box_privileges proves the RUNNING box can use its sudo scripts
# (internal/privops). Without them a box looks healthy - /healthz answers - but
# every privileged step fails: an app running as a non-root user (n8n, uid 1000)
# never gets its volume chowned and crash-loops with EACCES, deleting an app
# leaves its data behind. Measured on a VPS 2026-10-14.
#
# Two separate checks, because they fail for different reasons:
#   - NoNewPrivs of the box PROCESS: a property of the unit's sandbox, not of
#     the unit text. systemd turns it on implicitly for any seccomp-based option
#     (RestrictSUIDSGID=, ProtectKernelModules=, SystemCallFilter=, ...) when
#     User= is not root, and then the kernel ignores sudo's setuid bit. Only
#     /proc/<pid>/status tells the truth.
#   - `sudo -n <script> --check` as the box user: sudoers missing, rejected by
#     sudo-rs, or the scripts not installed.
# Returns 1 and prints why when either fails.
check_box_privileges() {
	pid="$(systemctl show -p MainPID --value keenrig-box.service 2>/dev/null || echo 0)"
	if [ -n "$pid" ] && [ "$pid" != "0" ] && [ -r "/proc/$pid/status" ]; then
		nnp="$(awk '/^NoNewPrivs:/ {print $2}' "/proc/$pid/status")"
		if [ "$nnp" = "1" ]; then
			echo "ERROR: keenrig-box runs with NoNewPrivs=1 - sudo can never work from it." >&2
			echo "  Apps that run as a non-root user (n8n, ...) will crash-loop with EACCES." >&2
			echo "  An option in keenrig-box.service (or a drop-in) enables it implicitly:" >&2
			echo "    systemctl cat keenrig-box | grep -E 'NoNewPrivileges|RestrictSUIDSGID|ProtectKernelModules|SystemCallFilter|PrivateDevices|LockPersonality'" >&2
			return 1
		fi
	fi
	if command -v sudo >/dev/null 2>&1; then
		if ! su -s /bin/sh "$KEENRIG_USER" -c "KEENRIG_BASE='$BASE' sudo -n '$BASE/scripts/appdata.sh' --check" >/dev/null 2>&1; then
			echo "ERROR: user $KEENRIG_USER cannot run $BASE/scripts/appdata.sh through sudo." >&2
			echo "  Check: sudo -l -U $KEENRIG_USER    and    visudo -cf /etc/sudoers.d/keenrig" >&2
			return 1
		fi
	fi
	return 0
}

# check_gateway proves the link printed at the end works: port 80 of THIS
# machine must reach THIS box. A 200 alone proves nothing - another web server
# on port 80 answers 200 with its own page - so it looks for the box's own
# /healthz body. Sets GW_OK=1 | 0, or leaves it empty when it cannot check.
check_gateway() {
	command -v curl >/dev/null 2>&1 || return 0
	log "checking that port 80 reaches keenrig-box"
	# Probe through the machine's OWN addresses, not only 127.0.0.1. Measured on
	# Ubuntu 26.04 (2026-10-14): the box redirects http -> https and gives every
	# non-loopback IP a self-signed cert (caddy/selftls.go), but loopback gets no
	# cert on purpose - so http://127.0.0.1/ 308s to an https:// that fails the
	# handshake, while http://<ip>/ works for every real visitor. Caddy picks the
	# cert by the LOCAL address when there is no SNI (curl sends none for an IP),
	# so hitting <ip> from here exercises exactly the path a browser takes.
	# IPv6 is skipped: the URL would need brackets and one IPv4 proves the path.
	hosts="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v ':' | grep . | head -n 3) 127.0.0.1"
	# The box pushes the catch-all route to the gateway after it starts, so the
	# first few requests can legitimately 404.
	i=0
	while [ "$i" -lt 30 ]; do
		for h in $hosts; do
			case "$(curl -sSkL --max-time 3 "http://$h/healthz" 2>/dev/null)" in
			*'"status":"ok"'* | *'"status": "ok"'*) GW_OK=1; return 0 ;;
			esac
		done
		i=$((i + 1))
		sleep 1
	done
	GW_OK=0
}

# join_cloud exchanges the one-time join token for agent credentials.
#
# It runs LAST, after every failure-prone step (Docker, download, gateway):
# the token is single-use with a 30-minute lifetime, and burning it on a
# machine that then dies at the download would force the user back to the
# Console for a new token just to retry. If pairing itself fails, the box is
# already installed and standalone — re-running this installer with a fresh
# token is cheap because every earlier step is idempotent.
join_cloud() {
	[ -n "$JOIN" ] || return 0
	pair_with_cloud

	# The API key is a secret: a root-owned 0600 EnvironmentFile, NOT a
	# command-line flag (visible in ps aux) and NOT the unit file itself
	# (0644 - readable by every user on the machine).
	mkdir -p /etc/keenrig
	old_umask="$(umask)"
	umask 077
	cat >/etc/keenrig/agent.env <<EOF
KEENRIG_CLOUD_URL=$CLOUD
KEENRIG_AGENT_KEY=$api_key
KEENRIG_ENV_ID=$env_id
KEENRIG_DATA_DIR=$BASE
EOF
	umask "$old_umask"
	chown root:root /etc/keenrig/agent.env
	chmod 0600 /etc/keenrig/agent.env
	systemctl restart keenrig-agent.service
	log "joined environment $env_id - the agent now syncs with $CLOUD"
	JOINED_KEY="$api_key"
}

# pair_with_cloud trades the one-time --join token for agent credentials and
# sets env_id / api_key. Nothing is written to disk here.
pair_with_cloud() {
	log "joining the control plane at $CLOUD"
	ver="$("$BASE/bin/keenrig-agent" --version 2>/dev/null | awk '{print $2}')"
	body="{\"token\":\"$JOIN\",\"host_id\":\"$(hostname 2>/dev/null || uname -n)\",\"version\":\"${ver:-unknown}\"}"
	# No --retry on purpose: the token is consumed server-side on first use, so
	# a blind retry can never succeed and only muddies the error.
	if command -v curl >/dev/null 2>&1; then
		res="$(curl -sS --max-time 30 -H 'Content-Type: application/json' \
			-d "$body" "$CLOUD/agent/v1/pair" 2>&1)" || true
	else
		res="$(wget -q -O- --header='Content-Type: application/json' \
			--post-data="$body" "$CLOUD/agent/v1/pair" 2>&1)" || true
	fi
	env_id="$(printf '%s' "$res" | sed -n 's/.*"env_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
	api_key="$(printf '%s' "$res" | sed -n 's/.*"api_key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
	if [ -z "$env_id" ] || [ -z "$api_key" ]; then
		echo "ERROR: pairing with $CLOUD failed." >&2
		echo "  Response: ${res:-<empty>}" >&2
		echo >&2
		echo "  The box itself is installed and running standalone. Join tokens are" >&2
		echo "  single-use and expire after 30 minutes - issue a fresh one in the" >&2
		echo "  Console and re-run this installer with the new --join token." >&2
		exit 1
	fi
}

# --- Docker Swarm for machines Keenrig created ----------------------------------
#
# The cloud never connects down to a machine, so the cluster forms by asking up:
# the first node runs `docker swarm init` and reports the join tokens; every
# other node asks until those tokens exist, then joins. Join tokens never travel
# in cloud-init - a node only gets them after pairing, with its own agent key.

agent_post() {
	if command -v curl >/dev/null 2>&1; then
		curl -sS --max-time 30 -H 'Content-Type: application/json' \
			-H "Authorization: Bearer $1" -d "$3" "$CLOUD$2" 2>&1 || true
	else
		wget -q -O- --header='Content-Type: application/json' \
			--header="Authorization: Bearer $1" --post-data="$3" "$CLOUD$2" 2>&1 || true
	fi
}

json_field() {
	printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"
}

swarm_state() {
	docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || true
}

swarm_report() {
	res="$(agent_post "$JOINED_KEY" /agent/v1/swarm/report "$1")"
	case "$res" in
	*'"error"'*) die "reporting to $CLOUD failed: $res" ;;
	esac
}

swarm_setup() {
	[ -n "$SWARM" ] || return 0
	[ -n "${JOINED_KEY:-}" ] || die "--swarm-init / --swarm-node need --join"
	command -v docker >/dev/null 2>&1 || die "Docker is required to join the cluster"
	tries=0
	while :; do
		res="$(agent_post "$JOINED_KEY" /agent/v1/swarm '{}')"
		case "$(json_field "$res" action)" in
		init) swarm_init "$res"; return ;;
		join) swarm_join "$res"; return ;;
		none) log "the cloud has no cluster work for this machine"; return ;;
		wait)
			tries=$((tries + 1))
			# The first node may still be installing: wait up to an hour.
			[ "$tries" -le 240 ] || die "the first node never created the cluster"
			log "waiting for the first node to create the cluster"
			sleep 15
			;;
		*)
			tries=$((tries + 1))
			[ "$tries" -le 20 ] || die "asking $CLOUD for the cluster failed: ${res:-<empty>}"
			sleep 15
			;;
		esac
	done
}

swarm_init() {
	addr="$(json_field "$1" advertise_addr)"
	[ -n "$addr" ] || addr="$(hostname -I 2>/dev/null | awk '{print $1}')"
	[ -n "$addr" ] || die "could not find this machine's address for the cluster"
	if [ "$(swarm_state)" != "active" ]; then
		log "creating the Docker Swarm cluster on $addr"
		docker swarm init --advertise-addr "$addr" >/dev/null || die "docker swarm init failed"
	fi
	mtok="$(docker swarm join-token -q manager)" || die "reading the manager join token failed"
	wtok="$(docker swarm join-token -q worker)" || die "reading the worker join token failed"
	swarm_report "{\"event\":\"init\",\"manager_addr\":\"$addr:2377\",\"manager_token\":\"$mtok\",\"worker_token\":\"$wtok\"}"

	# keenrig-box runs apps as Swarm services from now on.
	drop=/etc/systemd/system/keenrig-box.service.d/10-local.conf
	if ! grep -q '^Environment=KEENRIG_RUNTIME=' "$drop" 2>/dev/null; then
		echo "Environment=KEENRIG_RUNTIME=swarm" >>"$drop"
		systemctl daemon-reload
		systemctl restart keenrig-box.service
	fi
	log "cluster created - other nodes join it on their own"
}

swarm_join() {
	role="$(json_field "$1" role)"
	mgr="$(json_field "$1" manager_addr)"
	tok="$(json_field "$1" join_token)"
	addr="$(json_field "$1" advertise_addr)"
	[ -n "$addr" ] || addr="$(hostname -I 2>/dev/null | awk '{print $1}')"
	if [ "$(swarm_state)" != "active" ]; then
		log "joining the cluster at $mgr as a $role"
		docker swarm join --advertise-addr "$addr" --token "$tok" "$mgr" >/dev/null ||
			die "docker swarm join failed"
	fi
	# A 2-node cluster keeps node 2 as a worker (two managers lose quorum when
	# either fails). The third node to join as manager promotes it.
	promoted=""
	if [ "$role" = "manager" ]; then
		list="$(printf '%s' "$1" | sed -n 's/.*"promote"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p' | tr -d '"' | tr ',' ' ')"
		for h in $list; do
			case "$h" in *[!A-Za-z0-9._-]*) continue ;; esac
			if docker node promote "$h" >/dev/null 2>&1; then
				promoted="$promoted,\"$h\""
			fi
		done
	fi
	swarm_report "{\"event\":\"joined\",\"promoted\":[${promoted#,}]}"
	log "this machine is now part of the cluster"
}

# join_swarm_node is the whole install for --swarm-node: Docker, pair, join.
# Keenrig itself runs on the first node only, so nothing else is installed.
join_swarm_node() {
	[ -n "$JOIN" ] || die "--swarm-node needs --join <token>"
	install_docker
	pair_with_cloud
	mkdir -p /etc/keenrig
	old_umask="$(umask)"
	umask 077
	cat >/etc/keenrig/node.env <<EOF
KEENRIG_CLOUD_URL=$CLOUD
KEENRIG_AGENT_KEY=$api_key
KEENRIG_ENV_ID=$env_id
EOF
	umask "$old_umask"
	chmod 0600 /etc/keenrig/node.env
	JOINED_KEY="$api_key"
	swarm_setup
	log "Done. This node runs apps for environment $env_id."
}

# check_network asks the CLOUD whether this machine can be reached from the
# Internet, and prints the answer.
#
# WHY THE CLOUD ANSWERS AND NOT US: a machine cannot measure its own
# reachability. This box knows it is listening on port 80; it cannot know
# whether the home router, the ISP firewall, or carrier-grade NAT lets any
# packet get there. "Can it be reached" is only answerable from outside.
#
# WHY THIS RUNS AT INSTALL TIME: without it the sequence for a user behind NAT
# is: install finishes -> "Done" -> open the Admin link -> error page, with
# nothing anywhere saying why. Four steps, and the last one happens after they
# already believe it worked. This turns that into one line, here, while they
# are still looking at the terminal.
check_network() {
	[ -n "${JOINED_KEY:-}" ] || return 0
	log "asking $CLOUD whether this machine is reachable from the Internet"
	res=""
	if command -v curl >/dev/null 2>&1; then
		res="$(curl -sS --max-time 25 -H "Authorization: Bearer $JOINED_KEY" 			"$CLOUD/agent/v1/network" 2>&1)" || true
	else
		res="$(wget -q -O- --header="Authorization: Bearer $JOINED_KEY" 			"$CLOUD/agent/v1/network" 2>&1)" || true
	fi
	NET_IP="$(printf '%s' "$res" | sed -n 's/.*"public_ip"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
	NET_ADMIN="$(printf '%s' "$res" | sed -n 's/.*"admin_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
	case "$res" in
	*'"reachable":true'* | *'"reachable": true'*) NET_OK=1 ;;
	*) NET_OK=0 ;;
	esac
}

# setup_tunnel installs the Cloudflare tunnel, and ONLY when it is needed.
#
# A machine that answers on 80/443 does not get one: routing its traffic through
# a third party when nothing requires it adds a hop, a dependency, and someone
# else reading the plaintext. The decision comes from a MEASUREMENT made from
# outside (check_network), never from a guess about the network.
setup_tunnel() {
	log "installing the Cloudflare tunnel (this machine is not reachable directly)"

	if [ ! -x "$BASE/bin/cloudflared" ]; then
		cf_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$ARCH"
		log "downloading cloudflared"
		if ! fetch "$cf_url" "$BASE/bin/cloudflared.tmp"; then
			echo "WARNING: could not download cloudflared - the box runs, but nothing can reach it" >&2
			rm -f "$BASE/bin/cloudflared.tmp"
			return 1
		fi
		chmod 0755 "$BASE/bin/cloudflared.tmp"
		chown "$KEENRIG_USER":"$KEENRIG_USER" "$BASE/bin/cloudflared.tmp"
		mv "$BASE/bin/cloudflared.tmp" "$BASE/bin/cloudflared"
	fi

	# The script runs AS the keenrig user, so it goes next to the privileged
	# ones but is NOT in sudoers - it needs no root at all.
	src="$(dirname "$0")/scripts/tunnel.sh"
	if [ -f "$src" ]; then
		install -m 0755 -o root -g root "$src" "$BASE/scripts/tunnel.sh"
	else
		fetch "$RELEASES/$CHANNEL/scripts/tunnel.sh" "$BASE/scripts/tunnel.sh" || return 1
		chmod 0755 "$BASE/scripts/tunnel.sh"
		chown root:root "$BASE/scripts/tunnel.sh"
	fi

	usrc="$(dirname "$0")/systemd/keenrig-tunnel.service"
	if [ -f "$usrc" ]; then
		install -m 0644 "$usrc" /etc/systemd/system/keenrig-tunnel.service
	else
		fetch "$RELEASES/$CHANNEL/systemd/keenrig-tunnel.service" 			/etc/systemd/system/keenrig-tunnel.service || return 1
	fi

	systemctl daemon-reload
	systemctl enable --now keenrig-tunnel.service || {
		echo "WARNING: keenrig-tunnel did not start. See: journalctl -u keenrig-tunnel -n 50" >&2
		return 1
	}
	# Give it a moment to publish, then ask the cloud again - by then the
	# forwarder knows where to send visitors and can hand back a real URL.
	sleep 8
	check_network
	return 0
}

# --- upgrade --------------------------------------------------------------------
#
# upgrade_node moves an INSTALLED node to the channel's release without anyone
# copying files onto the machine by hand. It is the manual stand-in for
# keenrig-ota (keenrig-node/cmd/keenrig-ota) and follows the same order, so
# the ota can take this sequence over unchanged:
#
#   download + sha256 -> unpack into node/update/staging -> run the new box's
#   --version -> keep the current binaries in node/update/bin-previous ->
#   swap -> restart -> health check -> roll back if red.
#
# What it deliberately does NOT touch: the 10-local.conf drop-in (gateway,
# domain), /etc/keenrig/agent.env (the cloud pairing), Docker, the gateway
# config, and every byte of data. Those belong to this machine, not to a release.
#
# Staging and bin-previous live under node/update, on the SAME filesystem as
# bin/ — the swap and the rollback are renames, and a rename is only atomic
# within one filesystem (FILESYSTEM.md).
upgrade_node() {
	[ -x "$BASE/bin/keenrig-box" ] ||
		die "no keenrig-box in $BASE/bin - this machine has no node to upgrade (run the installer without --upgrade)"
	[ -f /etc/systemd/system/keenrig-box.service ] ||
		die "keenrig-box.service is not installed - run the installer without --upgrade"

	upd="$BASE/node/update"
	stage="$upd/staging"
	prev="$upd/bin-previous"
	mkdir -p "$upd"

	# One upgrade at a time: the timer and a person typing --upgrade must not
	# both swap bin/. The lock is taken BEFORE staging is touched — the second
	# run would otherwise delete the first one's download mid-flight.
	if command -v flock >/dev/null 2>&1; then
		exec 9>"$upd/.lock"
		flock -n 9 || die "another upgrade is already running on this machine"
	fi

	# 2>/dev/null BEFORE the input redirect: redirections apply left to right,
	# so the other order lets dash print "cannot open" for a missing file.
	cur_ver="$(tr -d '\r\n' 2>/dev/null <"$BASE/node/VERSION" || true)"
	# A release that failed its health check here is not retried on its own:
	# the timer would otherwise take the Admin down for a minute every 5
	# minutes, forever, on a build that is broken for this machine. The next
	# release (or --force) clears it.
	failed_ver="$(tr -d '\r\n' 2>/dev/null <"$upd/failed-version" || true)"

	# Ask the channel's VERSION file first (a few bytes) so a timer that finds
	# nothing new does not pull an 18 MB tarball every 5 minutes. It only
	# decides whether to DOWNLOAD — the decision to INSTALL is made later from
	# the downloaded binary itself, so a VERSION file uploaded ahead of its
	# tarball cannot install anything. Anything that is not a bare semver
	# (a 404 page, the Console SPA answering 200 with HTML) is ignored and the
	# tarball is fetched as before.
	chan_ver="$(fetch_text "$RELEASES/$CHANNEL/VERSION" | tr -d '\r\n ' || true)"
	case "$chan_ver" in
	[0-9]*.[0-9]*.[0-9]*)
		if [ "$FORCE" = "0" ] && [ -n "$cur_ver" ] && ! ver_gt "$chan_ver" "$cur_ver"; then
			log "on $cur_ver, channel $CHANNEL has $chan_ver - nothing to do"
			return 0
		fi
		if [ "$FORCE" = "0" ] && [ "$chan_ver" = "$failed_ver" ]; then
			log "skipping $chan_ver: it already failed its health check on this machine (use --force to retry)"
			return 0
		fi
		;;
	*) chan_ver="" ;;
	esac

	rm -rf "$stage"
	mkdir -p "$stage"

	url="$RELEASES/$CHANNEL/keenrig-linux-$ARCH.tar.gz"
	log "downloading $url"
	fetch "$url" "$stage/keenrig.tar.gz"
	# REQUIRED here, unlike a first install: replacing a WORKING box with a
	# truncated download is strictly worse than not upgrading at all.
	fetch "$url.sha256" "$stage/keenrig.tar.gz.sha256" ||
		die "could not fetch $url.sha256 - not upgrading without an integrity check"
	command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required for --upgrade"
	(cd "$stage" && sha256sum -c keenrig.tar.gz.sha256 >/dev/null) ||
		die "checksum mismatch - the download is corrupt, nothing was changed"
	tar -xzf "$stage/keenrig.tar.gz" -C "$stage"
	for b in keenrig-box keenrig-agent keenrig-ota; do
		[ -f "$stage/$b" ] || die "the archive is missing $b - nothing was changed"
		chmod 0755 "$stage/$b"
	done

	# Run the NEW binary before it replaces anything: a build for the wrong
	# architecture, or a broken one, fails here while the old box still runs.
	new_ver="$("$stage/keenrig-box" --version 2>/dev/null | awk '{print $NF}')" ||
		die "the new keenrig-box does not run on this machine - nothing was changed"
	[ -n "$new_ver" ] || die "the new keenrig-box printed no version - nothing was changed"
	if [ -f "$stage/VERSION" ]; then
		pkg_ver="$(tr -d '\r\n' <"$stage/VERSION")"
		[ "$pkg_ver" = "$new_ver" ] ||
			die "the package says $pkg_ver but its keenrig-box says $new_ver - refusing a mislabelled release"
	fi
	# Forward only. A channel that moves BACK (a release pulled, a stale mirror,
	# someone restoring an old backup of the channel) must not walk every node
	# down with it — downgrades cross schema migrations the old binary may not
	# read (OT-05). --force is the deliberate way to reinstall or go back.
	if [ "$FORCE" = "0" ] && [ -n "$cur_ver" ] && ! ver_gt "$new_ver" "$cur_ver"; then
		if [ "$new_ver" = "$cur_ver" ]; then
			log "already on $new_ver - nothing to do (use --force to reinstall it)"
		else
			log "channel $CHANNEL has $new_ver, OLDER than the running $cur_ver - not downgrading (use --force)"
		fi
		rm -rf "$stage"
		return 0
	fi
	if [ "$FORCE" = "0" ] && [ "$new_ver" = "$failed_ver" ]; then
		log "skipping $new_ver: it already failed its health check on this machine (use --force to retry)"
		rm -rf "$stage"
		return 0
	fi
	log "upgrading ${cur_ver:-<unknown version>} -> $new_ver"

	# Copy, not move, into bin-previous: bin/ also holds files that are not
	# part of a release (cloudflared), and the old binaries must stay in place
	# until the very moment the new ones replace them.
	rm -rf "$prev"
	mkdir -p "$prev"
	for b in keenrig-box keenrig-agent keenrig-ota; do
		[ ! -f "$BASE/bin/$b" ] || cp -p "$BASE/bin/$b" "$prev/$b"
	done
	printf '%s\n' "$cur_ver" >"$prev/VERSION"

	# Scripts, sudoers and unit files ship with the release (a fix to
	# caddy-bootstrap.sh or to keenrig-box.service is part of an upgrade too).
	# The privops scripts are fetched from the channel since there is no source
	# directory next to a piped script.
	install_privops
	install_unit_files
	systemctl daemon-reload

	# Swap: install to <name>.new then rename over the old file. Writing
	# straight onto a running executable fails with "Text file busy"; a rename
	# replaces the directory entry and the running process keeps its old inode.
	for b in keenrig-box keenrig-agent keenrig-ota; do
		install -m 0755 -o "$KEENRIG_USER" -g "$KEENRIG_USER" "$stage/$b" "$BASE/bin/$b.new"
		mv -f "$BASE/bin/$b.new" "$BASE/bin/$b"
	done
	printf '%s\n' "$new_ver" >"$BASE/node/VERSION"
	chown "$KEENRIG_USER":"$KEENRIG_USER" "$BASE/node/VERSION" 2>/dev/null || true

	log "restarting keenrig-box, keenrig-agent, keenrig-ota"
	# The gateway (keenrig-caddy) is NOT restarted: it is a separate process,
	# so apps keep serving traffic while the box restarts (OT-03).
	systemctl restart keenrig-box.service keenrig-agent.service keenrig-ota.service || true

	if upgrade_healthy "$new_ver"; then
		rm -rf "$stage"
		rm -f "$upd/failed-version"
		# The timer runs the SAVED copy of this script; keep it in step with
		# the release it just installed, so a fix to the upgrade logic itself
		# reaches nodes that upgrade on their own.
		[ ! -f "$AUTO_SCRIPT" ] || save_upgrade_script || true
		# Not a rollback trigger: rolling back swaps the BINARIES, while a broken
		# sandbox lives in the unit file and the sudoers - the old binary would be
		# just as broken. Say it loudly instead (the timer's journal keeps it).
		check_box_privileges || true
		echo
		log "Upgraded to $new_ver."
		echo "  The previous binaries are kept in $prev"
		return 0
	fi

	printf '%s\n' "$new_ver" >"$upd/failed-version"
	echo "ERROR: $new_ver did not come up healthy - rolling back to ${cur_ver:-the previous binaries}" >&2
	for b in keenrig-box keenrig-agent keenrig-ota; do
		[ -f "$prev/$b" ] || continue
		cp -p "$prev/$b" "$BASE/bin/$b.new"
		mv -f "$BASE/bin/$b.new" "$BASE/bin/$b"
	done
	tr -d '\r\n' <"$prev/VERSION" >"$BASE/node/VERSION" || true
	systemctl restart keenrig-box.service keenrig-agent.service keenrig-ota.service || true
	if upgrade_healthy "${cur_ver:-}"; then
		echo "  Rolled back; the node runs ${cur_ver:-its previous binaries} again." >&2
	else
		echo "  The rollback did not come up healthy either. See: journalctl -u keenrig-box -n 80" >&2
	fi
	echo "  The failed release is left in $stage for inspection." >&2
	exit 1
}

# --- auto-upgrade ---------------------------------------------------------------
#
# A systemd timer that runs `--upgrade` every 5 minutes. Everything that makes
# --upgrade safe (forward only, health check, rollback, no retry of a release
# that failed here, one run at a time) is what makes running it unattended
# acceptable. What it still lacks is a SIGNATURE: whoever controls the release
# host can push a binary to every node with this timer on. That is why it is
# opt-in, and why keenrig-ota (signed, DESIGN-ota.md) is meant to replace it.

# save_upgrade_script stores the CHANNEL's installer as the copy the timer runs.
# Not "this script": piped through `curl | sh` there is no file to copy. The
# channel carries get.sh next to the tarball (build-release.sh); a channel from
# before that falls back to the script served at the root of the release host.
save_upgrade_script() {
	tmp="$(mktemp)"
	if ! fetch "$RELEASES/$CHANNEL/get.sh" "$tmp" 2>/dev/null ||
		[ "$(head -n 1 "$tmp")" != "#!/bin/sh" ]; then
		fetch "${RELEASES%/dl}/" "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
	fi
	# The same two checks deploy-get.sh makes before SERVING it: it has to be a
	# shell script (not an HTML error page answered with 200) and valid sh.
	if [ "$(head -n 1 "$tmp")" != "#!/bin/sh" ] || ! sh -n "$tmp" 2>/dev/null; then
		rm -f "$tmp"
		return 1
	fi
	# An installer from before 2026-10-05 is a valid script that answers
	# `--upgrade` with "unknown option" — the timer would fail every 5 minutes
	# and nothing would say why. Only keep one that knows this mode.
	if ! grep -q -- '--auto-upgrade' "$tmp"; then
		rm -f "$tmp"
		return 1
	fi
	# root:root 0755 inside the root-owned scripts dir: the timer runs this AS
	# ROOT, so user keenrig must never be able to edit it (same rule as the
	# privops scripts next to it).
	install -m 0755 -o root -g root "$tmp" "$AUTO_SCRIPT"
	rm -f "$tmp"
}

install_auto_upgrade() {
	log "enabling automatic upgrades from channel $CHANNEL (every 5 minutes)"
	mkdir -p "$BASE/scripts"
	save_upgrade_script || die "could not fetch the installer for the auto-upgrade timer"

	# The timer upgrades from where THIS machine was installed from — a box on
	# a beta channel or a self-hosted release host stays there.
	mkdir -p /etc/keenrig
	cat >/etc/keenrig/upgrade.env <<EOF
KEENRIG_BASE=$BASE
KEENRIG_RELEASES=$RELEASES
KEENRIG_CHANNEL=$CHANNEL
KEENRIG_USER=$KEENRIG_USER
EOF
	chmod 0644 /etc/keenrig/upgrade.env

	write_upgrade_units
	systemctl daemon-reload
	systemctl enable --now keenrig-upgrade.timer
	log "auto-upgrade on - logs: journalctl -u keenrig-upgrade"
}

# write_upgrade_units writes the service + timer. Split out so a node that
# turned the timer on with an OLDER installer (15-minute interval) picks up
# today's schedule on its next tick: refresh_upgrade_units calls this on every
# --upgrade run, not only when a new release is installed.
write_upgrade_units() {
	cat >/etc/systemd/system/keenrig-upgrade.service <<EOF
[Unit]
Description=Keenrig: install the newer release from the channel, if there is one
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/keenrig/upgrade.env
ExecStart=/bin/sh $AUTO_SCRIPT --upgrade
# Download + swap + 60s health check + a possible rollback fits well inside this.
TimeoutStartSec=15min
EOF
	cat >/etc/systemd/system/keenrig-upgrade.timer <<EOF
[Unit]
Description=Keenrig: check the release channel every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
# Spread the fleet: every node asking the release host in the same second
# right after a publish is a self-inflicted load spike.
RandomizedDelaySec=1min

[Install]
WantedBy=timers.target
EOF
}

# refresh_upgrade_units rewrites the units of a timer that is already on, and
# reloads only when they changed. Most ticks find nothing to change, and a
# daemon-reload every 5 minutes on every node would be noise in the journal.
refresh_upgrade_units() {
	[ -f /etc/systemd/system/keenrig-upgrade.timer ] || return 0
	before="$(cat /etc/systemd/system/keenrig-upgrade.service /etc/systemd/system/keenrig-upgrade.timer 2>/dev/null)"
	write_upgrade_units
	after="$(cat /etc/systemd/system/keenrig-upgrade.service /etc/systemd/system/keenrig-upgrade.timer)"
	[ "$before" != "$after" ] || return 0
	log "auto-upgrade schedule updated (every 5 minutes)"
	systemctl daemon-reload
	# restart, not just reload: the timer keeps its old elapse time otherwise.
	systemctl restart keenrig-upgrade.timer || true
}

remove_auto_upgrade() {
	log "disabling automatic upgrades"
	systemctl disable --now keenrig-upgrade.timer 2>/dev/null || true
	rm -f /etc/systemd/system/keenrig-upgrade.timer /etc/systemd/system/keenrig-upgrade.service \
		/etc/keenrig/upgrade.env "$AUTO_SCRIPT"
	systemctl daemon-reload
}

apply_auto_upgrade() {
	case "$AUTO" in
	on) install_auto_upgrade ;;
	off) remove_auto_upgrade ;;
	"") [ "$UPGRADE" != "1" ] || refresh_upgrade_units ;;
	esac
}

# upgrade_healthy waits for the box to answer /healthz, then checks that it
# STAYS up: a binary that starts, answers once and then crash-loops passes a
# single probe. $1 = the version that should be running ("" = do not check).
upgrade_healthy() {
	i=0
	until curl -fsS --max-time 2 http://127.0.0.1:8080/healthz >/dev/null 2>&1; do
		i=$((i + 1))
		[ "$i" -lt 60 ] || { echo "  /healthz did not answer within 60s" >&2; return 1; }
		sleep 1
	done
	restarts="$(systemctl show -p NRestarts --value keenrig-box.service 2>/dev/null || echo 0)"
	sleep 10
	systemctl is-active --quiet keenrig-box.service || { echo "  keenrig-box stopped after starting" >&2; return 1; }
	now="$(systemctl show -p NRestarts --value keenrig-box.service 2>/dev/null || echo 0)"
	[ "$now" = "$restarts" ] || { echo "  keenrig-box restarted $((now - restarts)) time(s) in 10s - crash loop" >&2; return 1; }
	curl -fsS --max-time 2 http://127.0.0.1:8080/healthz >/dev/null 2>&1 ||
		{ echo "  /healthz stopped answering" >&2; return 1; }
	if [ -n "${1:-}" ]; then
		running="$("$BASE/bin/keenrig-box" --version 2>/dev/null | awk '{print $NF}')"
		[ "$running" = "$1" ] || { echo "  bin/keenrig-box reports $running, expected $1" >&2; return 1; }
	fi
	for s in keenrig-agent keenrig-ota; do
		systemctl is-active --quiet "$s.service" ||
			echo "  WARNING: $s is not running - see: journalctl -u $s -n 50" >&2
	done
	return 0
}

main() {
	if [ "$SWARM" = "node" ]; then
		join_swarm_node
		return
	fi
	if [ "$UPGRADE" = "1" ]; then
		command -v curl >/dev/null 2>&1 || die "--upgrade needs curl (for the health check)"
		upgrade_node
		apply_auto_upgrade
		return
	fi
	# --auto-upgrade / --no-auto-upgrade alone on a node that is already
	# installed: switch the timer and stop. Falling through to the full install
	# would rewrite 10-local.conf from this run's (absent) --domain/--gateway.
	installed=0
	[ -x "$BASE/bin/keenrig-box" ] && [ -f /etc/systemd/system/keenrig-box.service ] && installed=1
	if [ -n "$AUTO" ] && [ "$installed" = "1" ] && [ -z "$JOIN" ]; then
		apply_auto_upgrade
		return
	fi
	# --join on a node that already runs standalone: pair it with the Console
	# and stop. Same reason as above - a full re-install would rewrite
	# 10-local.conf and drop the --domain / --gateway it was installed with.
	if [ -n "$JOIN" ] && [ "$installed" = "1" ]; then
		# Ghép vào Console = nhận bản phát hành từ kênh. Không có timer thì box
		# kẹt mãi ở bản lúc cài và mọi bản sửa (vd. chown volume cho app chạy
		# user thường) không bao giờ tới — đã gặp 2026-10-15 trên box 0.1.6.
		[ -n "$AUTO" ] || AUTO=on
		apply_auto_upgrade
		join_cloud
		swarm_setup
		check_network
		if [ "${NET_OK:-}" != "1" ] && [ -n "${NET_IP:-}" ]; then
			setup_tunnel || true
		fi
		echo
		log "Done. This node is connected to $CLOUD - it appears in the Console shortly."
		echo "  Console: $CLOUD/login"
		return
	fi
	check_ports
	install_docker
	setup_user
	setup_dirs
	install_binaries
	install_gateway
	install_privops
	install_units
	bootstrap_gateway
	wait_healthy || true
	PRIV_OK=1
	check_box_privileges || PRIV_OK=0
	check_gateway
	# Before join_cloud: a failed pairing exits 1, and the node is installed
	# (and should keep upgrading) either way. Cài mới thì BẬT mặc định — lệnh
	# Console đưa cho khách chỉ có `--join`; muốn tắt thì `--no-auto-upgrade`.
	[ -n "$AUTO" ] || AUTO=on
	apply_auto_upgrade
	join_cloud
	swarm_setup
	check_network
	# Không vào được từ Internet, nhưng ĐÃ ghép cloud → dựng tunnel.
	if [ -n "${JOINED_KEY:-}" ] && [ "${NET_OK:-}" != "1" ] && [ -n "${NET_IP:-}" ]; then
		setup_tunnel || true
	fi

	ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
	echo
	if [ "${GW_OK:-}" = "0" ]; then
		# Everything else is installed, but the one link we would print does
		# not work. Saying "Done" here is what sent people to a page that was
		# not ours.
		echo "ERROR: keenrig-box is installed, but port 80 does not reach it." >&2
		echo "  The Admin link would not work. Check the gateway:" >&2
		echo "    journalctl -u keenrig-caddy -n 50       (or: journalctl -u nginx -n 50)" >&2
		echo "    ss -ltnp 'sport = :80'                  (who holds port 80)" >&2
		echo "    curl -skL http://${ip:-<server-ip>}/healthz   (must print {\"status\":\"ok\"})" >&2
		echo "  Fix it and re-run this installer - every step is idempotent." >&2
		exit 1
	fi
	if [ "$PRIV_OK" = "0" ]; then
		# Not "Done": the Admin works, but the first app that runs as a non-root
		# user would crash-loop, and nothing on screen would say why.
		echo "ERROR: keenrig-box is installed but cannot run its privileged scripts (see above)." >&2
		echo "  Fix it and re-run this installer - every step is idempotent." >&2
		exit 1
	fi
	log "Done."
	# The address printed is port 80 of the GATEWAY, not 8080 of the box: the
	# box listens on loopback (SEC-01) so 8080 is not reachable from outside.
	# The gateway accepts requests aimed straight at the IP and forwards them
	# to the Admin UI via the catch-all (PX-03) — no domain needed.
	echo "  Admin:  https://${ip:-<server-ip>}/"
	[ -z "$DOMAIN" ] || echo "  Domain: https://$DOMAIN/"
	echo "  First-run setup token:  journalctl -u keenrig-box | grep 'setup token'"
	echo
	if [ -n "$JOIN" ]; then
		echo "  This node is connected to $CLOUD - it appears in the Console shortly."
		echo "  Console: $CLOUD/login"
	else
		echo "  No cloud account needed: create the instance owner on the very first screen."
		echo
		echo "  Manage it from the Keenrig Console too (optional):"
		echo "    1. Sign in:  $CLOUD/login"
		echo "    2. Create environment -> pick a domain -> Machine: \"I have my own machine\""
		echo "       The Console shows a one-time token."
		echo "    3. Paste the token in this box's Admin -> Cloud Link, or run here:"
		echo "         curl -fsSL https://get.keenrig.com | sudo sh -s -- --join <token>"
		echo "       Only connects - nothing is reinstalled; apps and data stay."
	fi
	echo

	# The reachability verdict, stated plainly. A machine that cannot be reached
	# is not a broken install - everything here is running - but it is also not
	# a machine anyone can visit, and the user has to hear that NOW.
	if [ "${NET_OK:-}" = "1" ]; then
		echo "  Reachable from the Internet at ${NET_IP:-?}."
		[ -z "${NET_ADMIN:-}" ] || echo "  Admin (DNS is being pointed here now): $NET_ADMIN"
	elif [ -n "${NET_ADMIN:-}" ]; then
		echo "  This machine has no public address, so it is published through a tunnel."
		echo "  Admin: $NET_ADMIN"
		echo
		echo "  Traffic goes: browser -> keenrig -> Cloudflare -> this machine. Nothing"
		echo "  listens on a public port here, and nothing needs to."
	elif [ -n "${NET_IP:-}" ]; then
		echo "  THIS MACHINE CANNOT BE REACHED FROM THE INTERNET." >&2
		echo >&2
		echo "  The agent reached $CLOUD from $NET_IP, but nothing answers on port 80 or" >&2
		echo "  443 at that address. The box is installed and running - it just has no way" >&2
		echo "  for a browser to get to it, and it cannot obtain a certificate either." >&2
		echo >&2
		echo "  Usually one of:" >&2
		echo "    - ports 80/443 are not forwarded to this machine" >&2
		echo "    - a firewall or security group drops them" >&2
		echo "    - the connection is behind carrier-grade NAT (common on home ISPs)," >&2
		echo "      where no port forwarding is possible at all" >&2
		echo >&2
		echo "  Fix that and it starts working on its own - nothing here to re-run." >&2
	fi
	echo
	echo "  Note: by IP the certificate is self-signed, so the browser warns once -"
	echo "  accept it to continue. Point a domain at this machine and use that domain"
	echo "  instead: Caddy obtains a real certificate on its own, nothing else to do."
}

main "$@"
