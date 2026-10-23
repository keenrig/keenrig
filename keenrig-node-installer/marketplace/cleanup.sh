#!/bin/sh
# Keenrig — empty a build machine before it is snapshotted for a marketplace.
#
# A marketplace image is cloned publicly. Anything per-instance left in it is
# SHARED by every customer machine made from it (Keenrig Cloud (provision)):
#
#   instance/master.key   one AES key wrapping every customer's secrets
#   instance/platform.db  same setup token, same OIDC signing key
#   SSH host keys         same fingerprint everywhere → MITM-able
#   /etc/machine-id       same id for every journal and DHCP client
#
# So this script deletes them, and keenrig-box / systemd / cloud-init make new
# ones on the customer's first boot (scripts/firstboot.sh).
#
# Run LAST, as root, after `get.sh` and after firstboot.sh is in place.
# Refuses to run if any container exists: an image must be built from a clean
# install, never from a machine someone used.

set -eu

BASE="${KEENRIG_BASE:-/var/lib/keenrig}"

die() { echo "cleanup: $*" >&2; exit 1; }
log() { echo "cleanup: $*"; }

[ "$(id -u)" -eq 0 ] || die "must run as root"
[ -x "$BASE/bin/keenrig-box" ] || die "keenrig is not installed under $BASE"
[ -x /var/lib/cloud/scripts/per-instance/keenrig-firstboot.sh ] ||
	die "firstboot script missing - the customer would get no fresh identity hint and no login message"

if command -v docker >/dev/null 2>&1 && [ -n "$(docker ps -aq 2>/dev/null)" ]; then
	die "containers exist on this machine - build the image from a clean install"
fi

log "stopping keenrig services"
for u in keenrig-box keenrig-agent keenrig-ota keenrig-tunnel keenrig-caddy keenrig-upgrade.timer; do
	systemctl stop "$u" 2>/dev/null || true
done

log "emptying per-instance state under $BASE"
# Contents only: the directories keep the owner and mode get.sh gave them
# (instance/ is 0700), and keenrig-box expects them to exist.
find "$BASE/instance" -mindepth 1 -delete
for d in node/proxy/sites node/proxy/cert node/acme node/addons node/logs node/backup \
	node/update node/run node/agent apps; do
	[ -d "$BASE/$d" ] && find "$BASE/$d" -mindepth 1 -delete
done
# node/VERSION and node/proxy/caddy.json stay: they describe the release and
# the gateway, not the machine.

rm -f /root/keenrig-setup.txt /etc/keenrig/admin-url /etc/keenrig/.pinged

log "removing machine identity, keys and history"
rm -f /etc/ssh/ssh_host_*
rm -f /root/.ssh/authorized_keys
for h in /home/*/.ssh/authorized_keys; do [ -e "$h" ] && rm -f "$h"; done
rm -f /root/.bash_history /root/.lesshst /root/.wget-hsts
: >/etc/machine-id
rm -f /var/lib/dbus/machine-id

log "clearing logs and caches"
journalctl --rotate >/dev/null 2>&1 || true
journalctl --vacuum-time=1s >/dev/null 2>&1 || true
find /var/log -type f -exec truncate -s 0 {} + 2>/dev/null || true
apt-get -y autoremove >/dev/null 2>&1 || true
apt-get -y clean >/dev/null 2>&1 || true
rm -rf /tmp/* /var/tmp/*

# cloud-init must treat the customer's machine as new, so per-instance/
# (keenrig-firstboot.sh) runs there.
cloud-init clean --logs >/dev/null 2>&1 || true

[ -z "$(ls -A "$BASE/instance")" ] || die "$BASE/instance is not empty"
log "done - power off and snapshot now"
