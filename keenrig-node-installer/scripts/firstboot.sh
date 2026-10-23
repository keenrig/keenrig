#!/bin/sh
# Keenrig — first boot of a marketplace image (Vultr, DigitalOcean) or the last
# step of a scripted install (Linode StackScript).
#
#   Snapshot images: installed as /var/lib/cloud/scripts/per-instance/keenrig-firstboot.sh,
#                    so cloud-init runs it ONCE per new machine.
#   StackScript:     run right after `get.sh`.
#
# What it does, in order:
#   1. waits for keenrig-box (which creates a FRESH instance/ — master.key,
#      platform.db, setup token — because marketplace/cleanup.sh emptied it);
#   2. writes the Admin address + setup token to /root/keenrig-setup.txt (0600)
#      and installs a login message, so a user who opens the provider's web
#      console sees where to go without knowing about journalctl;
#   3. sends ONE request to get.keenrig.com/ping?src=<marketplace>&v=<version>,
#      nothing else in it. Disclosed on keenrig.com/privacy. Opt out by creating
#      /etc/keenrig/no-ping before first boot, or KEENRIG_NO_PING=1.
#
# POSIX sh, like get.sh. Never exits non-zero for a soft failure: a failed ping
# or a slow box must not make cloud-init mark the whole boot as failed.

set -u

BASE="${KEENRIG_BASE:-/var/lib/keenrig}"
ETC=/etc/keenrig
SETUP_FILE=/root/keenrig-setup.txt
PING_URL="${KEENRIG_PING_URL:-https://get.keenrig.com/ping}"
MOTD=/etc/update-motd.d/99-keenrig

log() { echo "keenrig-firstboot: $*"; }

[ "$(id -u)" -eq 0 ] || { echo "keenrig-firstboot: must run as root" >&2; exit 1; }
mkdir -p "$ETC"

# The marketplace name, written into the image at build time. Only [a-z0-9-],
# because it ends up in a URL and a log line.
src="$(tr -cd 'a-z0-9-' <"$ETC/install-source" 2>/dev/null | cut -c1-32)"
[ -n "$src" ] || src=unknown

# --- 1. wait for the box -------------------------------------------------------
systemctl start keenrig-box.service keenrig-agent.service keenrig-ota.service 2>/dev/null || true
i=0
until curl -fsS --max-time 2 http://127.0.0.1:8080/healthz >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -ge 120 ]; then
		log "keenrig-box did not answer within 120s - see: journalctl -u keenrig-box -n 50"
		break
	fi
	sleep 1
done

# --- 2. where to go, and the token -------------------------------------------
# First public IPv4. On DigitalOcean `hostname -I` also lists the 10.x anchor
# IP, and the order is not guaranteed — so skip private ranges explicitly.
public_ip() {
	for a in $(hostname -I 2>/dev/null); do
		case "$a" in
		*:*) continue ;;
		10.* | 127.* | 169.254.* | 192.168.*) continue ;;
		172.1[6-9].* | 172.2[0-9].* | 172.3[0-1].*) continue ;;
		esac
		echo "$a"
		return
	done
	hostname -I 2>/dev/null | awk '{print $1}'
}
ip="$(public_ip)"
url="http://${ip:-<server-ip>}/"
echo "$url" >"$ETC/admin-url"

# The box logs the token exactly once, when it creates it (authz.LoadOrCreateBootstrap).
token="$(journalctl -u keenrig-box --no-pager -o cat 2>/dev/null |
	sed -n 's/.*setup token (shown only once): //p' | tail -n 1)"

umask 077
cat >"$SETUP_FILE" <<EOF

  Keenrig is installed.

  1. Open  $url  in your browser.
  2. Create the owner account on the first screen.
     Do it now: until an owner exists, the first person to open that
     address can create it.

  Setup token (API only, not needed in the browser): ${token:-not found - journalctl -u keenrig-box | grep 'setup token'}
  Help: https://keenrig.com/en/docs/install   ·   hello@keenrig.com

EOF
umask 022

# Login message: shows the steps while no owner exists, a one-liner after.
cat >"$MOTD" <<'EOF'
#!/bin/sh
url="$(cat /etc/keenrig/admin-url 2>/dev/null)"
if curl -fsS --max-time 2 http://127.0.0.1:8080/api/v1/auth/setup 2>/dev/null | grep -q '"needs_setup":true'; then
	cat /root/keenrig-setup.txt 2>/dev/null
else
	echo
	echo "  Keenrig Admin: ${url:-http://<server-ip>/}"
	echo
fi
EOF
chmod 0755 "$MOTD"

# --- 3. one ping, once ---------------------------------------------------------
if [ "${KEENRIG_NO_PING:-0}" != "1" ] && [ ! -e "$ETC/no-ping" ] && [ ! -e "$ETC/.pinged" ]; then
	ver="$(tr -cd '0-9A-Za-z.+-' <"$BASE/node/VERSION" 2>/dev/null | cut -c1-32)"
	if curl -fsS --max-time 5 -o /dev/null "$PING_URL?src=$src&v=${ver:-unknown}" 2>/dev/null; then
		: >"$ETC/.pinged"
	fi
fi

log "done - $url"
exit 0
