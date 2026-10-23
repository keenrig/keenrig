#!/bin/sh
# keenrig tunnel — publish a box that has no public IP.
#
# The box runs cloudflared, which opens an OUTBOUND connection to Cloudflare and
# gets a public hostname back. This script reports that hostname to the control
# plane, which then forwards visitors of `admin.<parent-domain>` into it.
#
# WHY THE HOSTNAME IS REPORTED AND NOT CONFIGURED: a quick tunnel gets a NEW
# random hostname every time cloudflared starts. Nothing can be written down
# ahead of time - the only source of truth is what cloudflared just printed.
#
# WHY IT KEEPS REPORTING: the control plane refuses to forward into a tunnel
# that has gone quiet (StaleAfter, 5 minutes, in Keenrig Cloud (forwarder)),
# because a dead hostname makes requests hang until they time out, and "the
# page never loads" is a worse answer than a clear error. This heartbeat is
# what tells it the tunnel is still alive.
#
# WHY FAILURES ARE LOGGED: on 2026-09-07 admin on a test box answered 502 to every
# visitor while `journalctl -u keenrig-tunnel` showed nothing but "published
# at ...". The heartbeat had been failing for a long time and the old
# `curl ... || true` swallowed every failure. cloudflared alive + box healthy +
# control plane refusing to forward is a state nobody can see from the box
# unless this script says so. So a failed heartbeat now logs ONE line when its
# state changes (key refused / HTTP 5xx / cannot reach), one line when it
# recovers, and nothing in between - the same no-log-spam discipline the agent
# keeps under AG-08/AG-09.
#
# Environment (systemd passes it in from /etc/keenrig/agent.env, root-only 0600):
#   KEENRIG_CLOUD_URL   control plane, e.g. https://console.keenrig.com
#   KEENRIG_AGENT_KEY   this environment's API key
#   KEENRIG_TUNNEL_TARGET  what to publish (default the Admin UI on loopback)
#   KEENRIG_TUNNEL_REPORT_SECONDS  heartbeat cadence while healthy (default 60)
#   KEENRIG_TUNNEL_RETRY_SECONDS   cadence after a FAILED heartbeat (default 10)

set -eu

CLOUD="${KEENRIG_CLOUD_URL:-}"
KEY="${KEENRIG_AGENT_KEY:-}"
BASE="${KEENRIG_BASE:-/var/lib/keenrig}"
TARGET="${KEENRIG_TUNNEL_TARGET:-http://127.0.0.1:8080}"
CLOUDFLARED="${KEENRIG_CLOUDFLARED:-$BASE/bin/cloudflared}"
REPORT_EVERY="${KEENRIG_TUNNEL_REPORT_SECONDS:-60}"
# After a FAILED heartbeat the next attempt comes sooner. StaleAfter on the
# cloud is 5 minutes; at the 60s cadence one transient miss has already spent
# a fifth of that budget, and two misses in a row on a flapping link are
# ordinary. 10s turns "five chances before visitors see an error" into thirty.
RETRY_EVERY="${KEENRIG_TUNNEL_RETRY_SECONDS:-10}"

log() { echo "keenrig-tunnel: $*"; }
die() { echo "keenrig-tunnel: ERROR: $*" >&2; exit 1; }

[ -n "$CLOUD" ] || die "KEENRIG_CLOUD_URL is not set - this box is not joined to a control plane"
[ -n "$KEY" ] || die "KEENRIG_AGENT_KEY is not set"
[ -x "$CLOUDFLARED" ] || die "$CLOUDFLARED is missing or not executable"

# Heartbeat state, shared with the loop below. FAILS counts consecutive failed
# attempts (0 = healthy). LAST_FAIL is the failure the last log line described:
# a failure that keeps repeating stays silent, and only a CHANGE (401 -> 503,
# 503 -> cannot reach) earns a new line.
FAILS=0
LAST_FAIL=""

# report sends the current hostname up. An EMPTY value means "no tunnel any
# more", and sending it on shutdown is the point: it turns a stale forward into
# an immediate, explainable error instead of a hang.
#
# Returns 0 on a 2xx and 1 on anything else - and says WHY, once per change of
# state. Callers must tolerate the 1 (`report ... || true`): under `set -e` a
# bare call would take the whole script down on the first flapping link.
report() {
	code="$(curl -s -m 20 -o /dev/null -w '%{http_code}' \
		-H "Authorization: Bearer $KEY" \
		-H 'Content-Type: application/json' \
		-d "{\"url\":\"${1:-}\"}" \
		"$CLOUD/agent/v1/tunnel" 2>/dev/null)" && rc=0 || rc=$?

	if [ "$rc" -ne 0 ]; then
		# No answer at all: DNS (6), refused (7), timeout (28), TLS (35/60).
		# Only curl's exit code tells them apart, so it goes into the line.
		why="could not reach $CLOUD (curl exit $rc)"
	else
		case "$code" in
		2??)
			if [ "$FAILS" -gt 0 ]; then
				log "heartbeat restored after $FAILS failed attempts"
			fi
			FAILS=0
			LAST_FAIL=""
			return 0
			;;
		401 | 403)
			# The key this box holds is not the key the control plane knows:
			# revoked, or the environment was re-joined from another machine.
			# No amount of retrying fixes that - a person has to.
			why="rejected by $CLOUD (HTTP $code) - the agent key was refused; re-join this box from the Console"
			;;
		*)
			why="failed (HTTP $code)"
			;;
		esac
	fi
	FAILS=$((FAILS + 1))
	if [ "$why" != "$LAST_FAIL" ]; then
		log "heartbeat $why"
		LAST_FAIL="$why"
	fi
	return 1
}

LOG="$(mktemp)"
"$CLOUDFLARED" tunnel --no-autoupdate --url "$TARGET" >"$LOG" 2>&1 &
CF=$!

cleanup() {
	kill "$CF" 2>/dev/null || true
	# Best-effort, no retry: the unit is going down and systemd brings a new
	# one up in seconds. If this fails it says so (once), and the cloud still
	# stops forwarding on its own after StaleAfter.
	report "" || true
	rm -f "$LOG"
}
trap cleanup EXIT INT TERM

# Wait for the hostname. cloudflared prints it once, a second or two after the
# tunnel registers.
URL=""
i=0
while [ "$i" -lt 90 ]; do
	URL="$(grep -oE 'https://[a-z0-9][a-z0-9-]*\.trycloudflare\.com' "$LOG" 2>/dev/null | head -1 || true)"
	[ -n "$URL" ] && break
	# cloudflared died before printing anything: fail loudly instead of waiting
	# out the full timeout for a process that is already gone.
	kill -0 "$CF" 2>/dev/null || {
		log "cloudflared exited before publishing a hostname:"
		tail -5 "$LOG" >&2
		exit 1
	}
	sleep 1
	i=$((i + 1))
done
[ -n "$URL" ] || die "no tunnel hostname after 90s"

log "published at $URL -> $TARGET"
report "$URL" || true

# Heartbeat for as long as cloudflared lives. When it dies this loop ends, the
# trap clears the hostname, and systemd restarts the unit - which gets a NEW
# hostname and reports that one.
#
# While the last heartbeat failed the wait is RETRY_EVERY, not REPORT_EVERY:
# the cloud's StaleAfter clock is already running, and a 60s pause after a miss
# hands a fifth of it to a failure that may be over in a second.
while kill -0 "$CF" 2>/dev/null; do
	if [ "$FAILS" -eq 0 ]; then
		sleep "$REPORT_EVERY"
	else
		sleep "$RETRY_EVERY"
	fi
	report "$URL" || true
done
log "cloudflared exited"
