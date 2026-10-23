#!/bin/bash
# Keenrig — Akamai / Linode Marketplace StackScript.
#
# Linode runs this when the customer creates the machine, so there is no shared
# snapshot: every machine runs the real installer and gets its own identity.
# The Linode team may ask for it to be wrapped in their Ansible layout
# (marketplace-apps repo) during review — the three steps stay the same.
#
# No UDF fields: Keenrig needs no domain or account to start; the owner is
# created in the browser.

set -euo pipefail
exec > >(tee -a /var/log/keenrig-stackscript.log) 2>&1

CHANNEL=stable

# 1. the same installer everyone uses
curl -fsSL https://get.keenrig.com | sh -s -- --channel "$CHANNEL" --auto-upgrade

# 2. tag the source for the one first-boot ping (see keenrig.com/privacy)
mkdir -p /etc/keenrig
echo linode >/etc/keenrig/install-source

# 3. login message + /root/keenrig-setup.txt + ping
curl -fsSL "https://get.keenrig.com/dl/$CHANNEL/scripts/firstboot.sh" -o /usr/local/sbin/keenrig-firstboot
chmod 0755 /usr/local/sbin/keenrig-firstboot
/usr/local/sbin/keenrig-firstboot
