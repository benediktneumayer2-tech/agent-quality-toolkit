#!/bin/sh
# One-time setup of separate-user mode for aqt-trail. Run it yourself with sudo:
#
#   sudo sh scripts/setup-system-user.sh /path/to/aqt-trail
#
# It creates a system user `aqt-trail` that owns the log and the service key, a group
# `aqt-trail-clients` (you are added to it) that may append through the socket and read
# the log, and a systemd unit. Agents running as you can then append but can neither edit
# the log nor read the service key. Root and members of root-equivalent groups (docker,
# sudo) can still do anything: anchors remain the real guarantee. Nothing here is run by
# the test suite.
set -eu

AQT_TRAIL_BIN=${1:?usage: setup-system-user.sh /path/to/aqt-trail}
OWNER=${SUDO_USER:?run with sudo from your own account}
OWNER_UID=$(id -u "$OWNER")

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 2; }

getent group aqt-trail-clients >/dev/null || groupadd --system aqt-trail-clients
getent passwd aqt-trail >/dev/null || useradd --system --home-dir /var/lib/aqt-trail --shell /usr/sbin/nologin aqt-trail
usermod -a -G aqt-trail-clients "$OWNER"
usermod -a -G aqt-trail-clients aqt-trail

install -d -o aqt-trail -g aqt-trail-clients -m 0750 /var/lib/aqt-trail
install -d -o root -g root -m 0755 /etc/aqt
install -m 0755 "$AQT_TRAIL_BIN" /usr/local/bin/aqt-trail

cat > /etc/aqt/trail.toml <<CONF
[trail]
state = "/var/lib/aqt-trail"

[writer]
socket = "/run/aqt-trail/trail.sock"
socket_mode = "0660"
socket_group = "aqt-trail-clients"
log_mode = "0640"
allowed_uids = [$OWNER_UID]
CONF
chmod 0644 /etc/aqt/trail.toml

sudo -u aqt-trail XDG_CONFIG_HOME=/etc /usr/local/bin/aqt-trail init --config /etc/aqt/trail.toml
chmod 0750 /var/lib/aqt-trail
chgrp aqt-trail-clients /var/lib/aqt-trail /var/lib/aqt-trail/trail.json /var/lib/aqt-trail/keys
chmod 0640 /var/lib/aqt-trail/trail.json
chmod 0750 /var/lib/aqt-trail/keys
chgrp aqt-trail-clients /var/lib/aqt-trail/keys/service.key.pub

install -m 0644 "$(dirname "$0")/../examples/aqt-trail.service" /etc/systemd/system/aqt-trail.service
systemctl daemon-reload
systemctl enable --now aqt-trail.service

cat <<DONE
Done. Log out and in again (group membership), then in your shell profile set:
  export AQT_SINK=unix:/run/aqt-trail/trail.sock
and use: aqt-trail --state /var/lib/aqt-trail --config /etc/aqt/trail.toml verify
Spooled records (written while the writer was down) stay in your own state directory;
send them with: aqt-trail --config /etc/aqt/trail.toml drain
DONE
