#!/bin/sh
# One-time setup of separate-user mode for aqt-trail. Run it yourself with sudo:
#
#   sudo sh scripts/setup-system-user.sh /path/to/aqt-trail
#
# It creates a system user `aqt-trail` that owns the log and the service key, a group
# `aqt-trail-clients` (you are added to it) that may append through the socket and read
# the log, and a systemd unit. Agents running as you can then append but can neither edit
# the log nor read the service key. Root and members of root-equivalent groups (docker,
# sudo) can still do anything: anchors remain the real guarantee. The test suite runs only
# the --check mode below, on temporary installations.
#
# /path/to/aqt-trail must belong to an installation outside /home and /root (for example a
# virtual environment under /opt): the service runs as aqt-trail with ProtectHome=true. The
# installation must also be root's alone: the console script, its interpreter, the virtual
# environment, the standard library and the aqt_trail and aqt_evidence packages (and every folder
# above them) must be owned by root and not writable by group or others, or an agent running as you
# could change the code the service runs as aqt-trail. The script refuses anything else.
#
#   sh scripts/setup-system-user.sh --check /path/to/aqt-trail
#
# runs only these checks and changes nothing (no sudo needed). --owner-uid UID (only with --check)
# also accepts files owned by UID; the tests use it on temporary installations.
set -eu

usage() { echo "usage: setup-system-user.sh [--check [--owner-uid UID]] /path/to/aqt-trail" >&2; exit 2; }
CHECK_ONLY=0
TRUSTED_UID=0
while [ $# -gt 0 ]; do
    case "$1" in
        --check) CHECK_ONLY=1; shift ;;
        --owner-uid) [ $# -ge 2 ] || usage; TRUSTED_UID=$2; shift 2 ;;
        --) shift; break ;;
        -*) usage ;;
        *) break ;;
    esac
done
[ $# -eq 1 ] || usage
case "$1" in /*) AQT_TRAIL_BIN=$1 ;; *) AQT_TRAIL_BIN=$(pwd)/$1 ;; esac
case "$TRUSTED_UID" in ''|*[!0-9]*) usage ;; esac
[ "$TRUSTED_UID" -eq 0 ] || [ "$CHECK_ONLY" -eq 1 ] || { echo "--owner-uid is only accepted with --check" >&2; exit 2; }

refuse() {
    echo "refused: $*" >&2
    echo "Install aqt-spec and aqt-trail as root into a virtual environment outside /home that only root" >&2
    echo "can change (e.g. sudo python3 -m venv /opt/aqt; sudo /opt/aqt/bin/pip install ./aqt-spec ./aqt-trail);" >&2
    echo "see docs/separate-user.md." >&2
    exit 2
}

# One path: owned by root (or the trusted uid) and not writable by group or others. A parent folder
# may instead be a root-owned sticky folder such as /tmp, whose entries others cannot replace.
check_one() {  # $1 path, $2 leaf|parent
    [ -e "$1" ] || refuse "$1 does not exist"
    owner=$(stat -L -c %u "$1")
    mode=$((0$(stat -L -c %a "$1")))
    if [ "$owner" -ne 0 ] && [ "$owner" -ne "$TRUSTED_UID" ]; then
        refuse "$1 is owned by uid $owner, not by root"
    fi
    if [ $((mode & 022)) -ne 0 ]; then
        if [ "$2" = parent ] && [ "$owner" -eq 0 ] && [ $((mode & 01000)) -ne 0 ]; then
            return 0
        fi
        refuse "$1 is writable by group or others (mode $(stat -L -c %a "$1"))"
    fi
}

# A path and every folder above it, for the path as given and as resolved.
check_path() {  # $1 path
    for target in "$1" "$(readlink -f "$1")"; do
        case "$target" in
            /home/*|/root/*|/run/user/*)
                refuse "$target is inside a home folder; the aqt-trail service (ProtectHome=true) cannot run it" ;;
        esac
        check_one "$target" leaf
        dir=$(dirname "$target")
        while :; do
            check_one "$dir" parent
            [ "$dir" = / ] && break
            dir=$(dirname "$dir")
        done
    done
}

# Everything below a folder (symlinks followed; broken ones ignored).
check_tree() {  # $1 folder
    check_path "$1"
    bad=$(find -L "$1" ! -type l \( \( ! -user 0 ! -user "$TRUSTED_UID" \) -o -perm /022 \) -print -quit 2>&1) \
        || refuse "cannot check $1 completely: $bad"
    [ -z "$bad" ] || refuse "$bad (below $1) is not owned by root or is writable by group or others"
}

[ -f "$AQT_TRAIL_BIN" ] || refuse "$AQT_TRAIL_BIN is not a file"
check_path "$AQT_TRAIL_BIN"
# The console script's interpreter (and the Python it links to) must be root's and reachable for the service.
INTERPRETER=$(sed -n '1s/^#![[:space:]]*\([^[:space:]]*\).*/\1/p' "$AQT_TRAIL_BIN")
case "$INTERPRETER" in /*) ;; *) refuse "$AQT_TRAIL_BIN has no #! line with an absolute interpreter path" ;; esac
check_path "$INTERPRETER"

# Where that Python loads code from. Checked only after the interpreter itself; as root the probe
# runs as nobody, so nothing from the installation runs as root before it is checked.
PROBE='import importlib.util, sys, sysconfig
paths = sysconfig.get_paths()
print(sys.prefix if sys.prefix != sys.base_prefix else paths["stdlib"])
for key in ("stdlib", "platstdlib", "purelib", "platlib"):
    print(paths[key])
for name in ("aqt_trail", "aqt_evidence"):
    spec = importlib.util.find_spec(name)
    print(spec.submodule_search_locations[0] if spec and spec.submodule_search_locations else "MISSING " + name)'
if [ "$(id -u)" -eq 0 ]; then
    LOCATIONS=$(cd / && runuser -u nobody -- "$INTERPRETER" -I -c "$PROBE") || refuse "$INTERPRETER cannot be run by another user"
else
    LOCATIONS=$(cd / && "$INTERPRETER" -I -c "$PROBE") || refuse "$INTERPRETER -I failed"
fi
while IFS= read -r location; do
    case "$location" in
        "MISSING "*) refuse "the interpreter of $AQT_TRAIL_BIN cannot find ${location#MISSING }" ;;
        /*) if [ -e "$location" ]; then check_tree "$location"; fi ;;
        *) refuse "unexpected probe output: $location" ;;
    esac
done <<LOCATIONS
$LOCATIONS
LOCATIONS
WHO="root's alone"; [ "$TRUSTED_UID" -eq 0 ] || WHO="root's or uid $TRUSTED_UID's"
echo "installation check passed: $AQT_TRAIL_BIN, $INTERPRETER and the code they load are $WHO"
[ "$CHECK_ONLY" -eq 0 ] || exit 0

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

install -m 0644 "$(dirname "$0")/../examples/aqt-trail-system.service" /etc/systemd/system/aqt-trail.service
systemctl daemon-reload
systemctl enable --now aqt-trail.service

cat <<DONE
Done. Log out and in again (group membership), then in your shell profile set:
  export AQT_SINK=unix:/run/aqt-trail/trail.sock
and use: aqt-trail --state /var/lib/aqt-trail --config /etc/aqt/trail.toml verify
Spooled records (written while the writer was down) stay in your own state directory;
send them with: aqt-trail --config /etc/aqt/trail.toml drain
DONE
