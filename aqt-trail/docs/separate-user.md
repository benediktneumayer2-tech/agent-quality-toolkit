# Separate-user mode

In the default user mode the writer runs as you, so an agent running as you can edit the log or use the service
key. Tampering is still detected through anchors and pinned keys, but not prevented. Separate-user mode moves the
log and the key to a system user the agents cannot become.

**Requirement:** the service runs as the user `aqt-trail` with `ProtectHome=true`, so it cannot start an
`aqt-trail` installed in a home folder (also not one whose Python lives there, as uv-managed Pythons do). Install
`aqt-spec` and `aqt-trail` into a virtual environment outside `/home`, readable by every user, for example:

```sh
sudo python3 -m venv /opt/aqt
sudo /opt/aqt/bin/pip install ./aqt-spec ./aqt-trail      # from the repository root
sudo sh aqt-trail/scripts/setup-system-user.sh /opt/aqt/bin/aqt-trail
```

The script (read it first; it is never run by the tests) refuses a home-folder installation, then:

1. creates the system user `aqt-trail` and the group `aqt-trail-clients`, and adds you to the group;
2. writes `/etc/aqt/trail.toml`: state `/var/lib/aqt-trail`, socket `/run/aqt-trail/trail.sock` with mode
   **0660** and group `aqt-trail-clients` (the documented exception to the suite's 0600 rule), log mode 0640,
   your uid in `allowed_uids`;
3. initialises the trail as `aqt-trail` (the service key stays 0600, readable only by that user);
4. installs [`examples/aqt-trail-system.service`](../examples/aqt-trail-system.service) as
   `/etc/systemd/system/aqt-trail.service` and starts it.

The unit runs with `Group=aqt-trail-clients`, so the runtime folder `/run/aqt-trail` (0750), the socket and the
log (0640) belong to the clients group: members can reach the socket and read the log, nobody else can.

Afterwards set `AQT_SINK=unix:/run/aqt-trail/trail.sock` for your tools and hooks. You can read and verify the
log (group read) but not change it. Records spooled while the writer was down stay in your own state directory;
`aqt-trail --config /etc/aqt/trail.toml drain` sends them through the socket, and the writer records the gap.

Limits: root, and anyone in a root-equivalent group such as `docker` or `sudo`, can still change anything.
Anchors (head copies on another device, RFC 3161 tokens) remain the guarantee for everything before their time.
