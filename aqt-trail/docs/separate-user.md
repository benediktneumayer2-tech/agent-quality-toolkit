# Separate-user mode

In the default user mode the writer runs as you, so an agent running as you can edit the log or use the service
key. Tampering is still detected through anchors and pinned keys, but not prevented. Separate-user mode moves the
log and the key to a system user the agents cannot become.

```sh
sudo sh scripts/setup-system-user.sh "$(command -v aqt-trail)"
```

The script (read it first; it is never run by the tests):

1. creates the system user `aqt-trail` and the group `aqt-trail-clients`, and adds you to the group;
2. writes `/etc/aqt/trail.toml`: state `/var/lib/aqt-trail`, socket `/run/aqt-trail/trail.sock` with mode
   **0660** and group `aqt-trail-clients` (the documented exception to the suite's 0600 rule), log mode 0640,
   your uid in `allowed_uids`;
3. initialises the trail as `aqt-trail` (the service key stays 0600, readable only by that user);
4. installs and starts `examples/aqt-trail.service`.

Afterwards set `AQT_SINK=unix:/run/aqt-trail/trail.sock` for your tools and hooks. You can read and verify the
log (group read) but not change it. Records spooled while the writer was down stay in your own state directory;
`aqt-trail --config /etc/aqt/trail.toml drain` sends them through the socket, and the writer records the gap.

Limits: root, and anyone in a root-equivalent group such as `docker` or `sudo`, can still change anything.
Anchors (head copies on another device, RFC 3161 tokens) remain the guarantee for everything before their time.
