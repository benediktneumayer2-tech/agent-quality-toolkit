# The sshd of scripts/e2e-ssh.sh: AQT installed from this clone, four users, fixture data for one. Throw-away.
#   tester  AQT only in ~/.local/bin, as the install leaves it (not on the PATH of an SSH command); fixture data
#   pathy   aqt on the PATH of SSH commands (~/.ssh/environment)
#   qt      another program named aqt first on PATH (aqtinstall's), AQT as aqt-toolkit
#   bare    no AQT
FROM python:3.12-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-server procps >/dev/null \
    && rm -rf /var/lib/apt/lists/*
COPY src /src
RUN python -m venv /opt/aqt && /opt/aqt/bin/pip install -q --no-cache-dir "/src/aqt-spec[schema]" /src/aqt-trail \
    /src/aqt-signoff /src/aqt-change /src/aqt-sensei /src/aqt-quarantine /src/aqt-validate /src/aqt-capa /src/aqt-ui /src/aqt-cli
COPY authorized_keys host_ed25519 host_ed25519.pub fixture.py /setup/
RUN set -e; mkdir -p /run/sshd; \
    install -m 600 /setup/host_ed25519 /etc/ssh/ssh_host_ed25519_key; \
    install -m 644 /setup/host_ed25519.pub /etc/ssh/ssh_host_ed25519_key.pub; \
    printf 'Port 22\nHostKey /etc/ssh/ssh_host_ed25519_key\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nPermitUserEnvironment yes\nUsePAM no\n' \
        > /etc/ssh/sshd_config; \
    for u in tester pathy qt bare; do useradd -m -s /bin/bash $u; usermod -p '*' $u; \
      install -d -m 700 -o $u -g $u /home/$u/.ssh; install -m 600 -o $u -g $u /setup/authorized_keys /home/$u/.ssh/authorized_keys; done; \
    install -d -o tester -g tester /home/tester/.local /home/tester/.local/bin; \
    ln -s /opt/aqt/bin/aqt /home/tester/.local/bin/aqt; ln -s /opt/aqt/bin/aqt-toolkit /home/tester/.local/bin/aqt-toolkit; \
    echo 'PATH=/opt/aqt/bin:/usr/bin:/bin' > /home/pathy/.ssh/environment; chown pathy:pathy /home/pathy/.ssh/environment; \
    install -d -o qt -g qt /home/qt/bin; ln -s /opt/aqt/bin/aqt-toolkit /home/qt/bin/aqt-toolkit; \
    printf '#!/bin/sh\necho "aqtinstall(aqt) v3.1.21 on Python 3.12.3"\n' > /home/qt/bin/aqt; chmod 755 /home/qt/bin/aqt; \
    echo 'PATH=/home/qt/bin:/usr/bin:/bin' > /home/qt/.ssh/environment; chown qt:qt /home/qt/.ssh/environment; \
    runuser -u tester -- /opt/aqt/bin/python /setup/fixture.py init
# the tester's audit-trail writer in the background, sshd in the foreground
CMD ["/bin/sh", "-c", "runuser -u tester -- /opt/aqt/bin/aqt-trail serve >/tmp/writer.log 2>&1 & exec /usr/sbin/sshd -D -e"]
