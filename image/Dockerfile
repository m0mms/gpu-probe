FROM docker.io/library/debian@sha256:ec31d744f83f4a73447ba045aaab9409997efe5cc706eca4890c1be36cc1606a
RUN set -eu; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; \
    printf "%s\n" "deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://snapshot.debian.org/archive/debian/20261021T000000Z/ bookworm main" "deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://snapshot.debian.org/archive/debian-security/20261021T000000Z/ bookworm-security main" > /etc/apt/sources.list; \
    printf "#!/bin/sh\nexit 101\n" > /usr/sbin/policy-rc.d; chmod 0755 /usr/sbin/policy-rc.d; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3=3.11.2-1+b1 openssh-server=1:9.2p1-2+deb12u10 passwd=1:4.13+dfsg1-1+deb12u2; \
    rm -f /etc/ssh/ssh_host_*; \
    rm -rf /var/lib/apt/lists/*; \
    useradd --uid 10001 --user-group --no-create-home --home-dir /nonexistent --shell /bin/sh --password "*" gpu-probe; \
    install -d -m 0755 /etc/gpu-paid-worker /run/sshd /opt/gpu-probe; \
    dpkg-query -W > /opt/gpu-probe/packages.txt
COPY --chown=0:0 --chmod=0644 context/opt/gpu-probe/paid_probe/__init__.py /opt/gpu-probe/paid_probe/__init__.py
COPY --chown=0:0 --chmod=0644 context/opt/gpu-probe/paid_probe/capability_worker.py /opt/gpu-probe/paid_probe/capability_worker.py
COPY --chown=0:0 --chmod=0644 context/opt/gpu-probe/paid_probe/protocol.py /opt/gpu-probe/paid_probe/protocol.py
COPY --chown=0:0 --chmod=0644 context/opt/gpu-probe/paid_probe/worker_probe.py /opt/gpu-probe/paid_probe/worker_probe.py
COPY --chown=0:0 --chmod=0644 context/opt/gpu-probe/entry.py /opt/gpu-probe/entry.py
COPY --chown=0:0 --chmod=0644 context/opt/gpu-probe/startup.py /opt/gpu-probe/startup.py
COPY --chown=0:0 --chmod=0644 context/opt/gpu-probe/registration_input.py /opt/gpu-probe/registration_input.py
COPY --chown=0:0 --chmod=0644 context/opt/gpu-probe/identity.py /opt/gpu-probe/identity.py
COPY --chown=0:0 --chmod=0755 context/usr/local/libexec/gpu-paid-worker /usr/local/libexec/gpu-paid-worker
COPY --chown=0:0 --chmod=0644 context/etc/ssh/sshd_config_probe /etc/ssh/sshd_config_probe
EXPOSE 22
ENTRYPOINT ["/usr/bin/python3", "-I", "-S", "-B", "-c", "import sys,runpy; sys.path.insert(0, '/opt/gpu-probe'); runpy.run_path('/opt/gpu-probe/startup.py', run_name='__main__')"]
CMD []

RUN chmod 0755 /opt/gpu-probe/paid_probe

COPY --chown=0:0 --chmod=0644 notices/ /usr/share/doc/gpu-probe/
