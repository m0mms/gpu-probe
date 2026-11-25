set -eu
python -B /control/resource_guard.py
sha256sum /usr/sbin/policy-rc.d > /tmp/policy.before
cp /var/lib/dpkg/status /tmp/status.before
mv /usr/sbin/policy-rc.d /usr/sbin/policy-rc.d.cdma-saved
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d
export DEBIAN_FRONTEND=noninteractive
dpkg --install /inputs/*.deb
dpkg --audit
rm -f /etc/ssh/ssh_host_*
rm /usr/sbin/policy-rc.d
mv /usr/sbin/policy-rc.d.cdma-saved /usr/sbin/policy-rc.d
sha256sum -c /tmp/policy.before
test -x /usr/sbin/sshd
test -x /usr/bin/ssh-keygen
test -x /usr/bin/rsync
test ! -e /etc/ssh/sky_host_ed25519
test ! -e /etc/ssh/sky_authorized_keys
mkdir -p /run/sshd
ssh-keygen -q -t ed25519 -N '' -f /tmp/test_host
/usr/sbin/sshd -T -o HostKey=/tmp/test_host -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o PermitRootLogin=prohibit-password -o AllowTcpForwarding=no -o X11Forwarding=no > /tmp/sshd-effective
cat /tmp/sshd-effective
rsync --version
pgrep -x sshd && exit 99 || test "$?" = 1
rm -f /tmp/test_host /tmp/test_host.pub
printf '\nCDMA_PACKAGES_BEGIN\n'
dpkg-query -W -f='${binary:Package} ${Version}\n'
printf 'CDMA_PACKAGES_END\n'
