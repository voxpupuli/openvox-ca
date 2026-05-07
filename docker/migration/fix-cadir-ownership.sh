#!/bin/bash
# Pre-default OpenVox Server entrypoint hook for the migration test.
#
# The compose-migration.yml stack mounts a podman named volume at
# /etc/puppetlabs/puppetserver/ca so the test-runner can read the CA bundle
# the JVM produces.  A fresh named volume is owned by container UID 0
# (host UID 1000 in rootless mode) with mode 0755, which means the
# unprivileged `puppet` user that puppetserver drops to cannot create files
# in its own CA directory.  90-ca.sh succeeds because it runs as root, but
# the JVM init aborts with "Parent directory ... is not writable".
#
# Fix: chown the mount-point itself to puppet:puppet (UID 999) and tighten
# the mode before any of the bundled /container-entrypoint.d/* scripts run.
# This script is invoked from /container-custom-entrypoint.d/pre-default/
# (see container-entrypoint.sh: run_custom_handler pre-default).

set -euo pipefail

CADIR=/etc/puppetlabs/puppetserver/ca

if [ -d "$CADIR" ]; then
    chown -R puppet:puppet "$CADIR"
    chmod 0750 "$CADIR"
fi
