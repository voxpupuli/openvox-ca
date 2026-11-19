# OpenVox Server (JVM-based) image for the openvox-ca integration test stack.
#
# Installs OpenVox Server 8 + PuppetDB terminus from the official Vox Pupuli
# repository.  The built-in Puppet CA is disabled; the Go openvox-ca service
# handles all certificate operations.
#
# The entrypoint.sh bootstraps TLS certificates from the Go CA, configures
# webserver.conf and puppet.conf, then starts `puppetserver foreground`.

FROM registry.access.redhat.com/ubi10/ubi:10.3@sha256:73ea54bfbfb586075bd3d45df6483a7f68875233c8cc7cebcf9b2bb42306c308

# Install OpenVox Server + PuppetDB terminus + runtime tools.
RUN dnf -y install https://yum.voxpupuli.org/openvox8-release-el-10.noarch.rpm && \
    dnf -y install openvox-server openvoxdb-termini curl openssl util-linux-user && \
    dnf clean all

# Lower the default JVM heap for the integration test environment.
RUN echo 'JAVA_ARGS="-Xms512m -Xmx512m -XX:ReservedCodeCacheSize=512m"' \
        >> /etc/sysconfig/puppetserver

ENV PATH=/opt/puppetlabs/server/bin:/opt/puppetlabs/puppet/bin:${PATH}

# Give puppet ownership of config and SSL dirs so the entrypoint can write
# puppet.conf, webserver.conf, ca.cfg, etc. as non-root.
#
# The `puppet` user here is created by the openvox-server package, not by us,
# so we cannot choose its ids -- but `USER` below has to be numeric for the
# host to resolve it.  Assert the package's allocation instead, so that a
# future openvox-server which moves it fails the build here rather than
# silently running the server under an identity that owns none of these
# directories.  Supplementary groups are part of the assertion because the
# numeric `USER` form does not carry them the way the name form does: the
# runtime collects them by walking /etc/group for the named user, and a
# uid:gid pair skips that walk.
#
# Re-verify by hand when editing this -- CI only ever takes the passing branch.
# See docs/development/testing.md, "Container identity guards"; mutate the image
# rather than `expected`, or the check proves only that the comparison runs.
RUN expected="52:52:52"; actual="$(id -u puppet):$(id -g puppet):$(id -G puppet)"; \
    [ "$actual" = "$expected" ] || { \
        echo "openvox-server puppet uid:gid:groups is $actual, not $expected." >&2; \
        echo "If the uid or gid moved, update expected above and USER below to match." >&2; \
        echo "If the extra ids are supplementary groups, USER cannot carry them --" >&2; \
        echo "add group_add: to the compose services that run this image instead." >&2; \
        exit 1; \
    } && \
    mkdir -p /etc/puppetlabs/puppet/ssl && \
    chown -R puppet:puppet \
        /etc/puppetlabs/puppet \
        /etc/puppetlabs/puppetserver/conf.d \
        /etc/puppetlabs/puppetserver/services.d

# Copy bootstrap + startup entrypoint.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 8140

# SECURITY: Run as non-root to limit blast radius of container escape.
# NIST 800-53: AC-6 (Least Privilege), CM-7 (Least Functionality)
#
# 52:52 is the openvox-server package's `puppet` user, asserted above.
USER 52:52

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
