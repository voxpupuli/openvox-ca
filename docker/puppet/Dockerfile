# OpenVox Server (JVM-based) image for the openvox-ca integration test stack.
#
# Installs OpenVox Server 8 + PuppetDB terminus from the official Vox Pupuli
# repository.  The built-in Puppet CA is disabled; the Go openvox-ca service
# handles all certificate operations.
#
# The entrypoint.sh bootstraps TLS certificates from the Go CA, configures
# webserver.conf and puppet.conf, then starts `puppetserver foreground`.

FROM quay.io/centos/centos:stream10

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
RUN mkdir -p /etc/puppetlabs/puppet/ssl && \
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
USER puppet

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
