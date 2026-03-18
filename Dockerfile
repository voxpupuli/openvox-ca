# ---- Build Stage ----
FROM quay.io/centos/centos:stream10 AS builder

RUN dnf install -y golang git && dnf clean all

WORKDIR /src
COPY go.mod go.sum ./
# GOTOOLCHAIN=auto lets Go download the exact version required by go.mod
# (the distro-packaged Go bootstraps the download).
RUN GOTOOLCHAIN=auto go mod download

COPY . .
RUN GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-s -w" -o /puppet-ca     ./cmd/puppet-ca/ && \
    go build -ldflags="-s -w" -o /puppet-ca-ctl ./cmd/puppet-ca-ctl/

# ---- Runtime Stage ----
FROM quay.io/centos/centos:stream10

# curl: health checks and agent CSR submission
# openssl: CSR generation and cert verification in integration tests
RUN dnf install -y curl openssl && dnf clean all && \
    useradd -m puppet && \
    mkdir -p /etc/puppetlabs/puppet/ssl/ca /data && \
    chown -R puppet:puppet /etc/puppetlabs/puppet /data

COPY --from=builder /puppet-ca     /usr/local/bin/puppet-ca
COPY --from=builder /puppet-ca-ctl /usr/local/bin/puppet-ca-ctl

USER puppet
EXPOSE 8140

# --cadir             : where CA state is stored
# --verbosity         : debug logging
#
# NOTE: autosign is OFF by default. Set --autosign-config=true only in
# dev/test environments — autosign lets any CSR submitter obtain a signed
# certificate without operator review.
ENTRYPOINT ["/usr/local/bin/puppet-ca"]
CMD ["--cadir=/etc/puppetlabs/puppet/ssl/ca", \
     "--verbosity=1"]
