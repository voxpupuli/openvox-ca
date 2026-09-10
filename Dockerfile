# ---- Build Stage ----
FROM quay.io/centos/centos:stream10 AS builder

RUN dnf install -y golang git && dnf clean all

WORKDIR /src
COPY go.mod go.sum ./
# GOTOOLCHAIN=auto lets Go download the exact version required by go.mod
# (the distro-packaged Go bootstraps the download).
RUN GOTOOLCHAIN=auto go mod download

COPY . .
ENV GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux
RUN go build -ldflags="-s -w" -o /openvox-ca     ./cmd/openvox-ca/ && \
    go build -ldflags="-s -w" -o /openvox-ca-ctl ./cmd/openvox-ca-ctl/

# ---- Runtime Stage ----
FROM quay.io/centos/centos:stream10

# curl: the healthcheck in this repository's compose.yml runs
#   `curl -skf https://localhost:8140/healthz/ready` inside this container, with
#   a busybox-wget fallback that only exists in the -alpine variant. stream10
#   ships no wget, so curl is what makes that example work. It is declared
#   rather than left to the base even though curl-minimal is currently part of
#   it: a dependency satisfied only by what the base happens to include is the
#   failure mode that #316 exists to stop repeating.
#
# openssl is NOT installed. It was here for CSR generation and certificate
# inspection in the integration suites, which do not run in this image -- they
# run in the one built from test/Dockerfile.run, which now declares it. The
# binaries are built CGO_ENABLED=0 and link no OpenSSL; nothing in this image
# invokes the command. Removing it is the point of #316: the published image
# should carry what openvox-ca needs to run, so that a future change of base
# (#292) is not also a negotiation with the test suites.
#
# The puppet uid/gid is pinned to 1000 rather than left to useradd's first-free
# allocation: `USER` below has to be numeric so a host that cannot read the
# image's /etc/passwd -- Kubernetes checking `runAsNonRoot`, or an operator
# matching ownership on a bind mount -- can still tell who the process runs as.
# 1000 is what useradd picks today, so the runtime identity is unchanged.
# Both assertions below must be re-verified by hand when edited -- CI only ever
# takes their passing branch. See docs/development/testing.md, "Container
# identity guards", for the mutations and the messages they should produce.
RUN dnf install -y curl && dnf clean all && \
    groupadd -g 1000 puppet && \
    useradd -m -u 1000 -g 1000 puppet && \
    { [ "$(id -u puppet):$(id -g puppet)" = "1000:1000" ] || \
        { echo "puppet is $(id -u puppet):$(id -g puppet), not 1000:1000; USER below must match" >&2; exit 1; }; } && \
    mkdir -p /etc/puppetlabs/puppet/ssl/ca /data && \
    chown -R puppet:puppet /etc/puppetlabs/puppet /data && \
    for d in /etc/puppetlabs/puppet/ssl/ca /data; do \
        [ "$(stat -c %u:%g "$d")" = "1000:1000" ] || \
            { echo "$d is owned by $(stat -c %u:%g "$d"), not 1000:1000; the CA could not write there" >&2; exit 1; }; \
    done

COPY --from=builder /openvox-ca     /usr/local/bin/openvox-ca
COPY --from=builder /openvox-ca-ctl /usr/local/bin/openvox-ca-ctl

USER 1000:1000
EXPOSE 8140

# --cadir             : where CA state is stored
# --verbosity         : debug logging
#
# NOTE: autosign is OFF by default. Set --autosign-config=true only in
# dev/test environments. Autosign lets any CSR submitter obtain a signed
# certificate without operator review.
ENTRYPOINT ["/usr/local/bin/openvox-ca"]
CMD ["--cadir=/etc/puppetlabs/puppet/ssl/ca", \
     "--verbosity=1"]
