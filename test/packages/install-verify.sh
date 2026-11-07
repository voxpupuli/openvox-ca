#!/bin/bash
# Install-and-verify for the deb and rpm packages (openvox-ca#254).
#
#   test/packages/install-verify.sh deb|rpm <dist-dir>
#
# <dist-dir> holds what `mage build:packages` wrote, and <dist-dir>/upgrade
# what test/packages/build-upgrade.sh wrote. The package for the container
# engine's own architecture is the one installed, so CI runs this once per
# format on an amd64 and an arm64 runner.
#
# A package that installs cleanly and produces a CA nothing can talk to looks
# exactly like a working one, so this installs each package into a container
# booted with systemd as PID 1 and judges it from the installed state: it
# starts the units, talks TLS to the CA through the certificate the package
# linked, takes over a CA placed before install, upgrades, removes and purges.
# systemd has to be PID 1 because almost everything that matters here -- the
# first-boot oneshot, deb-systemd-invoke and policy-rc.d, presets,
# record-environment -- happens only under a running systemd.
#
# Each scenario gets a fresh container from one image per format. The image
# holds systemd and the tools the assertions use, and installs none of the
# packages' own dependencies, so one that the base image lacks and
# packaging/nfpm.yaml forgot fails the install here rather than on an
# operator's host. That covers only what the base lacks: ucf on Debian,
# hostname on EL, which the main scenario asserts are absent before it
# installs. passwd, shadow-utils and Debian's hostname are in the base images,
# so a dependency on them dropped from nfpm.yaml would pass here unnoticed.
#
# Needs docker able to run --privileged containers, which GitHub's runners and
# Docker Desktop both can. CONTAINER_ENGINE names another docker-compatible
# command, such as podman; only docker has been exercised. Run from the project
# root. Output: TAP. Exit 0 when every assertion passes, 1 otherwise.

# The single-quoted scripts below are run by sh inside the container, so their
# $(...) is meant to expand there and not here.
# shellcheck disable=SC2016

set -uo pipefail

if [[ $# -ne 2 || ( $1 != deb && $1 != rpm ) ]]; then
    printf 'usage: %s deb|rpm <dist-dir>\n' "$0" >&2
    exit 2
fi
FORMAT=$1
DIST=$2
ENGINE=${CONTAINER_ENGINE:-docker}

# The boot wait bounds each probe with timeout(1), which older macOS releases
# lack; Homebrew's coreutils installs it, also as gtimeout.
if ! TIMEOUT=$(command -v timeout || command -v gtimeout); then
    printf 'Bail out! no timeout command on PATH: install coreutils (Homebrew also names it gtimeout)\n'
    exit 1
fi

# -- TAP ---------------------------------------------------------------------
T=0
FAILURES=0
SCENARIO_FAILURES=0

pass() {
    T=$((T + 1))
    printf 'ok %d - %s\n' "$T" "$1"
}

# fail DESCRIPTION [DIAGNOSTIC] reports a failure, its diagnostic (already
# TAP-commented), and on a scenario's first failure the units' journal. At the
# first failure rather than at the scenario's end: a unit that times out
# starting blocks each later step for its TimeoutStartSec, and a few of those
# outlast the CI job, which would then be killed before the end ever printed it.
fail() {
    T=$((T + 1))
    FAILURES=$((FAILURES + 1))
    SCENARIO_FAILURES=$((SCENARIO_FAILURES + 1))
    printf 'not ok %d - %s\n' "$T" "$1"
    [[ -n ${2:-} ]] && printf '%s\n' "$2"
    if [[ $SCENARIO_FAILURES -eq 1 && -n $C ]]; then
        printf '# journal of %s at its first failure:\n' "$C"
        in_c 'journalctl --no-pager -u openvox-ca-first-boot -u openvox-ca' 2>&1 | tail -n 150 | sed 's/^/#   /'
    fi
}

# check DESCRIPTION SCRIPT runs SCRIPT with sh inside the current container
# and passes when it exits zero. On failure its output is shown as a TAP
# diagnostic, so an assertion explains itself without a second run.
check() {
    local out
    if out=$(in_c "$2" 2>&1); then
        pass "$1"
    else
        fail "$1" "$([[ -n $out ]] && printf '%s\n' "$out" | sed 's/^/#   /')"
    fi
}

# -- The packages ------------------------------------------------------------
# Docker reports the architecture as .Architecture, podman as .Host.Arch.
engine_arch=$("$ENGINE" info --format '{{.Architecture}}' 2>/dev/null) ||
    engine_arch=$("$ENGINE" info --format '{{.Host.Arch}}' 2>/dev/null)
case "$engine_arch" in
x86_64 | amd64) DEB_ARCH=amd64 RPM_ARCH=x86_64 ;;
aarch64 | arm64) DEB_ARCH=arm64 RPM_ARCH=aarch64 ;;
*)
    printf 'Bail out! %s reports an unsupported or unreadable architecture: "%s"\n' "$ENGINE" "$engine_arch"
    exit 1
    ;;
esac

# A leg labelled for one architecture must not quietly test another: CI names
# the architecture it expects, and a runner that disagrees is a wiring fault.
# Required under GitHub Actions, so that losing packages.yml's env line fails
# the leg instead of switching the comparison off.
if [[ ${GITHUB_ACTIONS:-} == true && -z ${OPENVOX_CA_PKGTEST_ARCH:-} ]]; then
    printf 'Bail out! OPENVOX_CA_PKGTEST_ARCH is unset; packages.yml must name the architecture each leg expects\n'
    exit 1
fi
if [[ -n ${OPENVOX_CA_PKGTEST_ARCH:-} && $OPENVOX_CA_PKGTEST_ARCH != "$DEB_ARCH" ]]; then
    printf 'Bail out! expected to run on %s, but the container engine is %s\n' \
        "$OPENVOX_CA_PKGTEST_ARCH" "$DEB_ARCH"
    exit 1
fi

# pick DIR prints the one package for this format and architecture in DIR, or
# a TAP bail line and a non-zero status, for the caller to print: it runs in a
# command substitution, where neither its output nor its exit reaches the
# terminal by itself.
pick() {
    local matches
    if [[ $FORMAT == deb ]]; then
        matches=("$1"/openvox-ca_*_"$DEB_ARCH".deb)
    else
        matches=("$1"/openvox-ca-*."$RPM_ARCH".rpm)
    fi
    if [[ ${#matches[@]} -ne 1 || ! -f ${matches[0]} ]]; then
        printf 'Bail out! expected exactly one %s package for %s in %s, found: %s\n' \
            "$FORMAT" "$DEB_ARCH" "$1" "${matches[*]}"
        return 1
    fi
    printf '%s\n' "${matches[0]}"
}

# Staged under fixed names, so every assertion below can say /pkgs/first.deb
# rather than carry a version around.
STAGE=.test-output/packages/$FORMAT-$DEB_ARCH
rm -rf "$STAGE" && mkdir -p "$STAGE"
for which in first upgrade; do
    dir=$DIST
    [[ $which == upgrade ]] && dir=$DIST/upgrade
    if ! pkg=$(pick "$dir"); then
        printf '%s\n' "$pkg"
        exit 1
    fi
    cp "$pkg" "$STAGE/$which.$FORMAT" || exit 1
done
STAGE=$(cd "$STAGE" && pwd)

VERSION=$(sed -n 's/^const Version = "\([^"]*\)"$/\1/p' internal/version/version.go)

# -- The image ---------------------------------------------------------------
IMAGE=openvox-ca-pkgtest:$FORMAT
if [[ $FORMAT == deb ]]; then
    # debconf-utils for debconf-set-selections and debconf-communicate.
    # Pinned by digest, which Renovate moves (see renovate.json).
    dockerfile='FROM docker.io/library/debian:trixie@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6
RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus curl openssl debconf-utils procps
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]'
else
    # cpio to unpack the rpm for the takeover scenario's pre-placed CA.
    # Unpinned, as everywhere in this repository: quay.io drops a CentOS
    # Stream digest once a newer build lands (renovate.json says so). The
    # repository metadata is kept rather than cleaned, so each scenario's
    # install resolves dependencies from it instead of fetching it again.
    dockerfile='FROM quay.io/centos/centos:stream10
RUN dnf install -y systemd openssl procps-ng cpio
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]'
fi
printf '# building %s\n' "$IMAGE"
if ! build_log=$(printf '%s\n' "$dockerfile" | "$ENGINE" build -q -t "$IMAGE" - 2>&1); then
    printf '%s\n' "$build_log" | sed 's/^/# /'
    printf 'Bail out! could not build %s\n' "$IMAGE"
    exit 1
fi

# -- Containers --------------------------------------------------------------
C=
CONTAINERS=()
cleanup() {
    [[ ${#CONTAINERS[@]} -gt 0 ]] && "$ENGINE" rm -f "${CONTAINERS[@]}" >/dev/null 2>&1
}
trap cleanup EXIT

in_c() {
    "$ENGINE" exec -i "$C" sh -c "$1"
}

# start SCENARIO HOSTNAME boots a fresh container and makes it current.
start() {
    C=openvox-ca-pkgtest-$FORMAT-$1-$$
    SCENARIO_FAILURES=0
    CONTAINERS+=("$C")
    printf '# -- %s (hostname %s)\n' "$1" "$2"
    "$ENGINE" run -d --name "$C" --hostname "$2" \
        --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
        -v "$STAGE:/pkgs:ro" "$IMAGE" >/dev/null || {
        printf 'Bail out! could not start %s\n' "$C"
        exit 1
    }
    # "degraded" is fine: some unit irrelevant to a container (modules-load,
    # say) failing is not this test's concern. Anything else after the wait
    # means systemd never finished booting.
    # Retried, because straight after `run` there may be no systemd to ask
    # yet, and then --wait has nothing to wait on and answers nothing. Bounded
    # by one deadline rather than a count of tries, each of which could block,
    # so a boot that hangs still reaches the diagnostics below well inside the
    # CI job's own timeout.
    local state='' left deadline=$((SECONDS + 180))
    while ((SECONDS < deadline)); do
        # At least 1: the clock can reach the deadline after the test above,
        # and `timeout 0` means no limit at all.
        left=$((deadline - SECONDS))
        ((left < 1)) && left=1
        state=$("$TIMEOUT" "$left" "$ENGINE" exec "$C" systemctl is-system-running --wait 2>/dev/null)
        [[ $state == running || $state == degraded ]] && break
        sleep 1
    done
    if [[ $state != running && $state != degraded ]]; then
        # Shown now, because the exit below runs the trap that removes the
        # container, and with it systemd's own account of why it stopped.
        printf '# container state: %s\n' "$("$ENGINE" inspect -f '{{.State.Status}} (exit {{.State.ExitCode}})' "$C" 2>&1)"
        "$ENGINE" logs "$C" 2>&1 | tail -n 80 | sed 's/^/#   /'
        printf 'Bail out! systemd in %s did not boot: %s\n' "$C" "${state:-no answer}"
        exit 1
    fi
}

# -- Package operations ------------------------------------------------------
# Each prints the package manager's output into $LOG and returns its status,
# so a scenario can both judge the exit and grep what the scripts said.
LOG=
pm() {
    LOG=$(in_c "$1" 2>&1)
}

if [[ $FORMAT == deb ]]; then
    # stdin from /dev/null and the noninteractive frontend: any prompt would
    # either take its default or fail, never wait. The conffile options are
    # what an unattended upgrade passes: keep the operator's file, leave the
    # package's beside it.
    APT='DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold'
    install_first() { pm "$APT install /pkgs/first.deb </dev/null"; }
    install_upgrade() { pm "$APT install /pkgs/upgrade.deb </dev/null"; }
    remove_pkg() { pm "$APT remove openvox-ca </dev/null"; }
    purge_pkg() { pm "$APT purge openvox-ca </dev/null"; }
    file_version() { in_c "dpkg-deb -f $1 Version"; }
else
    install_first() { pm 'dnf install -y /pkgs/first.rpm'; }
    install_upgrade() { pm 'dnf install -y /pkgs/upgrade.rpm'; }
    remove_pkg() { pm 'dnf remove -y openvox-ca'; }
    file_version() { in_c "rpm -qp --qf '%{VERSION}-%{RELEASE}' $1"; }
fi

# judge DESCRIPTION reports the last package operation's status, with its
# output as the diagnostic when it failed.
judge() {
    local status=$?
    if [[ $status -eq 0 ]]; then
        pass "$1"
    else
        fail "$1 (exit $status)" "$(printf '%s\n' "$LOG" | tail -n 60 | sed 's/^/#   /')"
    fi
}

said() {
    if grep -qF -- "$2" <<<"$LOG"; then
        pass "$1"
    else
        fail "$1" "$(printf '#   expected the output to contain: %s\n' "$2"
            printf '%s\n' "$LOG" | tail -n 40 | sed 's/^/#   /')"
    fi
}

SSL=/etc/puppetlabs/puppet/ssl

# -- Shared assertions -------------------------------------------------------

# payload checks what a fresh install put on disk.
payload() {
    check "both binaries are installed 0755 in /usr/bin" \
        'test "$(stat -c %a /usr/bin/openvox-ca) $(stat -c %a /usr/bin/openvox-ca-ctl)" = "755 755"'
    check "openvox-ca --version reports $VERSION" \
        "/usr/bin/openvox-ca --version | grep -E '(^| )$VERSION( |\$)'"
    check "openvox-ca-ctl --version reports $VERSION" \
        "/usr/bin/openvox-ca-ctl --version | grep -E '(^| )$VERSION( |\$)'"
    check "the puppet account exists, with no login shell" \
        'getent group puppet && getent passwd puppet | grep -E ":/etc/puppetlabs/puppet:/usr/sbin/nologin$"'
    check "both units are installed, rendered for /usr/bin" \
        'test -f /usr/lib/systemd/system/openvox-ca-first-boot.service &&
         grep -x "ExecStart=/usr/bin/openvox-ca" /usr/lib/systemd/system/openvox-ca.service &&
         ! grep -n "@BINDIR@" /usr/lib/systemd/system/openvox-ca.service'
    check "first-boot is installed executable" 'test -x /usr/libexec/openvox-ca/first-boot'
    if [[ $FORMAT == deb ]]; then
        check "the deb ships both Debian drop-ins and no record-environment" \
            'test -f /usr/lib/systemd/system/openvox-ca.service.d/00-debian.conf &&
             test -f /usr/lib/systemd/system/openvox-ca-first-boot.service.d/00-debian.conf &&
             test ! -e /usr/libexec/openvox-ca/record-environment'
    else
        check "the rpm ships record-environment and no Debian drop-ins" \
            'test -x /usr/libexec/openvox-ca/record-environment &&
             test ! -e /usr/lib/systemd/system/openvox-ca.service.d &&
             test ! -e /usr/lib/systemd/system/openvox-ca-first-boot.service.d'
    fi
    check "systemd-analyze verify accepts both units" \
        'systemd-analyze verify openvox-ca.service openvox-ca-first-boot.service'
    check "config.yaml is 0640 root:puppet" \
        'test "$(stat -c "%a %U:%G" /etc/openvox-ca/config.yaml)" = "640 root:puppet"'
    check "the CA directory is 0770 puppet:puppet" \
        "test \"\$(stat -c '%a %U:%G' $SSL/ca)\" = '770 puppet:puppet'"
    check "the migration guide the takeover warning names is installed" \
        'test -s /usr/share/doc/openvox-ca/docs/migrating-from-puppet-server.md'
}

# serves NAME [CACERT] asserts the CA answers TLS on NAME:8141, verified
# against CACERT (by default the certs/ca.pem the package linked), and that
# what it serves as its CA certificate is the one in the CA directory. No -k,
# and --resolve rather than trusting whatever /etc/hosts says about NAME.
serves() {
    local cacert=${2:-$SSL/certs/ca.pem}
    check "the CA serves verifiably as $1 on 8141, trusted through $cacert" \
        "curl -fsS --resolve $1:8141:127.0.0.1 --cacert $cacert \
            https://$1:8141/puppet-ca/v1/certificate/ca -o /root/served.pem &&
         test \"\$(openssl x509 -in /root/served.pem -noout -fingerprint -sha256)\" = \
              \"\$(openssl x509 -in $SSL/ca/ca_crt.pem -noout -fingerprint -sha256)\""
}

unit_state() {
    check "openvox-ca.service is $1 and $2" \
        "test \"\$(systemctl is-enabled openvox-ca.service 2>&1)\" = $1 &&
         test \"\$(systemctl is-active openvox-ca.service 2>&1)\" = $2"
}

# remember_ca records the CA's key and certificate digests; ca_unchanged
# asserts they still match. The takeover cases depend on byte identity: a CA
# re-minted under the same name would serve just as verifiably.
remember_ca() {
    check "the CA's certificate and key digests are recorded" \
        "sha256sum $SSL/ca/ca_crt.pem $SSL/ca/ca_key.pem >/root/ca.sha256 && test \$(wc -l </root/ca.sha256) -eq 2"
}
ca_unchanged() {
    check "the CA certificate and key are byte-identical $1" 'sha256sum -c --quiet /root/ca.sha256'
}

# remember_pid and restarted assert that an upgrade restarts the service onto
# the new package: a CA left running the old one passes every other check
# after an upgrade, because it was already serving.
remember_pid() {
    check "the running service's PID is recorded" \
        'systemctl show -p MainPID --value openvox-ca.service >/root/mainpid && test "$(cat /root/mainpid)" != 0'
}
restarted() {
    check "the upgrade restarted the service" \
        'pid=$(systemctl show -p MainPID --value openvox-ca.service) &&
         test "$pid" != 0 && test "$pid" != "$(cat /root/mainpid)"'
}

# stopped asserts that removing the package stopped both units and left no
# openvox-ca process running from the deleted binary. The unit file going is
# rpm's or dpkg's doing whatever the maintainer scripts did, so it proves
# nothing about them; these do.
stopped() {
    check "$1 stops both units and leaves no openvox-ca process" \
        '! systemctl is-active --quiet openvox-ca.service &&
         ! systemctl is-active --quiet openvox-ca-first-boot.service &&
         ! pgrep -x openvox-ca'
}

# environment NAME asserts the running service was given NAME through the
# install-time environment file. Read from the process, because a file on disk
# that the unit does not read would otherwise pass.
environment() {
    check "the running service has OPENVOX_CA_CERTNAME=$1 from $2" \
        "tr '\\0' '\\n' </proc/\$(systemctl show -p MainPID --value openvox-ca)/environ |
            grep -x OPENVOX_CA_CERTNAME=$1"
}

# place_ca DIR mints a CA into DIR with the packaged openvox-ca-ctl, unpacked
# rather than installed, before the package is: the state of a host that ran
# OpenVox Server's CA. The account is created first, as Server's own package
# would have, and owns the tree, as Server leaves it.
place_ca() {
    local unpack
    if [[ $FORMAT == deb ]]; then
        unpack='dpkg-deb -x /pkgs/first.deb /root/unpacked'
    else
        unpack='cd /root/unpacked && rpm2cpio /pkgs/first.rpm | cpio -idm --quiet'
    fi
    check "a CA is placed in $1 before install" \
        "mkdir -p /root/unpacked && ($unpack) &&
         { getent group puppet >/dev/null || groupadd --system puppet; } &&
         { getent passwd puppet >/dev/null ||
             useradd --system -g puppet -d /etc/puppetlabs/puppet -s /usr/sbin/nologin puppet; } &&
         mkdir -p $1 &&
         /root/unpacked/usr/bin/openvox-ca-ctl setup --cadir $1 --hostname foreign.example.test &&
         chown -R puppet:puppet /etc/puppetlabs"
}

# -- Debian ------------------------------------------------------------------
deb_scenarios() {
    # The main line: install, upgrade, remove, purge both ways, preseed.
    start main ca.example.test
    # The official image forbids starting daemons; this scenario is the host
    # that does not. policy-rc scenario below keeps one.
    in_c 'rm -f /usr/sbin/policy-rc.d'

    check "the image does not already carry ucf" '! dpkg -s ucf >/dev/null 2>&1'
    install_first
    judge "a non-interactive install succeeds"
    check "the install pulled in ucf, a declared dependency" 'dpkg -s ucf >/dev/null'
    payload
    unit_state enabled active
    check "provisioning minted a node certificate for the host's FQDN" \
        "test -f $SSL/certs/ca.example.test.pem && test \"\$(readlink $SSL/certs/openvox-ca-server.pem)\" = ca.example.test.pem"
    serves ca.example.test
    check "/etc/default/openvox-ca carries the detected name and the admin list" \
        'grep -x OPENVOX_CA_CERTNAME=ca.example.test /etc/default/openvox-ca &&
         grep -x OPENVOX_CA_PUPPET_SERVER=ca.example.test /etc/default/openvox-ca'
    environment ca.example.test /etc/default/openvox-ca
    check "debconf-communicate reads the answer back" \
        'echo "get openvox-ca/ca-name" | debconf-communicate openvox-ca | grep -x "0 ca.example.test"'
    check "config.yaml is a dpkg conffile and /etc/default/openvox-ca is not" \
        "dpkg-query -W -f='\${Conffiles}\\n' openvox-ca | grep -q ' /etc/openvox-ca/config.yaml ' &&
         ! dpkg-query -W -f='\${Conffiles}\\n' openvox-ca | grep -q /etc/default/openvox-ca"
    check "ucf has registered /etc/default/openvox-ca to openvox-ca" \
        'ucfq -w /etc/default/openvox-ca | grep -q "^/etc/default/openvox-ca:openvox-ca:"'
    remember_ca

    in_c 'echo "# local edit (install-verify)" >>/etc/openvox-ca/config.yaml
          echo "# local edit (install-verify)" >>/etc/default/openvox-ca'
    remember_pid
    install_upgrade
    judge "an upgrade succeeds"
    check "the upgrade installed $(file_version /pkgs/upgrade.deb)" \
        "test \"\$(dpkg-query -W -f='\${Version}' openvox-ca)\" = '$(file_version /pkgs/upgrade.deb)'"
    check "the upgrade kept the edited config.yaml and left the new default as .dpkg-dist" \
        'grep -q "local edit (install-verify)" /etc/openvox-ca/config.yaml &&
         grep -q "build-upgrade.sh" /etc/openvox-ca/config.yaml.dpkg-dist'
    # apt's --force-confold reaches ucf as DPKG_FORCE, which outranks any
    # conflict policy the postinst could pass it, so this pins that the file
    # goes through ucf at all -- bypassing it is how an edit gets lost -- not
    # ucf's own choice. An unattended upgrade passes the same option.
    check "the upgrade kept the edit to /etc/default/openvox-ca and left the new rendering as .ucf-dist" \
        'grep -q "local edit (install-verify)" /etc/default/openvox-ca &&
         grep -q "build-upgrade.sh" /etc/default/openvox-ca.ucf-dist'
    unit_state enabled active
    restarted
    ca_unchanged "across the upgrade"
    serves ca.example.test

    remove_pkg
    judge "apt remove succeeds"
    check "apt remove leaves the unit masked" \
        'test "$(systemctl is-enabled openvox-ca.service 2>&1)" = masked'
    stopped "apt remove"
    ca_unchanged "after remove"

    install_upgrade
    judge "reinstalling after remove succeeds"
    unit_state enabled active
    ca_unchanged "after reinstall"
    serves ca.example.test

    purge_pkg
    judge "apt purge with the question at its default succeeds"
    check "the default purge keeps the CA directory" "test -f $SSL/ca/ca_key.pem"
    ca_unchanged "after the default purge"
    check "purge removes /etc/default/openvox-ca and unmasks the unit" \
        'test ! -e /etc/default/openvox-ca &&
         test "$(systemctl is-enabled openvox-ca.service 2>&1)" != masked'

    # A purge that kept the CA makes the next install a takeover, by design:
    # dpkg has forgotten the package, so nothing says whose the CA is.
    install_first
    judge "reinstalling after a purge that kept the CA succeeds"
    said "and says it is not starting the CA it found" "neither enabled nor started"
    said "naming where it found it" "$SSL/ca already holds a CA"
    check "and neither enables nor starts it" \
        'test "$(systemctl is-enabled openvox-ca.service)" != enabled && ! systemctl is-active --quiet openvox-ca.service'
    check "systemctl enable --now adopts it" 'systemctl enable --now openvox-ca.service'
    ca_unchanged "after adoption"
    serves ca.example.test

    in_c 'echo "openvox-ca openvox-ca/purge_ca_data boolean true" | debconf-set-selections'
    purge_pkg
    judge "apt purge with purge_ca_data preseeded true succeeds"
    check "it removes the CA directory and provisioning's links" \
        "test ! -e $SSL/ca && test ! -e $SSL/certs/ca.pem && test ! -e $SSL/crl.pem &&
         test ! -e $SSL/certs/openvox-ca-server.pem && test ! -e $SSL/private_keys/openvox-ca-server.pem"
    check "and leaves the rest of the ssl tree" \
        "test -f $SSL/certs/ca.example.test.pem && test -f $SSL/private_keys/ca.example.test.pem"

    in_c 'echo "openvox-ca openvox-ca/ca-name string named.example.test" | debconf-set-selections'
    install_first
    judge "a preseeded install succeeds"
    unit_state enabled active
    check "it mints for the preseeded name, not the detected one" \
        "test \"\$(readlink $SSL/certs/openvox-ca-server.pem)\" = named.example.test.pem"
    check "/etc/default/openvox-ca carries the preseeded name" \
        'grep -x OPENVOX_CA_CERTNAME=named.example.test /etc/default/openvox-ca &&
         grep -x OPENVOX_CA_PUPPET_SERVER=named.example.test /etc/default/openvox-ca'
    environment named.example.test /etc/default/openvox-ca
    check "debconf-communicate reads the preseeded answer back" \
        'echo "get openvox-ca/ca-name" | debconf-communicate openvox-ca | grep -x "0 named.example.test"'
    serves named.example.test

    # policy-rc.d forbidding starts, on a host whose name resolves to nothing
    # usable: the install succeeds and starts nothing, and the start that
    # follows provisions under the localhost fallback.
    start policy-rc localhost
    in_c 'printf "#!/bin/sh\nexit 101\n" >/usr/sbin/policy-rc.d && chmod 0755 /usr/sbin/policy-rc.d'
    install_first
    judge "an install under a policy-rc.d that forbids starts succeeds"
    unit_state enabled inactive
    check "nothing was provisioned" "test ! -e $SSL/ca/ca_crt.pem"
    check "/etc/default/openvox-ca sets no name, since none was usable" \
        'test -f /etc/default/openvox-ca && ! grep -q "^OPENVOX_CA_" /etc/default/openvox-ca'
    localhost_fallback

    # A CA placed before install is adopted, not overwritten.
    start takeover ca.example.test
    in_c 'rm -f /usr/sbin/policy-rc.d'
    place_ca "$SSL/ca"
    remember_ca
    in_c "cp $SSL/ca/ca_crt.pem /root/placed-ca.pem"
    install_first
    judge "installing onto a pre-placed CA succeeds"
    said "and does not start, naming the CA it found" "$SSL/ca already holds a CA"
    said "and the warning names the migration guide" \
        "/usr/share/doc/openvox-ca/docs/migrating-from-puppet-server.md"
    check "and neither enables nor starts it" \
        'test "$(systemctl is-enabled openvox-ca.service)" != enabled && ! systemctl is-active --quiet openvox-ca.service'
    ca_unchanged "after install"
    check "systemctl enable --now adopts it" 'systemctl enable --now openvox-ca.service'
    ca_unchanged "after adoption"
    serves ca.example.test /root/placed-ca.pem

    # The other two takeover triggers, each on a first install. The first
    # purge removes the adopted CA so it cannot be the trigger; the second
    # is the default one, and keeps only the empty CA directory the
    # unstarted install left.
    in_c 'echo "openvox-ca openvox-ca/purge_ca_data boolean true" | debconf-set-selections'
    purge_pkg
    judge "apt purge with purge_ca_data preseeded true succeeds"
    place_ca /etc/puppetlabs/puppetserver/ca
    install_first
    judge "installing beside OpenVox Server's own CA directory succeeds"
    said "and does not start, naming that directory" \
        "/etc/puppetlabs/puppetserver/ca already holds a CA"
    check "and neither enables nor starts it" \
        'test "$(systemctl is-enabled openvox-ca.service)" != enabled && ! systemctl is-active --quiet openvox-ca.service'
    purge_pkg
    judge "apt purge with the question at its default succeeds"
    in_c 'rm -rf /etc/puppetlabs/puppetserver &&
          printf "[Service]\nExecStart=/bin/true\n" >/etc/systemd/system/puppetserver.service'
    install_first
    judge "installing where puppetserver.service is installed succeeds"
    said "and does not start, naming OpenVox Server" "OpenVox Server (puppetserver.service) is installed"
    check "and neither enables nor starts it" \
        'test "$(systemctl is-enabled openvox-ca.service)" != enabled && ! systemctl is-active --quiet openvox-ca.service'
}

# localhost_fallback starts the CA on a host named localhost and asserts the
# last tier of the name chain: it still provisions, under "localhost", says so
# in the marker, and serves verifiably under that name.
localhost_fallback() {
    check "starting it provisions despite no usable name" 'systemctl start openvox-ca.service'
    check "under the name localhost" \
        "test \"\$(readlink $SSL/certs/openvox-ca-server.pem)\" = localhost.pem"
    check "leaving the unresolved-certname marker" "test -s $SSL/openvox-ca-certname-unresolved"
    check "and the oneshot exited zero" \
        'test "$(systemctl show -p ExecMainStatus --value openvox-ca-first-boot)" = 0'
    serves localhost
}

# -- EL ----------------------------------------------------------------------
rpm_scenarios() {
    start main ca.example.test
    check "the image does not already carry hostname" '! rpm -q hostname'
    install_first
    judge "dnf install succeeds"
    check "the install pulled in hostname, a declared dependency" 'rpm -q hostname'
    payload
    unit_state disabled inactive
    check "installing provisions nothing" "test ! -e $SSL/ca/ca_crt.pem"
    check "systemctl enable --now provisions and starts" 'systemctl enable --now openvox-ca.service'
    unit_state enabled active
    serves ca.example.test
    check "the shipped config.yaml is unmodified (rpm -V)" \
        '! rpm -V openvox-ca | grep " /etc/openvox-ca/config.yaml$"'
    check "/etc/sysconfig/openvox-ca is 0600 root:root" \
        'test "$(stat -c "%a %U:%G" /etc/sysconfig/openvox-ca)" = "600 root:root"'
    check "it records the provisioned name and the admin list" \
        'grep -x OPENVOX_CA_CERTNAME=ca.example.test /etc/sysconfig/openvox-ca &&
         grep -x OPENVOX_CA_PUPPET_SERVER=ca.example.test /etc/sysconfig/openvox-ca'
    environment ca.example.test /etc/sysconfig/openvox-ca
    remember_ca

    # Once per host. A plain restart provisions nothing, so it only shows the
    # file is left alone. The run after it is the one that matters: with the
    # file and the serving links deleted it relinks the credential, as
    # re-minting under a corrected name does, which is the run first-boot
    # leaves its marker on -- so only record-environment's own record stands
    # between it and a rewrite. The service then starts without the file.
    in_c 'sha256sum /etc/sysconfig/openvox-ca >/root/sysconfig.sha256'
    check "restarting an already-provisioned host leaves it unchanged" \
        'systemctl restart openvox-ca-first-boot.service openvox-ca.service && sha256sum -c --quiet /root/sysconfig.sha256'
    check "deleted, a run that relinks the serving credential does not write it again" \
        "rm /etc/sysconfig/openvox-ca $SSL/certs/openvox-ca-server.pem $SSL/private_keys/openvox-ca-server.pem &&
         systemctl restart openvox-ca-first-boot.service openvox-ca.service &&
         test -L $SSL/certs/openvox-ca-server.pem && test ! -e /etc/sysconfig/openvox-ca"
    unit_state enabled active
    serves ca.example.test

    in_c 'echo "# local edit (install-verify)" >>/etc/openvox-ca/config.yaml'
    remember_pid
    install_upgrade
    judge "an upgrade succeeds"
    check "the upgrade installed $(file_version /pkgs/upgrade.rpm)" \
        "test \"\$(rpm -q --qf '%{VERSION}-%{RELEASE}' openvox-ca)\" = '$(file_version /pkgs/upgrade.rpm)'"
    check "the upgrade kept the edited config.yaml and left the new default as .rpmnew" \
        'grep -q "local edit (install-verify)" /etc/openvox-ca/config.yaml &&
         grep -q "build-upgrade.sh" /etc/openvox-ca/config.yaml.rpmnew'
    unit_state enabled active
    restarted
    ca_unchanged "across the upgrade"
    serves ca.example.test

    remove_pkg
    judge "dnf remove succeeds"
    ca_unchanged "after dnf remove"
    check "the rest of the ssl tree is intact" \
        "test -f $SSL/certs/ca.example.test.pem && test -f $SSL/private_keys/ca.example.test.pem && test -L $SSL/certs/ca.pem"
    stopped "dnf remove"
    check "dnf remove disables both units, leaving no link behind" \
        'test -z "$(find /etc/systemd/system -mindepth 2 -name "openvox-ca*" -print)" &&
         ! systemctl cat openvox-ca.service openvox-ca-first-boot.service >/dev/null 2>&1'

    start localhost localhost
    install_first
    judge "dnf install succeeds on a host with no usable name"
    check "enabling it" 'systemctl enable openvox-ca.service'
    localhost_fallback
    check "a fallback name is not recorded in /etc/sysconfig/openvox-ca" \
        'test ! -e /etc/sysconfig/openvox-ca'

    start takeover ca.example.test
    place_ca "$SSL/ca"
    remember_ca
    in_c "cp $SSL/ca/ca_crt.pem /root/placed-ca.pem"
    install_first
    judge "installing onto a pre-placed CA succeeds"
    unit_state disabled inactive
    ca_unchanged "after install"
    check "systemctl enable --now adopts it" 'systemctl enable --now openvox-ca.service'
    ca_unchanged "after adoption"
    serves ca.example.test /root/placed-ca.pem
}

started=$SECONDS
if [[ $FORMAT == deb ]]; then
    deb_scenarios
else
    rpm_scenarios
fi
printf '1..%d\n' "$T"
printf '# %s (%s): %d of %d failed, in %ds\n' "$FORMAT" "$DEB_ARCH" "$FAILURES" "$T" $((SECONDS - started))
[[ $FAILURES -eq 0 ]]
