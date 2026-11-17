#!/usr/bin/env python3
"""A deliberately unreliable HTTP server, for http-helpers-test.sh.

Reproduces the transport-level failures the migration suite's assertions used
to render indistinguishable (issue #208), so the helpers in http-helpers.sh can
be tested against real curl rather than against a mock of it.  In particular it
can answer with a valid status line and Content-Length and then close the
connection early -- the truncated-transfer case that made curl exit 18 while
the server's own log recorded a clean 200.

Speaks HTTP/1.0 over a raw socket rather than using http.server, because a
truncated response needs control the framework does not give.

Usage:
    flaky-server.py PORTFILE BEHAVIOUR...

PORTFILE is written with the bound port once the socket is listening; the
caller polls for it rather than guessing a port.  BEHAVIOURs are consumed one
per request, and the last one repeats forever once the list runs out, so
`flaky-server.py p truncate ok` serves one truncated response and then answers
normally for the rest of the run.

Behaviours:
    ok          200 with a PEM-shaped body
    truncate    200, honest Content-Length, half the body, then close
    500         500 with a short HTML error body
    empty       200 with Content-Length: 0
    hangup      close the connection without writing anything
    notfound    404 with a short body
    stall       200 and an honest Content-Length, then never send the body
"""

import socket
import sys
import time

# How long `stall` holds the connection open having sent nothing but headers.
# Only has to outlast the caller's --max-time; the caller kills us afterwards,
# and the accept timeout below bounds us even if it does not.
STALL_SECONDS = 30

# Body long enough that half of it is still recognisably a PEM header, so a
# truncated read is distinguishable from an empty one in the diagnostics.
PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    + "".join("MIIB%02dAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" % i
             for i in range(20))
    + "-----END CERTIFICATE-----\n"
)


def respond(conn, behaviour):
    if behaviour == "hangup":
        return

    if behaviour == "500":
        body = "<html><body>internal server error</body></html>\n"
        head = "HTTP/1.0 500 Internal Server Error\r\n"
    elif behaviour == "notfound":
        body = "Not Found\n"
        head = "HTTP/1.0 404 Not Found\r\n"
    elif behaviour == "empty":
        body = ""
        head = "HTTP/1.0 200 OK\r\n"
    else:  # ok, truncate, stall
        body = PEM
        head = "HTTP/1.0 200 OK\r\n"

    raw = body.encode()
    head += "Content-Type: text/plain\r\nContent-Length: %d\r\n\r\n" % len(raw)
    conn.sendall(head.encode())

    if behaviour == "stall":
        # Head sent, body never. curl waits for the Content-Length it was
        # promised and hits --max-time, which is the only way to reach its
        # exit 28 -- the one state http-helpers.sh documents that no other
        # behaviour here can produce.
        time.sleep(STALL_SECONDS)
    elif behaviour == "truncate":
        # Claim the full length, send half, hang up.  curl notices the short
        # read and exits 18 (CURLE_PARTIAL_FILE), while a server-side log
        # would record a normal 200 -- exactly the pair of observations in
        # #208.  The suite asserts on that exit status, not on curl's message
        # for it, which newer curl reworded (#606).
        conn.sendall(raw[: len(raw) // 2])
    else:
        conn.sendall(raw)


def main():
    portfile, behaviours = sys.argv[1], sys.argv[2:] or ["ok"]

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    # Write the port only once we are listening, so the caller's wait for this
    # file is also a wait for the socket to be connectable.
    with open(portfile, "w") as fh:
        fh.write("%d\n" % srv.getsockname()[1])

    # A daemon thread that outlives the parent script would keep CI hanging;
    # the caller kills us, but exit anyway after a generous idle timeout.
    srv.settimeout(120)

    i = 0
    while True:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            return
        with conn:
            try:
                conn.settimeout(10)
                conn.recv(65536)  # drain the request line and headers
                respond(conn, behaviours[min(i, len(behaviours) - 1)])
            except OSError:
                pass
        i += 1


if __name__ == "__main__":
    main()
