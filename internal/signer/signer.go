// Copyright (C) 2026 Trevor Vaughan
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

// Package signer implements an isolated CA key signer that communicates over
// a socketpair. The signer holds the CA private key in a separate process;
// the frontend never loads the key into its own address space.
//
// Protocol: net/rpc over a pre-connected Unix socketpair (inherited via fd 3).
// NIST 800-53: SC-4 (Information in Shared System Resources), SC-3 (Security Function Isolation)
package signer

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/rpc"
	"os"
	"os/signal"
	"syscall"
)

// InheritedFD is the file descriptor number used to pass the socketpair
// endpoint to child processes via exec.Cmd.ExtraFiles.
const InheritedFD = 3

// PSKFD is the file descriptor number used to pass the read end of the
// PSK pipe to child processes via exec.Cmd.ExtraFiles.
const PSKFD = 4

// pskLen is the expected PSK length in bytes.
const pskLen = 32

// SignRequest is sent from the frontend to the signer process.
type SignRequest struct {
	Digest   []byte
	HashFunc crypto.Hash
}

// SignResponse is returned from the signer to the frontend.
type SignResponse struct {
	Signature []byte
}

// ---------- Server (signer process) ----------

// Service holds the CA private key and serves signing requests over RPC.
type Service struct {
	key crypto.Signer
}

// Sign performs a cryptographic signing operation using the isolated CA key.
func (s *Service) Sign(req *SignRequest, resp *SignResponse) error {
	sig, err := s.key.Sign(rand.Reader, req.Digest, req.HashFunc)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}
	resp.Signature = sig
	return nil
}

// Serve runs the signer RPC server on the inherited socketpair fd.
// It blocks until the connection is closed or a SIGTERM/SIGINT is received.
//
// Before serving RPC calls the signer performs a mandatory mutual
// challenge-response handshake using the PSK read from the inherited pipe
// (fd 4): it verifies the frontend's HMAC proof before serving any request,
// and supplies its own proof so the frontend can reject an impostor signer.
func Serve(key crypto.Signer) error {
	// Recover the socketpair endpoint passed via ExtraFiles (fd 3).
	conn, err := connFromFD(InheritedFD)
	if err != nil {
		return fmt.Errorf("recovering socketpair fd %d: %w", InheritedFD, err)
	}
	defer conn.Close()

	// PSK authentication handshake.
	psk, err := loadPSK()
	if err != nil {
		return fmt.Errorf("loading PSK: %w", err)
	}
	if err := serverHandshake(conn, psk); err != nil {
		return fmt.Errorf("PSK handshake failed: %w", err)
	}
	slog.Info("PSK handshake succeeded")

	svc := &Service{key: key}
	server := rpc.NewServer()
	if err := server.RegisterName("Signer", svc); err != nil {
		return fmt.Errorf("registering signer RPC service: %w", err)
	}

	slog.Info("Signer process ready", "pid", os.Getpid())

	// Shut down cleanly on signal by closing the connection. The buffer
	// matches the number of registered signals so a coincident
	// SIGTERM+SIGINT cannot drop a notification, and the goroutine is
	// wired to a done channel so it exits when ServeConn returns on its
	// own (e.g. the frontend closed the socketpair) instead of leaking
	// with signal.Notify still registered.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)

	done := make(chan struct{})
	defer close(done)

	go awaitShutdown(conn, sigCh, done)

	// ServeConn blocks, handling multiplexed RPC calls on the single connection.
	server.ServeConn(conn)
	return nil
}

// awaitShutdown is the goroutine body Serve runs to translate signals
// into a connection close. It blocks until either:
//   - a value arrives on sigCh (typically SIGTERM/SIGINT routed via
//     signal.Notify), in which case it closes conn so ServeConn unblocks;
//   - done is closed (ServeConn already returned and Serve is winding
//     down), in which case it returns without touching conn.
//
// Extracted into its own function so the done-vs-signal selection can
// be exercised in tests without spawning a real signer process or
// raising real OS signals.
func awaitShutdown(conn io.Closer, sigCh <-chan os.Signal, done <-chan struct{}) {
	select {
	case <-sigCh:
		slog.Info("Signer process shutting down")
		_ = conn.Close()
	case <-done:
	}
}

// connFromFD wraps a raw file descriptor as a net.Conn.
func connFromFD(fd int) (net.Conn, error) {
	f := os.NewFile(uintptr(fd), "signer-socketpair")
	if f == nil {
		return nil, fmt.Errorf("fd %d is not valid", fd)
	}
	conn, err := net.FileConn(f)
	f.Close() // FileConn dups the fd; close the original
	if err != nil {
		return nil, fmt.Errorf("converting fd %d to net.Conn: %w", fd, err)
	}
	return conn, nil
}

// ---------- Client (frontend process) ----------

// RemoteSigner implements crypto.Signer by proxying Sign() calls to the
// signer process over an RPC connection.
type RemoteSigner struct {
	client *rpc.Client
	pub    crypto.PublicKey
}

// DialConn connects to the signer process and performs the mutual PSK
// handshake, returning the authenticated connection: the frontend proves
// knowledge of the PSK to the signer and verifies the signer's counter-proof
// before returning. The caller must eventually create a RemoteSigner via
// NewRemoteSigner once the public key is available.
//
// This two-step approach allows the frontend to wait for the signer to be
// ready (via the PSK handshake) before reading the CA cert from disk.
func DialConn() (net.Conn, error) {
	conn, err := connFromFD(InheritedFD)
	if err != nil {
		return nil, fmt.Errorf("recovering socketpair fd %d: %w", InheritedFD, err)
	}

	// PSK authentication handshake.
	psk, err := loadPSK()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("loading PSK: %w", err)
	}
	if err := clientHandshake(conn, psk); err != nil {
		conn.Close()
		return nil, fmt.Errorf("PSK handshake failed: %w", err)
	}
	slog.Info("PSK handshake succeeded")

	return conn, nil
}

// NewRemoteSigner wraps an already-authenticated connection as a RemoteSigner.
func NewRemoteSigner(conn net.Conn, pub crypto.PublicKey) *RemoteSigner {
	return &RemoteSigner{
		client: rpc.NewClient(conn),
		pub:    pub,
	}
}

// Dial connects to the signer process using the inherited socketpair fd.
// Convenience wrapper that combines DialConn + NewRemoteSigner.
func Dial(pub crypto.PublicKey) (*RemoteSigner, error) {
	conn, err := DialConn()
	if err != nil {
		return nil, err
	}
	return NewRemoteSigner(conn, pub), nil
}

// Public returns the public key corresponding to the isolated CA private key.
func (r *RemoteSigner) Public() crypto.PublicKey {
	return r.pub
}

// Sign proxies the signing operation to the isolated signer process.
// The rand parameter is ignored; randomness is provided by the signer process.
func (r *RemoteSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	req := &SignRequest{Digest: digest, HashFunc: opts.HashFunc()}
	var resp SignResponse
	if err := r.client.Call("Signer.Sign", req, &resp); err != nil {
		return nil, fmt.Errorf("remote sign: %w", err)
	}
	return resp.Signature, nil
}

// Close shuts down the RPC connection to the signer.
func (r *RemoteSigner) Close() error {
	return r.client.Close()
}

// ---------- PSK handshake ----------

// loadPSK reads the hex-encoded PSK from the pipe inherited on fd 4. The
// launcher pre-loads the pipe and closes the write end before spawning, so
// a single read drains it to EOF.
//
// SECURITY: the PSK deliberately travels over a pipe rather than an
// environment variable. A process's exec-time environment stays visible in
// /proc/<pid>/environ for its whole lifetime (os.Unsetenv only mutates the
// process's own copy) and is captured verbatim by crash-dump and support
// tooling such as systemd-coredump; a pipe is consumed once and leaves no
// such residue.
func loadPSK() ([]byte, error) {
	// Verify fd 4 really is a pipe before wrapping it in an os.File. If the
	// process was not spawned by the launcher, fd 4 is either closed or owned
	// by something else entirely (e.g. the runtime's poller), and it must not
	// be read from or closed.
	var st syscall.Stat_t
	if err := syscall.Fstat(PSKFD, &st); err != nil {
		return nil, fmt.Errorf("PSK pipe fd %d unavailable (process not spawned by the launcher?): %w", PSKFD, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFIFO {
		return nil, fmt.Errorf("fd %d is not a pipe (process not spawned by the launcher?)", PSKFD)
	}

	f := os.NewFile(uintptr(PSKFD), "signer-psk-pipe")
	defer f.Close()
	psk, err := parsePSK(f)
	if err != nil {
		return nil, fmt.Errorf("reading PSK from inherited fd %d: %w", PSKFD, err)
	}
	return psk, nil
}

// parsePSK reads a hex-encoded PSK from r and decodes and validates it.
func parsePSK(r io.Reader) ([]byte, error) {
	// Read one byte beyond the expected hex length so over-length input
	// becomes an odd-length hex string and fails decoding, rather than
	// being silently truncated to a plausible PSK.
	hexPSK, err := io.ReadAll(io.LimitReader(r, 2*pskLen+1))
	if err != nil {
		return nil, err
	}
	psk, err := hex.DecodeString(string(hexPSK))
	if err != nil {
		return nil, fmt.Errorf("decoding PSK: %w", err)
	}
	if len(psk) != pskLen {
		return nil, fmt.Errorf("PSK must be %d bytes, got %d", pskLen, len(psk))
	}
	return psk, nil
}

// nonceLen is the length of each side's random handshake nonce.
const nonceLen = 32

// Handshake proof labels provide domain separation between the two
// directions, so a proof generated by one endpoint can never be replayed
// as the other endpoint's proof.
var (
	frontendProofLabel = []byte("openvox-ca frontend")
	signerProofLabel   = []byte("openvox-ca signer")
)

// handshakeProof computes HMAC-SHA256(psk, label || serverNonce || clientNonce).
// Binding both nonces makes each proof unique to this handshake run.
func handshakeProof(psk, label, serverNonce, clientNonce []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write(label)
	mac.Write(serverNonce)
	mac.Write(clientNonce)
	return mac.Sum(nil)
}

// serverHandshake runs the signer's side of the mutual handshake: send a
// random nonce, verify the frontend's proof over both nonces, then return
// the signer's own proof so the frontend can reject an impostor signer.
func serverHandshake(conn net.Conn, psk []byte) error {
	// Generate and send a random nonce.
	serverNonce := make([]byte, nonceLen)
	if _, err := rand.Read(serverNonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}
	if _, err := conn.Write(serverNonce); err != nil {
		return fmt.Errorf("sending nonce: %w", err)
	}

	// Read the frontend's nonce and proof, sent in one flight.
	buf := make([]byte, nonceLen+sha256.Size)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("reading frontend nonce and proof: %w", err)
	}
	clientNonce, clientProof := buf[:nonceLen], buf[nonceLen:]

	if !hmac.Equal(clientProof, handshakeProof(psk, frontendProofLabel, serverNonce, clientNonce)) {
		return fmt.Errorf("PSK authentication failed: frontend proof mismatch")
	}

	// Prove our own knowledge of the PSK to the frontend.
	if _, err := conn.Write(handshakeProof(psk, signerProofLabel, serverNonce, clientNonce)); err != nil {
		return fmt.Errorf("sending signer proof: %w", err)
	}
	return nil
}

// clientHandshake runs the frontend's side of the mutual handshake: read
// the signer's nonce, send our own nonce plus a proof over both, then
// verify the signer's proof so a process that merely holds the socketpair
// fd cannot impersonate the signer.
func clientHandshake(conn net.Conn, psk []byte) error {
	// Read nonce from server.
	serverNonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(conn, serverNonce); err != nil {
		return fmt.Errorf("reading server nonce: %w", err)
	}

	// Send our nonce and proof in one flight.
	clientNonce := make([]byte, nonceLen)
	if _, err := rand.Read(clientNonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}
	msg := make([]byte, 0, nonceLen+sha256.Size)
	msg = append(msg, clientNonce...)
	msg = append(msg, handshakeProof(psk, frontendProofLabel, serverNonce, clientNonce)...)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("sending frontend nonce and proof: %w", err)
	}

	// Verify the signer's counter-proof.
	serverProof := make([]byte, sha256.Size)
	if _, err := io.ReadFull(conn, serverProof); err != nil {
		return fmt.Errorf("reading signer proof: %w", err)
	}
	if !hmac.Equal(serverProof, handshakeProof(psk, signerProofLabel, serverNonce, clientNonce)) {
		return fmt.Errorf("PSK authentication failed: signer proof mismatch")
	}
	return nil
}

// ---------- Socketpair creation (used by launcher) ----------

// Socketpair creates a connected pair of Unix stream sockets.
// Returns (signerEnd, frontendEnd, error). The caller passes each end to
// the respective child process via exec.Cmd.ExtraFiles.
func Socketpair() (signer, frontend *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}
	// Raw socketpair fds are inheritable by default. Mark them close-on-exec
	// so a child only ever receives the end deliberately passed to it via
	// ExtraFiles (which dups the fd with the flag cleared) — otherwise a
	// child spawned while either end is open would inherit both.
	syscall.CloseOnExec(fds[0])
	syscall.CloseOnExec(fds[1])
	return os.NewFile(uintptr(fds[0]), "signer-sock"), os.NewFile(uintptr(fds[1]), "frontend-sock"), nil
}
