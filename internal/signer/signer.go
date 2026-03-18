// Copyright (C) 2026 Trevor Vaughan
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

// pskEnvVar is the environment variable containing the hex-encoded PSK.
const pskEnvVar = "PUPPET_CA_SIGNER_PSK"

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
// If PUPPET_CA_SIGNER_PSK is set, the signer performs a challenge-response
// handshake before serving RPC calls: it sends a 32-byte random nonce,
// then expects the client to respond with HMAC-SHA256(PSK, nonce).
func Serve(key crypto.Signer) error {
	// Recover the socketpair endpoint passed via ExtraFiles (fd 3).
	conn, err := connFromFD(InheritedFD)
	if err != nil {
		return fmt.Errorf("recovering socketpair fd %d: %w", InheritedFD, err)
	}
	defer conn.Close()

	// PSK authentication handshake.
	if psk, err := loadPSK(); err != nil {
		return fmt.Errorf("loading PSK: %w", err)
	} else if psk != nil {
		if err := serverHandshake(conn, psk); err != nil {
			return fmt.Errorf("PSK handshake failed: %w", err)
		}
		slog.Info("PSK handshake succeeded")
	}

	svc := &Service{key: key}
	server := rpc.NewServer()
	if err := server.RegisterName("Signer", svc); err != nil {
		return fmt.Errorf("registering signer RPC service: %w", err)
	}

	slog.Info("Signer process ready", "pid", os.Getpid())

	// Shut down cleanly on signal by closing the connection.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		slog.Info("Signer process shutting down")
		conn.Close()
	}()

	// ServeConn blocks, handling multiplexed RPC calls on the single connection.
	server.ServeConn(conn)
	return nil
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

// DialConn connects to the signer process and performs the PSK handshake,
// returning the authenticated connection. The caller must eventually create
// a RemoteSigner via NewRemoteSigner once the public key is available.
//
// This two-step approach allows the frontend to wait for the signer to be
// ready (via the PSK handshake) before reading the CA cert from disk.
func DialConn() (net.Conn, error) {
	conn, err := connFromFD(InheritedFD)
	if err != nil {
		return nil, fmt.Errorf("recovering socketpair fd %d: %w", InheritedFD, err)
	}

	// PSK authentication handshake.
	if psk, err := loadPSK(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("loading PSK: %w", err)
	} else if psk != nil {
		if err := clientHandshake(conn, psk); err != nil {
			conn.Close()
			return nil, fmt.Errorf("PSK handshake failed: %w", err)
		}
		slog.Info("PSK handshake succeeded")
	}

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

// loadPSK reads the PSK from the environment variable. Returns nil if unset.
func loadPSK() ([]byte, error) {
	hexPSK := os.Getenv(pskEnvVar)
	if hexPSK == "" {
		return nil, nil
	}
	psk, err := hex.DecodeString(hexPSK)
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", pskEnvVar, err)
	}
	if len(psk) != pskLen {
		return nil, fmt.Errorf("%s must be %d bytes, got %d", pskEnvVar, pskLen, len(psk))
	}
	// Clear from environment after reading to reduce exposure.
	os.Unsetenv(pskEnvVar)
	return psk, nil
}

// serverHandshake sends a random nonce and verifies the client's HMAC response.
func serverHandshake(conn net.Conn, psk []byte) error {
	// Generate and send a random nonce.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}
	if _, err := conn.Write(nonce); err != nil {
		return fmt.Errorf("sending nonce: %w", err)
	}

	// Read the client's HMAC response.
	clientMAC := make([]byte, sha256.Size)
	if _, err := io.ReadFull(conn, clientMAC); err != nil {
		return fmt.Errorf("reading client HMAC: %w", err)
	}

	// Compute expected HMAC and compare.
	mac := hmac.New(sha256.New, psk)
	mac.Write(nonce)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(clientMAC, expectedMAC) {
		return fmt.Errorf("PSK authentication failed: HMAC mismatch")
	}
	return nil
}

// clientHandshake reads the server's nonce and responds with HMAC-SHA256(PSK, nonce).
func clientHandshake(conn net.Conn, psk []byte) error {
	// Read nonce from server.
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(conn, nonce); err != nil {
		return fmt.Errorf("reading server nonce: %w", err)
	}

	// Compute and send HMAC response.
	mac := hmac.New(sha256.New, psk)
	mac.Write(nonce)
	response := mac.Sum(nil)

	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("sending HMAC response: %w", err)
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
	return os.NewFile(uintptr(fds[0]), "signer-sock"), os.NewFile(uintptr(fds[1]), "frontend-sock"), nil
}
