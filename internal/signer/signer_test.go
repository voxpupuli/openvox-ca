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

package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/rpc"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing/iotest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RemoteSigner over RPC", func() {
	// verifies that a signing request can be sent over an RPC connection and
	// returns a valid signature.
	It("round-trips a signing request", func() {
		// Generate a test key.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred(), "generating test key")

		// Create a connected socket pair for testing.
		serverConn, clientConn := net.Pipe()

		// Start RPC server in a goroutine.
		svc := &Service{key: key}
		server := rpc.NewServer()
		Expect(server.RegisterName("Signer", svc)).To(Succeed(), "registering service")
		go server.ServeConn(serverConn)

		// Create a RemoteSigner using the client end.
		rs := &RemoteSigner{
			client: rpc.NewClient(clientConn),
			pub:    key.Public(),
		}
		DeferCleanup(rs.Close)

		// Verify Public() returns the correct key.
		Expect(rs.Public()).To(Equal(key.Public()), "Public() returned wrong key")

		// Sign a test digest.
		digest := sha256.Sum256([]byte("test data"))
		sig, err := rs.Sign(rand.Reader, digest[:], crypto.SHA256)
		Expect(err).NotTo(HaveOccurred(), "remote Sign failed")

		// Verify the signature with the public key.
		Expect(ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig)).To(BeTrue(), "signature verification failed")
	})

	// verifies that multiple concurrent signing requests work.
	It("handles concurrent signing requests", func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred(), "generating test key")

		serverConn, clientConn := net.Pipe()

		svc := &Service{key: key}
		server := rpc.NewServer()
		Expect(server.RegisterName("Signer", svc)).To(Succeed(), "registering service")
		go server.ServeConn(serverConn)

		rs := &RemoteSigner{
			client: rpc.NewClient(clientConn),
			pub:    key.Public(),
		}
		DeferCleanup(rs.Close)

		// Fire 10 concurrent signing requests.
		errs := make(chan error, 10)
		for i := range 10 {
			go func(i int) {
				digest := sha256.Sum256([]byte{byte(i)})
				sig, err := rs.Sign(rand.Reader, digest[:], crypto.SHA256)
				if err != nil {
					errs <- err
					return
				}
				if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
					errs <- fmt.Errorf("signature verification failed for i=%d", i)
					return
				}
				errs <- nil
			}(i)
		}

		for range 10 {
			Expect(<-errs).NotTo(HaveOccurred(), "concurrent sign failed")
		}
	})
})

var _ = Describe("Socketpair", func() {
	// verifies that Socketpair creates a connected pair of sockets.
	It("creates a connected pair of sockets", func() {
		s, f, err := Socketpair()
		Expect(err).NotTo(HaveOccurred(), "Socketpair")
		DeferCleanup(s.Close)
		DeferCleanup(f.Close)

		// Write on one end, read on the other.
		msg := []byte("hello")
		go func() {
			s.Write(msg)
		}()

		buf := make([]byte, len(msg))
		n, err := f.Read(buf)
		Expect(err).NotTo(HaveOccurred(), "read")
		Expect(string(buf[:n])).To(Equal(string(msg)))
	})
})

var _ = Describe("PSK handshake", func() {
	// verifies the challenge-response handshake succeeds when both sides share
	// the same PSK.
	It("succeeds when both sides share the same PSK", func() {
		psk := make([]byte, 32)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred(), "generating PSK")

		serverConn, clientConn := net.Pipe()
		DeferCleanup(serverConn.Close)
		DeferCleanup(clientConn.Close)

		errCh := make(chan error, 1)
		go func() {
			errCh <- serverHandshake(serverConn, psk)
		}()

		Expect(clientHandshake(clientConn, psk)).To(Succeed(), "client handshake")
		Expect(<-errCh).NotTo(HaveOccurred(), "server handshake")
	})

	// verifies the handshake fails on both sides with mismatched PSKs: the
	// server rejects the frontend's proof, and the client consequently never
	// receives a valid counter-proof.
	It("fails with mismatched PSKs", func() {
		serverPSK := make([]byte, 32)
		clientPSK := make([]byte, 32)
		rand.Read(serverPSK)
		rand.Read(clientPSK)

		serverConn, clientConn := net.Pipe()
		DeferCleanup(serverConn.Close)
		DeferCleanup(clientConn.Close)

		errCh := make(chan error, 1)
		go func() {
			err := serverHandshake(serverConn, serverPSK)
			if err != nil {
				// Close so the client's read of the never-sent counter-proof
				// fails instead of blocking forever.
				serverConn.Close()
			}
			errCh <- err
		}()

		Expect(clientHandshake(clientConn, clientPSK)).To(
			MatchError(ContainSubstring("reading signer proof")),
			"client should fail once the server aborts")
		Expect(<-errCh).To(
			MatchError(ContainSubstring("frontend proof mismatch")),
			"server should reject the mismatched frontend proof")
	})

	// verifies the frontend rejects an endpoint that holds the socketpair but
	// not the PSK — the impostor-signer case the mutual handshake exists to
	// prevent.
	It("rejects a signer that cannot prove knowledge of the PSK", func() {
		psk := make([]byte, 32)
		rand.Read(psk)

		serverConn, clientConn := net.Pipe()
		DeferCleanup(serverConn.Close)
		DeferCleanup(clientConn.Close)

		// Impostor signer: follows the message flow but forges the proof.
		go func() {
			defer GinkgoRecover()
			nonce := make([]byte, 32)
			rand.Read(nonce)
			_, err := serverConn.Write(nonce)
			Expect(err).NotTo(HaveOccurred(), "impostor sending nonce")
			buf := make([]byte, 32+sha256.Size)
			_, err = io.ReadFull(serverConn, buf)
			Expect(err).NotTo(HaveOccurred(), "impostor reading frontend flight")
			forged := make([]byte, sha256.Size)
			rand.Read(forged)
			_, err = serverConn.Write(forged)
			Expect(err).NotTo(HaveOccurred(), "impostor sending forged proof")
		}()

		Expect(clientHandshake(clientConn, psk)).To(
			MatchError(ContainSubstring("signer proof mismatch")),
			"client should reject a forged signer proof")
	})

	// verifies signing works after a successful PSK handshake.
	It("signs after a successful PSK handshake", func() {
		psk := make([]byte, 32)
		rand.Read(psk)
		pskHex := hex.EncodeToString(psk)

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred(), "generating key")

		serverConn, clientConn := net.Pipe()

		// Server side: handshake then serve RPC.
		go func() {
			if err := serverHandshake(serverConn, psk); err != nil {
				fmt.Printf("server handshake: %v\n", err)
				serverConn.Close()
				return
			}
			svc := &Service{key: key}
			srv := rpc.NewServer()
			srv.RegisterName("Signer", svc)
			srv.ServeConn(serverConn)
		}()

		// Client side: parse the PSK as the frontend would, handshake, then
		// create a RemoteSigner.
		loadedPSK, err := parsePSK(strings.NewReader(pskHex))
		Expect(err).NotTo(HaveOccurred(), "parsePSK")
		Expect(clientHandshake(clientConn, loadedPSK)).To(Succeed(), "client handshake")

		rs := &RemoteSigner{
			client: rpc.NewClient(clientConn),
			pub:    key.Public(),
		}
		DeferCleanup(rs.Close)

		digest := sha256.Sum256([]byte("psk-test"))
		sig, err := rs.Sign(rand.Reader, digest[:], crypto.SHA256)
		Expect(err).NotTo(HaveOccurred(), "sign after PSK handshake")
		Expect(ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig)).To(BeTrue(), "signature verification failed after PSK handshake")
	})
})

var _ = Describe("parsePSK", func() {
	// verifies parsePSK drains a pre-loaded pipe to EOF, matching how the
	// launcher delivers the PSK to a child on fd 4.
	It("reads a PSK from a pre-loaded pipe", func() {
		psk := make([]byte, 32)
		rand.Read(psk)

		r, w, err := os.Pipe()
		Expect(err).NotTo(HaveOccurred(), "creating pipe")
		DeferCleanup(func() { _ = r.Close() })
		_, err = w.WriteString(hex.EncodeToString(psk))
		Expect(err).NotTo(HaveOccurred(), "writing PSK to pipe")
		Expect(w.Close()).To(Succeed(), "closing pipe write end")

		parsed, err := parsePSK(r)
		Expect(err).NotTo(HaveOccurred(), "parsePSK")
		Expect(parsed).To(Equal(psk), "parsed PSK should round-trip")
	})

	// verifies parsePSK rejects an empty stream via the length check: the
	// handshake is mandatory, so a missing PSK must be an error rather than
	// a silent downgrade.
	It("rejects an empty stream", func() {
		_, err := parsePSK(strings.NewReader(""))
		Expect(err).To(MatchError(ContainSubstring("PSK must be 32 bytes, got 0")),
			"empty stream should fail the length check")
	})

	// verifies parsePSK rejects non-hex values via the hex decoder.
	It("rejects non-hex values", func() {
		_, err := parsePSK(strings.NewReader("not-hex-data"))
		Expect(err).To(MatchError(ContainSubstring("decoding PSK")),
			"non-hex input should fail hex decoding")
	})

	// verifies parsePSK rejects a well-formed but short PSK via the length
	// check.
	It("rejects PSKs of wrong length", func() {
		_, err := parsePSK(strings.NewReader(hex.EncodeToString([]byte("short"))))
		Expect(err).To(MatchError(ContainSubstring("PSK must be 32 bytes, got 5")),
			"short PSK should fail the length check")
	})

	// verifies parsePSK rejects trailing garbage after a valid PSK rather
	// than silently truncating it. The one-byte read overshoot makes the
	// input an odd-length hex string, so this surfaces as a decode error —
	// never as the length check.
	It("rejects trailing garbage", func() {
		psk := make([]byte, 32)
		rand.Read(psk)
		_, err := parsePSK(strings.NewReader(hex.EncodeToString(psk) + "\n"))
		Expect(err).To(MatchError(ContainSubstring("decoding PSK")),
			"trailing bytes should surface as an odd-length hex decode error")
	})

	// verifies parsePSK propagates reader failures, covering the read-error
	// branch distinctly from the validation branches.
	It("propagates read errors", func() {
		readErr := errors.New("pipe exploded")
		_, err := parsePSK(iotest.ErrReader(readErr))
		Expect(err).To(MatchError(readErr), "reader failure should propagate unwrapped")
	})
})

// trackingCloser is a minimal io.Closer used by the awaitShutdown specs
// to observe whether the helper closed the underlying connection.
type trackingCloser struct {
	mu     sync.Mutex
	closed bool
}

func (c *trackingCloser) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *trackingCloser) Closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

var _ = Describe("awaitShutdown", func() {
	// is the positive path: when done is closed (i.e. ServeConn returned and
	// the caller signalled shutdown), the helper must exit without touching the
	// underlying connection. Without this property the goroutine would block on
	// sigCh forever and leak on every clean signer exit.
	It("returns on done without closing the connection", func() {
		closer := &trackingCloser{}
		sigCh := make(chan os.Signal, 1)
		done := make(chan struct{})

		finished := make(chan struct{})
		go func() {
			defer close(finished)
			awaitShutdown(closer, sigCh, done)
		}()

		close(done)

		select {
		case <-finished:
		case <-time.After(time.Second):
			Fail("awaitShutdown did not return when done was closed")
		}

		Expect(closer.Closed()).To(BeFalse(), "connection was closed even though shutdown was via done; should only close on signal")
	})

	// is the negative path: when a signal arrives on sigCh, the helper must
	// close the connection so the blocked ServeConn returns and Serve can clean
	// up.
	It("closes the connection on signal", func() {
		closer := &trackingCloser{}
		sigCh := make(chan os.Signal, 1)
		done := make(chan struct{})

		finished := make(chan struct{})
		go func() {
			defer close(finished)
			awaitShutdown(closer, sigCh, done)
		}()

		sigCh <- syscall.SIGTERM

		select {
		case <-finished:
		case <-time.After(time.Second):
			Fail("awaitShutdown did not return after signal")
		}

		Expect(closer.Closed()).To(BeTrue(), "connection was not closed after signal; ServeConn would block forever")
	})
})
