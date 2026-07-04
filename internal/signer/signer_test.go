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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"sync"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// fakeVerifiableKey wraps a crypto.Signer with a controllable KeyVerifier
// implementation, so tests can drive both the "key doesn't support
// verification" and "key does, and reports success/failure" paths without
// needing a real OpenBao-backed key.
type fakeVerifiableKey struct {
	crypto.Signer
	verifyErr   error
	verifyCalls int
}

func (k *fakeVerifiableKey) VerifyCurrentKey(_ context.Context) error {
	k.verifyCalls++
	return k.verifyErr
}

// setPSKEnv sets the PSK environment variable for the duration of the current
// spec, restoring its prior value (set or unset) via DeferCleanup. It replaces
// the upstream tests' use of t.Setenv, which is unavailable inside Ginkgo
// nodes.
func setPSKEnv(value string) {
	prev, had := os.LookupEnv(pskEnvVar)
	Expect(os.Setenv(pskEnvVar, value)).To(Succeed())
	DeferCleanup(func() {
		if had {
			Expect(os.Setenv(pskEnvVar, prev)).To(Succeed())
		} else {
			Expect(os.Unsetenv(pskEnvVar)).To(Succeed())
		}
	})
}

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

var _ = Describe("RemoteSigner.VerifyCurrentKey over RPC", func() {
	// verifies that a key with no KeyVerifier capability (the common case:
	// a local PEM-file key, or any crypto.Signer that doesn't implement it)
	// reports success trivially -- there's nothing to re-check.
	It("succeeds when the underlying key has no verification capability", func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred(), "generating test key")

		serverConn, clientConn := net.Pipe()
		svc := &Service{key: key}
		server := rpc.NewServer()
		Expect(server.RegisterName("Signer", svc)).To(Succeed(), "registering service")
		go server.ServeConn(serverConn)

		rs := &RemoteSigner{client: rpc.NewClient(clientConn), pub: key.Public()}
		DeferCleanup(rs.Close)

		Expect(rs.VerifyCurrentKey(context.Background())).To(Succeed())
	})

	// verifies a successful live verification (the key matches its source of
	// truth) is forwarded across the RPC boundary as success.
	It("forwards a successful verification", func() {
		fake := &fakeVerifiableKey{Signer: mustGenerateKey()}
		serverConn, clientConn := net.Pipe()
		svc := &Service{key: fake}
		server := rpc.NewServer()
		Expect(server.RegisterName("Signer", svc)).To(Succeed(), "registering service")
		go server.ServeConn(serverConn)

		rs := &RemoteSigner{client: rpc.NewClient(clientConn), pub: fake.Public()}
		DeferCleanup(rs.Close)

		Expect(rs.VerifyCurrentKey(context.Background())).To(Succeed())
		Expect(fake.verifyCalls).To(Equal(1))
	})

	// verifies a failed live verification (e.g. the key was rotated at its
	// provider) is forwarded across the RPC boundary as an error, not
	// silently swallowed -- this is the whole point of the check.
	It("forwards a failed verification", func() {
		fake := &fakeVerifiableKey{Signer: mustGenerateKey(), verifyErr: errors.New("key rotated at provider")}
		serverConn, clientConn := net.Pipe()
		svc := &Service{key: fake}
		server := rpc.NewServer()
		Expect(server.RegisterName("Signer", svc)).To(Succeed(), "registering service")
		go server.ServeConn(serverConn)

		rs := &RemoteSigner{client: rpc.NewClient(clientConn), pub: fake.Public()}
		DeferCleanup(rs.Close)

		err := rs.VerifyCurrentKey(context.Background())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("key rotated at provider"))
		Expect(fake.verifyCalls).To(Equal(1))
	})
})

// mustGenerateKey is a small helper for tests that only need a valid
// crypto.Signer to embed in a fakeVerifiableKey and don't care about its
// specific value.
func mustGenerateKey() crypto.Signer {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

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

	// verifies the handshake fails with mismatched PSKs.
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
			errCh <- serverHandshake(serverConn, serverPSK)
		}()

		// Client uses a different PSK; handshake should complete on client side
		// but server should reject.
		_ = clientHandshake(clientConn, clientPSK)

		Expect(<-errCh).To(HaveOccurred(), "server handshake should have failed with wrong PSK")
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

		// Client side: handshake then create RemoteSigner.
		setPSKEnv(pskHex)
		loadedPSK, err := loadPSK()
		Expect(err).NotTo(HaveOccurred(), "loadPSK")
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

var _ = Describe("loadPSK", func() {
	// verifies loadPSK returns nil when env var is unset.
	It("returns nil when the env var is empty", func() {
		setPSKEnv("")
		psk, err := loadPSK()
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(psk).To(BeNil(), "expected nil PSK when env var is empty")
	})

	// verifies loadPSK rejects non-hex values.
	It("rejects non-hex values", func() {
		setPSKEnv("not-hex-data")
		_, err := loadPSK()
		Expect(err).To(HaveOccurred(), "expected error for invalid hex PSK")
	})

	// verifies loadPSK rejects PSKs of wrong length.
	It("rejects PSKs of wrong length", func() {
		setPSKEnv(hex.EncodeToString([]byte("short")))
		_, err := loadPSK()
		Expect(err).To(HaveOccurred(), "expected error for wrong-length PSK")
	})

	// verifies loadPSK removes the env var after reading.
	It("clears the env var after reading", func() {
		psk := make([]byte, 32)
		rand.Read(psk)
		// Note: loadPSK calls os.Unsetenv, so setPSKEnv's restore must not
		// reintroduce the value; it saves the prior (unset) state and restores
		// that, matching the upstream test's os.Setenv + t.Cleanup(os.Unsetenv).
		setPSKEnv(hex.EncodeToString(psk))

		_, err := loadPSK()
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		// After loadPSK, the env var should be cleared.
		Expect(os.Getenv(pskEnvVar)).To(Equal(""), "env var should be cleared after loadPSK")
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
