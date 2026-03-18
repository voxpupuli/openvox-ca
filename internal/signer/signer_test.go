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

package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"testing"
)

// TestSignRoundTrip verifies that a signing request can be sent over an RPC
// connection and returns a valid signature.
func TestSignRoundTrip(t *testing.T) {
	// Generate a test key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}

	// Create a connected socket pair for testing.
	serverConn, clientConn := net.Pipe()

	// Start RPC server in a goroutine.
	svc := &Service{key: key}
	server := rpc.NewServer()
	if err := server.RegisterName("Signer", svc); err != nil {
		t.Fatalf("registering service: %v", err)
	}
	go server.ServeConn(serverConn)

	// Create a RemoteSigner using the client end.
	rs := &RemoteSigner{
		client: rpc.NewClient(clientConn),
		pub:    key.Public(),
	}
	defer rs.Close()

	// Verify Public() returns the correct key.
	if rs.Public() != key.Public() {
		t.Error("Public() returned wrong key")
	}

	// Sign a test digest.
	digest := sha256.Sum256([]byte("test data"))
	sig, err := rs.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("remote Sign failed: %v", err)
	}

	// Verify the signature with the public key.
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		t.Error("signature verification failed")
	}
}

// TestSocketpair verifies that Socketpair creates a connected pair of sockets.
func TestSocketpair(t *testing.T) {
	s, f, err := Socketpair()
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer s.Close()
	defer f.Close()

	// Write on one end, read on the other.
	msg := []byte("hello")
	go func() {
		s.Write(msg)
	}()

	buf := make([]byte, len(msg))
	n, err := f.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Errorf("got %q, want %q", buf[:n], msg)
	}
}

// TestSignConcurrent verifies that multiple concurrent signing requests work.
func TestSignConcurrent(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}

	serverConn, clientConn := net.Pipe()

	svc := &Service{key: key}
	server := rpc.NewServer()
	if err := server.RegisterName("Signer", svc); err != nil {
		t.Fatalf("registering service: %v", err)
	}
	go server.ServeConn(serverConn)

	rs := &RemoteSigner{
		client: rpc.NewClient(clientConn),
		pub:    key.Public(),
	}
	defer rs.Close()

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
		if err := <-errs; err != nil {
			t.Errorf("concurrent sign failed: %v", err)
		}
	}
}

// TestPSKHandshakeSuccess verifies the challenge-response handshake succeeds
// when both sides share the same PSK.
func TestPSKHandshakeSuccess(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatalf("generating PSK: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- serverHandshake(serverConn, psk)
	}()

	if err := clientHandshake(clientConn, psk); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}

// TestPSKHandshakeWrongKey verifies the handshake fails with mismatched PSKs.
func TestPSKHandshakeWrongKey(t *testing.T) {
	serverPSK := make([]byte, 32)
	clientPSK := make([]byte, 32)
	rand.Read(serverPSK)
	rand.Read(clientPSK)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- serverHandshake(serverConn, serverPSK)
	}()

	// Client uses a different PSK — handshake should complete on client side
	// but server should reject.
	_ = clientHandshake(clientConn, clientPSK)

	if err := <-errCh; err == nil {
		t.Fatal("server handshake should have failed with wrong PSK")
	}
}

// TestPSKSignRoundTrip verifies signing works after a successful PSK handshake.
func TestPSKSignRoundTrip(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	pskHex := hex.EncodeToString(psk)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

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
	t.Setenv(pskEnvVar, pskHex)
	loadedPSK, err := loadPSK()
	if err != nil {
		t.Fatalf("loadPSK: %v", err)
	}
	if err := clientHandshake(clientConn, loadedPSK); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	rs := &RemoteSigner{
		client: rpc.NewClient(clientConn),
		pub:    key.Public(),
	}
	defer rs.Close()

	digest := sha256.Sum256([]byte("psk-test"))
	sig, err := rs.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign after PSK handshake: %v", err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		t.Error("signature verification failed after PSK handshake")
	}
}

// TestLoadPSKMissing verifies loadPSK returns nil when env var is unset.
func TestLoadPSKMissing(t *testing.T) {
	t.Setenv(pskEnvVar, "")
	psk, err := loadPSK()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if psk != nil {
		t.Error("expected nil PSK when env var is empty")
	}
}

// TestLoadPSKInvalid verifies loadPSK rejects non-hex values.
func TestLoadPSKInvalid(t *testing.T) {
	t.Setenv(pskEnvVar, "not-hex-data")
	_, err := loadPSK()
	if err == nil {
		t.Error("expected error for invalid hex PSK")
	}
}

// TestLoadPSKWrongLength verifies loadPSK rejects PSKs of wrong length.
func TestLoadPSKWrongLength(t *testing.T) {
	t.Setenv(pskEnvVar, hex.EncodeToString([]byte("short")))
	_, err := loadPSK()
	if err == nil {
		t.Error("expected error for wrong-length PSK")
	}
}

// TestLoadPSKClearsEnv verifies loadPSK removes the env var after reading.
func TestLoadPSKClearsEnv(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	// Note: we use os.Setenv directly because loadPSK calls os.Unsetenv,
	// which would conflict with t.Setenv's cleanup.
	os.Setenv(pskEnvVar, hex.EncodeToString(psk))
	t.Cleanup(func() { os.Unsetenv(pskEnvVar) })

	_, err := loadPSK()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// After loadPSK, the env var should be cleared.
	if v := os.Getenv(pskEnvVar); v != "" {
		t.Errorf("env var should be cleared after loadPSK, got %q", v)
	}
}
