// Copyright (C) 2026 Chris Boot
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

package storage

import (
	"bytes"
	"testing"
	"time"
)

// These tests exercise pure helpers of the etcd backend without requiring a
// running cluster. Integration tests that spin up an embedded etcd live in
// etcd_integration_test.go behind a build tag.

func TestEncodeDecodeBlobRoundTrip(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		[]byte("hello"),
		bytes.Repeat([]byte{0xAB}, 4096),
	}
	// Truncate to nanosecond precision to match encode/decode semantics.
	when := time.Unix(0, time.Now().UnixNano())
	for _, data := range cases {
		enc := encodeBlob(when, data)
		if len(enc) != 8+len(data) {
			t.Fatalf("encoded length = %d, want %d", len(enc), 8+len(data))
		}
		gotTime, gotData, err := decodeBlob(enc)
		if err != nil {
			t.Fatalf("decodeBlob: %v", err)
		}
		if !gotTime.Equal(when) {
			t.Fatalf("time = %v, want %v", gotTime, when)
		}
		if !bytes.Equal(gotData, data) {
			t.Fatalf("data = %q, want %q", gotData, data)
		}
	}
}

func TestDecodeBlobRejectsShortInput(t *testing.T) {
	for _, n := range []int{0, 1, 7} {
		if _, _, err := decodeBlob(make([]byte, n)); err == nil {
			t.Errorf("decodeBlob(len=%d) = nil error, want error", n)
		}
	}
}

// TestDecodeBlobReturnsIndependentBuffer verifies that the returned data slice
// does not alias the input buffer. The etcd and redis Get paths return this
// slice straight to callers; if it shared the client's response buffer, a
// caller modifying the slice would corrupt the client's internal state, and
// a future read of the same buffer would observe stale or torn bytes.
func TestDecodeBlobReturnsIndependentBuffer(t *testing.T) {
	when := time.Unix(0, time.Now().UnixNano())
	original := []byte("payload-bytes")
	enc := encodeBlob(when, original)

	_, decoded, err := decodeBlob(enc)
	if err != nil {
		t.Fatalf("decodeBlob: %v", err)
	}

	// Mutate the source buffer; the decoded slice must not see the change.
	for i := 8; i < len(enc); i++ {
		enc[i] = 0xFF
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("decoded data aliases input buffer: got %q, want %q", decoded, original)
	}
}

func TestEtcdPhysicalKey(t *testing.T) {
	b := &EtcdBackend{prefix: "/puppet-ca"}
	tests := []struct {
		logical string
		want    string
		wantErr bool
	}{
		{KeyCACert, "/puppet-ca/ca/cert", false},
		{KeyCAKey, "/puppet-ca/ca/key", false},
		{KeyCAPubKey, "/puppet-ca/ca/pubkey", false},
		{KeyCRL, "/puppet-ca/ca/crl", false},
		{KeySerial, "/puppet-ca/serial", false},
		{KeyInventory, "/puppet-ca/inventory/data", false},
		{KeyInventoryHMAC, "/puppet-ca/inventory/hmac", false},
		{KeyHMACKey, "/puppet-ca/private/hmac_key", false},
		{CSRKey("node1.example.com"), "/puppet-ca/requests/node1.example.com", false},
		{CertKey("node1.example.com"), "/puppet-ca/signed/node1.example.com", false},
		{"", "", true},
		{"unknown", "", true},
		{"../evil", "", true},
		{CSRKey("../evil"), "", true},
	}
	for _, tc := range tests {
		got, err := b.physicalKey(tc.logical)
		if (err != nil) != tc.wantErr {
			t.Errorf("physicalKey(%q): err = %v, wantErr = %v", tc.logical, err, tc.wantErr)
			continue
		}
		if got != tc.want {
			t.Errorf("physicalKey(%q) = %q, want %q", tc.logical, got, tc.want)
		}
	}
}

func TestEtcdConfigDefaults(t *testing.T) {
	cfg := EtcdConfig{}
	cfg.applyDefaults()
	if cfg.DialTimeout != 5*time.Second {
		t.Errorf("DialTimeout = %v, want 5s", cfg.DialTimeout)
	}
	if cfg.RequestTimeout != 5*time.Second {
		t.Errorf("RequestTimeout = %v, want 5s", cfg.RequestTimeout)
	}
	if cfg.KeyPrefix != "/puppet-ca" {
		t.Errorf("KeyPrefix = %q, want /puppet-ca", cfg.KeyPrefix)
	}

	cfg2 := EtcdConfig{KeyPrefix: "/custom/"}
	cfg2.applyDefaults()
	if cfg2.KeyPrefix != "/custom" {
		t.Errorf("KeyPrefix trailing slash not stripped: %q", cfg2.KeyPrefix)
	}
}

func TestEtcdBackendImplementsBackend(t *testing.T) {
	// Compile-time check via the interface.
	var _ Backend = (*EtcdBackend)(nil)
}
