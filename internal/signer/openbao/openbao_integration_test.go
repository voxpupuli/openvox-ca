// Copyright (C) 2026 Chris Boot
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

//go:build openbao_integration

// This suite runs against a real OpenBao server (see
// compose-backends-openbao.yml and `mage test:backendsOpenBao`, which brings
// the server up, configures the transit engine and a scoped AppRole, and
// tears it down again). Unlike
// openbao_test.go's httptest fakes, this exists to catch places where a
// fake's assumptions about OpenBao's actual wire format drifted from reality
// -- which is exactly how the json.Number handling in latestKeyVersion and
// the SDK's PUT-not-POST Write behaviour were caught during development.
package openbao_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/signer/openbao"
)

// liveOpenBaoConfig returns a Config for the running OpenBao instance, or skips
// the test if the mage target's environment variables aren't set (e.g. a
// bare `go test -tags openbao_integration ./...` without the compose service up).
func liveOpenBaoConfig(t *testing.T, keyName string) openbao.Config {
	t.Helper()
	addr := os.Getenv("PUPPET_CA_TEST_OPENBAO_ADDR")
	if addr == "" {
		t.Skip("set PUPPET_CA_TEST_OPENBAO_ADDR (see mage test:backendsOpenBao) to run OpenBao integration tests")
	}
	return openbao.Config{
		Addr:                addr,
		KeyName:             keyName,
		AuthMethod:          openbao.AuthAppRole,
		AppRoleRoleID:       os.Getenv("PUPPET_CA_TEST_OPENBAO_ROLE_ID"),
		AppRoleSecretIDFile: os.Getenv("PUPPET_CA_TEST_OPENBAO_SECRET_ID_FILE"),
	}
}

// TestLiveSignAndVerify exercises Load + Sign + Public against the
// mage-provisioned "test-key" (created ahead of time so this test only
// needs sign/read capability, mirroring the least-privilege policy this
// project recommends for a production server).
func TestLiveSignAndVerify(t *testing.T) {
	cfg := liveOpenBaoConfig(t, envOrDefault("PUPPET_CA_TEST_OPENBAO_KEY_NAME", "test-key"))
	ctx := context.Background()

	tm, err := openbao.NewTokenManager(ctx, cfg)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	defer tm.Close()

	provider := openbao.NewKeyProvider(tm, cfg.EffectiveTransitMount(), cfg.KeyName)
	signer, err := provider.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	digest := sha256.Sum256([]byte("live openbao integration test"))
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Public() = %T, want *rsa.PublicKey", signer.Public())
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature did not verify against a real OpenBao server: %v", err)
	}
}

// TestLiveGenerateThenLoad exercises the "openvox-ca creates the key itself
// on first boot" convenience path (KeyProvider.Generate) against a key name
// that must not already exist, then confirms a subsequent Load sees it.
func TestLiveGenerateThenLoad(t *testing.T) {
	cfg := liveOpenBaoConfig(t, envOrDefault("PUPPET_CA_TEST_OPENBAO_GENERATE_KEY_NAME", "test-generate-key"))
	ctx := context.Background()

	tm, err := openbao.NewTokenManager(ctx, cfg)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	defer tm.Close()

	provider := openbao.NewKeyProvider(tm, cfg.EffectiveTransitMount(), cfg.KeyName)

	if _, err := provider.Load(ctx); err == nil {
		t.Fatalf("Load succeeded before Generate -- is %q left over from a previous run?", cfg.KeyName)
	}

	if _, err := provider.Generate(ctx, ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	loaded, err := provider.Load(ctx)
	if err != nil {
		t.Fatalf("Load after Generate: %v", err)
	}
	if _, ok := loaded.Public().(*ecdsa.PublicKey); !ok {
		t.Fatalf("loaded key Public() = %T, want *ecdsa.PublicKey", loaded.Public())
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
