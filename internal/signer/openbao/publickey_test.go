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

package openbao_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/signer/openbao"
)

var _ = Describe("Transit public key", func() {
	// docs/openbao-transit.md quotes this refusal to operators who create an
	// ed25519 Transit key, so its wording is a contract. Transit hands out an
	// Ed25519 public key as bare base64 rather than PEM, which is the shape
	// served here.
	It("refuses an ed25519 key, which Transit returns as bare base64, by name", func() {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		Expect(err).NotTo(HaveOccurred())

		mux := http.NewServeMux()
		mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"auth": map[string]interface{}{"client_token": "tok", "lease_duration": 3600, "renewable": true},
			})
		})
		mux.HandleFunc("/v1/transit/keys/edkey", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"data": map[string]interface{}{
					"name":           "edkey",
					"type":           "ed25519",
					"latest_version": float64(1),
					"keys": map[string]interface{}{
						"1": map[string]interface{}{"public_key": base64.StdEncoding.EncodeToString(pub)},
					},
				},
			})
		})
		srv := httptest.NewServer(mux)
		DeferCleanup(srv.Close)

		secretFile := filepath.Join(GinkgoT().TempDir(), "secret-id")
		Expect(os.WriteFile(secretFile, []byte("secret"), 0o600)).To(Succeed())
		cfg := openbao.Config{
			Addr:                srv.URL,
			KeyName:             "edkey",
			AuthMethod:          openbao.AuthAppRole,
			AppRoleRoleID:       "role",
			AppRoleSecretIDFile: secretFile,
		}
		tm, err := openbao.NewTokenManager(context.Background(), cfg)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(tm.Close)

		_, err = openbao.NewKeyProvider(tm, cfg.EffectiveTransitMount(), cfg.KeyName).Load(context.Background())
		Expect(err).To(MatchError(`transit key "edkey": public_key is not valid PEM`))
	})
})
