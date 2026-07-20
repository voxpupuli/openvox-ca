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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/signer/openbao"
)

// fakeOpenBao is a minimal in-memory stand-in for the handful of OpenBao HTTP
// endpoints this package calls: AppRole/Kubernetes login, token lookup-self and
// renew-self, and Transit read/create/sign. It signs with a real key so
// tests can verify the returned signature actually validates.
type fakeOpenBao struct {
	t   *testing.T
	mu  sync.Mutex
	key crypto.Signer

	validTokens map[string]bool
	nextToken   int

	// lastAppRoleSecretID / lastK8sJWT record what the most recent login
	// request actually presented, so tests can assert credentials were
	// re-read from source rather than cached.
	lastAppRoleSecretID string
	lastK8sJWT          string

	// approveAppRoleSecretID / approveK8sJWT gate login success. Nil means
	// "always approve".
	approveAppRoleSecretID func(secretID string) bool
	approveK8sJWT          func(jwt string) bool
}

func newFakeOpenBao(t *testing.T) *fakeOpenBao {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating fake transit key: %v", err)
	}
	return newFakeOpenBaoWithKey(t, key)
}

// newFakeOpenBaoWithKey builds a fake whose Transit key is the caller-supplied
// signer, so a test can drive the ECDSA signing path (the shared RSA fake
// cannot) or any other key type.
func newFakeOpenBaoWithKey(t *testing.T, key crypto.Signer) *fakeOpenBao {
	t.Helper()
	return &fakeOpenBao{
		t:           t,
		key:         key,
		validTokens: map[string]bool{},
	}
}

func (f *fakeOpenBao) issueToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextToken++
	tok := fmt.Sprintf("token-v%d", f.nextToken)
	f.validTokens[tok] = true
	return tok
}

func (f *fakeOpenBao) revoke(tok string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.validTokens, tok)
}

func (f *fakeOpenBao) isValid(tok string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.validTokens[tok]
}

func (f *fakeOpenBao) currentKey() crypto.Signer {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.key
}

// signDigest mimics OpenBao Transit's sign endpoint over the fake's key,
// honouring the signature_algorithm the client sends: "pss" -> RSA-PSS,
// otherwise PKCS#1 v1.5 for RSA; ECDSA always produces an ASN.1-DER signature.
// It returns exactly the raw bytes Transit base64-encodes after the
// "vault:v<N>:" prefix, so the client's decodeTransitSignature and the caller's
// crypto verification exercise the real wire shapes.
func (f *fakeOpenBao) signDigest(digest []byte, sigAlgo string) ([]byte, error) {
	switch key := f.currentKey().(type) {
	case *rsa.PrivateKey:
		if sigAlgo == "pss" {
			return rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
		}
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, key, digest)
	default:
		return nil, fmt.Errorf("fake transit key type %T not supported", key)
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]interface{}{"errors": []string{msg}})
}

func (f *fakeOpenBao) authSecret(token string) map[string]interface{} {
	return map[string]interface{}{
		"auth": map[string]interface{}{
			"client_token":   token,
			"lease_duration": 3600,
			"renewable":      true,
		},
	}
}

func (f *fakeOpenBao) server() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RoleID   string `json:"role_id"`
			SecretID string `json:"secret_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.lastAppRoleSecretID = body.SecretID
		f.mu.Unlock()
		if f.approveAppRoleSecretID != nil && !f.approveAppRoleSecretID(body.SecretID) {
			writeError(w, http.StatusForbidden, "invalid secret_id")
			return
		}
		writeJSON(w, http.StatusOK, f.authSecret(f.issueToken()))
	})

	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			JWT  string `json:"jwt"`
			Role string `json:"role"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.lastK8sJWT = body.JWT
		f.mu.Unlock()
		if f.approveK8sJWT != nil && !f.approveK8sJWT(body.JWT) {
			writeError(w, http.StatusForbidden, "invalid jwt")
			return
		}
		writeJSON(w, http.StatusOK, f.authSecret(f.issueToken()))
	})

	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Vault-Token")
		if !f.isValid(tok) {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"data": map[string]interface{}{
				"id":        tok,
				"ttl":       3600,
				"renewable": true,
			},
		})
	})

	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Vault-Token")
		if !f.isValid(tok) {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
		writeJSON(w, http.StatusOK, f.authSecret(tok))
	})

	mux.HandleFunc("/v1/transit/keys/mykey", func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Vault-Token")
		if !f.isValid(tok) {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			der, err := x509.MarshalPKIXPublicKey(f.currentKey().Public())
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"data": map[string]interface{}{
					"name":           "mykey",
					"latest_version": float64(1),
					"keys": map[string]interface{}{
						"1": map[string]interface{}{"public_key": string(pubPEM)},
					},
				},
			})
		default:
			writeError(w, http.StatusMethodNotAllowed, "unsupported method")
		}
	})

	mux.HandleFunc("/v1/transit/sign/mykey", func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Vault-Token")
		if !f.isValid(tok) {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
		var body struct {
			Input     string `json:"input"`
			Prehashed bool   `json:"prehashed"`
			HashAlgo  string `json:"hash_algorithm"`
			SigAlgo   string `json:"signature_algorithm"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !body.Prehashed || body.HashAlgo != "sha2-256" {
			writeError(w, http.StatusBadRequest, "test fake only supports prehashed sha2-256")
			return
		}
		digest, err := base64.StdEncoding.DecodeString(body.Input)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad input encoding")
			return
		}
		sig, err := f.signDigest(digest, body.SigAlgo)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"data": map[string]interface{}{
				"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig),
			},
		})
	})

	return httptest.NewServer(mux)
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	return path
}

func TestSignAndVerify_AppRole(t *testing.T) {
	fake := newFakeOpenBao(t)
	srv := fake.server()
	defer srv.Close()

	secretIDFile := writeTempFile(t, "my-secret-id")
	cfg := openbao.Config{
		Addr:       srv.URL,
		KeyName:    "mykey",
		AuthMethod: openbao.AuthAppRole,

		AppRoleRoleID:       "my-role-id",
		AppRoleSecretIDFile: secretIDFile,
	}

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

	digest := sha256.Sum256([]byte("hello world"))
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Public() returned %T, want *rsa.PublicKey", signer.Public())
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
}

func TestSignAndVerify_ECDSA(t *testing.T) {
	// The shared fake signs with RSA; drive the ECDSA branch of Signer.sign
	// (signature_algorithm omitted) and decodeTransitSignature's DER path with
	// an ECDSA-keyed fake, then verify the returned ASN.1 signature.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}
	fake := newFakeOpenBaoWithKey(t, ecKey)
	srv := fake.server()
	defer srv.Close()

	cfg := openbao.Config{
		Addr:                srv.URL,
		KeyName:             "mykey",
		AuthMethod:          openbao.AuthAppRole,
		AppRoleRoleID:       "my-role-id",
		AppRoleSecretIDFile: writeTempFile(t, "my-secret-id"),
	}

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

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() returned %T, want *ecdsa.PublicKey", signer.Public())
	}

	digest := sha256.Sum256([]byte("ecdsa over transit"))
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatalf("ECDSA signature did not verify")
	}
}

func TestSignAndVerify_RSAPSS(t *testing.T) {
	// Drive the RSA-PSS branch of Signer.sign (signature_algorithm=pss),
	// selected by passing *rsa.PSSOptions, and verify the returned signature
	// as PSS rather than PKCS#1 v1.5.
	fake := newFakeOpenBao(t)
	srv := fake.server()
	defer srv.Close()

	cfg := openbao.Config{
		Addr:                srv.URL,
		KeyName:             "mykey",
		AuthMethod:          openbao.AuthAppRole,
		AppRoleRoleID:       "my-role-id",
		AppRoleSecretIDFile: writeTempFile(t, "my-secret-id"),
	}

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

	digest := sha256.Sum256([]byte("pss over transit"))
	pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	sig, err := signer.Sign(nil, digest[:], pssOpts)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub := signer.Public().(*rsa.PublicKey)
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, pssOpts); err != nil {
		t.Fatalf("PSS signature did not verify: %v", err)
	}
}

func TestKubernetesAuth_RereadsJWTOnEveryLogin(t *testing.T) {
	fake := newFakeOpenBao(t)
	srv := fake.server()
	defer srv.Close()

	jwtFile := writeTempFile(t, "jwt-v1")
	cfg := openbao.Config{
		Addr:       srv.URL,
		KeyName:    "mykey",
		AuthMethod: openbao.AuthKubernetes,
		K8sRole:    "my-role",
		K8sJWTFile: jwtFile,
	}

	ctx := context.Background()
	tm, err := openbao.NewTokenManager(ctx, cfg)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	defer tm.Close()

	fake.mu.Lock()
	firstJWT := fake.lastK8sJWT
	fake.mu.Unlock()
	if firstJWT != "jwt-v1" {
		t.Fatalf("first login JWT = %q, want %q", firstJWT, "jwt-v1")
	}

	// Simulate kubelet rotating the bound ServiceAccount token file in
	// place, then force a re-authentication the way the reactive 403 path
	// does. If the auth method cached the JWT at construction (the bug this
	// package works around in the upstream SDK's KubernetesAuth type),
	// this would still send "jwt-v1".
	if err := os.WriteFile(jwtFile, []byte("jwt-v2"), 0o600); err != nil {
		t.Fatalf("rotating jwt file: %v", err)
	}
	if err := tm.Reauth(ctx); err != nil {
		t.Fatalf("Reauth: %v", err)
	}

	fake.mu.Lock()
	secondJWT := fake.lastK8sJWT
	fake.mu.Unlock()
	if secondJWT != "jwt-v2" {
		t.Fatalf("re-login JWT = %q, want %q (JWT was not re-read from disk)", secondJWT, "jwt-v2")
	}
}

func TestSign_ReactiveReauthOn403(t *testing.T) {
	fake := newFakeOpenBao(t)
	srv := fake.server()
	defer srv.Close()

	tokenFile := writeTempFile(t, "token-v1")
	// Pre-seed the fake server's valid token set to match the file so the
	// initial lookup-self succeeds; NewTokenManager's login step will then
	// have already validated it once.
	fake.mu.Lock()
	fake.validTokens["token-v1"] = true
	fake.mu.Unlock()

	cfg := openbao.Config{
		Addr:       srv.URL,
		KeyName:    "mykey",
		AuthMethod: openbao.AuthToken,
		TokenFile:  tokenFile,
	}

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

	// Simulate the token being revoked out-of-band, and the operator
	// rotating the token file to a new one that the fake server will
	// accept. A naive implementation that read the token once at startup
	// and never again would keep failing; Sign's reactive Reauth should
	// notice the 403, re-read the file, and retry successfully.
	fake.revoke("token-v1")
	fake.mu.Lock()
	fake.validTokens["token-v2"] = true
	fake.mu.Unlock()
	if err := os.WriteFile(tokenFile, []byte("token-v2"), 0o600); err != nil {
		t.Fatalf("rotating token file: %v", err)
	}

	digest := sha256.Sum256([]byte("recovers after revocation"))
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign did not self-heal after token revocation: %v", err)
	}
	pub := signer.Public().(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
}

// TestTokenAuth_WatcherRenews proves the token-auth login re-shapes lookup-self
// into a renewable auth secret so the LifetimeWatcher actually renews the
// token. A raw lookup-self secret carries no auth/lease envelope, so the
// watcher would treat it as un-renewable, end immediately, and never call
// renew-self -- driving run() into a re-auth busy loop.
func TestTokenAuth_WatcherRenews(t *testing.T) {
	var lookups, renews int32

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&lookups, 1)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			// A short TTL so the watcher's renewal threshold is crossed
			// quickly and the test doesn't have to wait long.
			"data": map[string]interface{}{"id": "tok", "ttl": 1, "renewable": true},
		})
	})
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&renews, 1)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"auth": map[string]interface{}{"client_token": "tok", "lease_duration": 1, "renewable": true},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := openbao.Config{
		Addr:       srv.URL,
		KeyName:    "mykey",
		AuthMethod: openbao.AuthToken,
		TokenFile:  writeTempFile(t, "tok"),
	}
	ctx := context.Background()
	tm, err := openbao.NewTokenManager(ctx, cfg)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	defer tm.Close()

	// Within a few renewal cycles the watcher should have called renew-self at
	// least once. If the login handed the watcher a bare lookup-self secret,
	// it would instead re-login over and over -- lookups would climb and
	// renews would stay at zero.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&renews) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&renews); got == 0 {
		t.Fatalf("watcher never renewed the token (renew-self calls = 0, lookup-self calls = %d); "+
			"the token login is not producing a renewable secret",
			atomic.LoadInt32(&lookups))
	}
}

func TestKeyProvider_GenerateThenLoad_ECDSA(t *testing.T) {
	// This test uses a dedicated fake server whose transit key starts out
	// absent (Load must report ErrKeyProviderKeyNotFound) and is created on
	// Generate. The shared fakeOpenBao always answers GET with a key present,
	// so we build a tiny purpose-specific server here instead.
	var mu sync.Mutex
	var priv *ecdsa.PrivateKey
	created := false

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"auth": map[string]interface{}{"client_token": "tok", "lease_duration": 3600, "renewable": true},
		})
	})
	mux.HandleFunc("/v1/transit/keys/newkey", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			var body struct {
				Type string `json:"type"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Type != "ecdsa-p256" {
				writeError(w, http.StatusBadRequest, "unexpected type "+body.Type)
				return
			}
			mu.Lock()
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				mu.Unlock()
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			priv = k
			created = true
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			mu.Lock()
			ok := created
			var pubPEM []byte
			if ok {
				der, _ := x509.MarshalPKIXPublicKey(priv.Public())
				pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
			}
			mu.Unlock()
			if !ok {
				writeError(w, http.StatusNotFound, "key not found")
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"data": map[string]interface{}{
					"name":           "newkey",
					"latest_version": float64(1),
					"keys": map[string]interface{}{
						"1": map[string]interface{}{"public_key": string(pubPEM)},
					},
				},
			})
		default:
			writeError(w, http.StatusMethodNotAllowed, "unsupported method "+r.Method)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := openbao.Config{
		Addr:                srv.URL,
		KeyName:             "newkey",
		AuthMethod:          openbao.AuthAppRole,
		AppRoleRoleID:       "role",
		AppRoleSecretIDFile: writeTempFile(t, "secret"),
	}
	ctx := context.Background()
	tm, err := openbao.NewTokenManager(ctx, cfg)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	defer tm.Close()

	provider := openbao.NewKeyProvider(tm, cfg.EffectiveTransitMount(), cfg.KeyName)

	// Assert the exact sentinel CA.Init branches on (errors.Is), not just a
	// message containing "not found": a refactor that stopped wrapping the
	// sentinel but kept the words would still let the CA mistake a real
	// failure for "no key yet, safe to bootstrap".
	if _, err := provider.Load(ctx); !errors.Is(err, ca.ErrKeyProviderKeyNotFound) {
		t.Fatalf("Load before Generate: got err %v, want one wrapping ca.ErrKeyProviderKeyNotFound", err)
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
