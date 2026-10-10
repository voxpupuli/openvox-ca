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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/openbao/openbao/api/v2"

	"github.com/voxpupuli/openvox-ca/internal/signer/openbao"
)

// operatorToken is the token a token_file holds in these specs: one this
// process did not mint and must never revoke.
const operatorToken = "operator-token"

// lifecycleFake stands in for the OpenBao endpoints a token's lifecycle
// touches — login, lookup, renewal and revocation — plus enough of Transit to
// sign with, and counts what it is asked to do. openbao_test.go's fakeOpenBao
// is bound to *testing.T, which Ginkgo nodes do not have.
type lifecycleFake struct {
	key *ecdsa.PrivateKey

	mu        sync.Mutex
	nextToken int
	valid     map[string]bool
	logins    int
	signs     int
	renewed   []string

	// refuseSign lists tokens Transit sign answers 403 for, whatever their
	// validity elsewhere; refuseAllSigns refuses every token, as a policy that
	// no longer grants Transit would.
	refuseSign     map[string]bool
	refuseAllSigns bool

	// holdRefused, when positive, makes each refused sign wait until that many
	// have arrived, so they are all outstanding at once before any is answered.
	holdRefused int
	refusedIn   int
	released    chan struct{}
}

func newLifecycleFake() *lifecycleFake {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	return &lifecycleFake{
		key:        key,
		valid:      map[string]bool{operatorToken: true},
		refuseSign: map[string]bool{},
		released:   make(chan struct{}),
	}
}

func (f *lifecycleFake) loginCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logins
}

func (f *lifecycleFake) signCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.signs
}

func (f *lifecycleFake) renewedTokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.renewed...)
}

func (f *lifecycleFake) isValid(tok string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.valid[tok]
}

// refuseSignsWith makes Transit sign answer 403 for tok from now on.
func (f *lifecycleFake) refuseSignsWith(tok string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refuseSign[tok] = true
}

func (f *lifecycleFake) login(w http.ResponseWriter) {
	f.mu.Lock()
	f.logins++
	f.nextToken++
	tok := fmt.Sprintf("minted-%d", f.nextToken)
	f.valid[tok] = true
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"auth": map[string]interface{}{"client_token": tok, "lease_duration": 3600, "renewable": true},
	})
}

// awaitRefusalQuorum blocks a refused sign until holdRefused of them have
// arrived (or a generous timeout passes, so a broken spec fails rather than
// hangs).
func (f *lifecycleFake) awaitRefusalQuorum() {
	f.mu.Lock()
	if f.holdRefused == 0 {
		f.mu.Unlock()
		return
	}
	f.refusedIn++
	if f.refusedIn == f.holdRefused {
		close(f.released)
	}
	f.mu.Unlock()
	select {
	case <-f.released:
	case <-time.After(5 * time.Second):
	}
}

func (f *lifecycleFake) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, _ *http.Request) { f.login(w) })
	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, _ *http.Request) { f.login(w) })
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Vault-Token")
		if !f.isValid(tok) {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"data": map[string]interface{}{"id": tok, "ttl": 3600, "renewable": true},
		})
	})
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Vault-Token")
		f.mu.Lock()
		f.renewed = append(f.renewed, tok)
		ok := f.valid[tok]
		f.mu.Unlock()
		if !ok {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"auth": map[string]interface{}{"client_token": tok, "lease_duration": 3600, "renewable": true},
		})
	})
	mux.HandleFunc("/v1/transit/keys/mykey", func(w http.ResponseWriter, _ *http.Request) {
		der, err := x509.MarshalPKIXPublicKey(f.key.Public())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"data": map[string]interface{}{
				"name":           "mykey",
				"latest_version": json.Number("1"),
				"keys":           map[string]interface{}{"1": map[string]interface{}{"public_key": string(pubPEM)}},
			},
		})
	})
	mux.HandleFunc("/v1/transit/sign/mykey", func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Vault-Token")
		f.mu.Lock()
		f.signs++
		refused := f.refuseAllSigns || f.refuseSign[tok] || !f.valid[tok]
		f.mu.Unlock()
		if refused {
			f.awaitRefusalQuorum()
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
		var body struct {
			Input string `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		digest, err := base64.StdEncoding.DecodeString(body.Input)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"data": map[string]interface{}{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig)},
		})
	})
	return httptest.NewServer(mux)
}

// secretFile writes content to a fresh private file and returns its path.
func secretFile(content string) string {
	path := filepath.Join(GinkgoT().TempDir(), "secret")
	Expect(os.WriteFile(path, []byte(content), 0o600)).To(Succeed())
	return path
}

var _ = Describe("OpenBao token lifecycle", func() {
	var (
		fake   *lifecycleFake
		srv    *httptest.Server
		digest []byte
	)

	BeforeEach(func() {
		fake = newLifecycleFake()
		srv = fake.server()
		DeferCleanup(srv.Close)
		sum := sha256.Sum256([]byte("openvox-ca token lifecycle"))
		digest = sum[:]
	})

	configFor := func(method openbao.AuthMethodKind) openbao.Config {
		cfg := openbao.Config{Addr: srv.URL, KeyName: "mykey", AuthMethod: method}
		switch method {
		case openbao.AuthAppRole:
			cfg.AppRoleRoleID = "role"
			cfg.AppRoleSecretIDFile = secretFile("secret-id")
		case openbao.AuthKubernetes:
			cfg.K8sRole = "role"
			cfg.K8sJWTFile = secretFile("service-account-jwt")
		case openbao.AuthToken:
			cfg.TokenFile = secretFile(operatorToken)
		}
		return cfg
	}

	start := func(method openbao.AuthMethodKind) *openbao.TokenManager {
		tm, err := openbao.NewTokenManager(context.Background(), configFor(method))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(tm.Close)
		return tm
	}

	load := func(tm *openbao.TokenManager) crypto.Signer {
		signer, err := openbao.NewKeyProvider(tm, "transit", "mykey").Load(context.Background())
		Expect(err).NotTo(HaveOccurred())
		return signer
	}

	verifies := func(signer crypto.Signer, sig []byte) bool {
		return ecdsa.VerifyASN1(signer.Public().(*ecdsa.PublicKey), digest, sig)
	}

	Describe("re-authentication after a 403 from Transit", func() {
		Context("when the previous login was less than the minimum interval ago", func() {
			It("fails with the 403 and a throttling error, without logging in again", func() {
				fake.refuseAllSigns = true
				signer := load(start(openbao.AuthAppRole))
				Expect(fake.loginCount()).To(Equal(1))

				_, err := signer.Sign(nil, digest, crypto.SHA256)

				Expect(err).To(MatchError(openbao.ErrReauthThrottled))
				var respErr *api.ResponseError
				Expect(errors.As(err, &respErr)).To(BeTrue(), "the 403 itself should still be in the chain")
				Expect(respErr.StatusCode).To(Equal(http.StatusForbidden))
				Expect(fake.loginCount()).To(Equal(1), "a throttled 403 must not log in")
				Expect(fake.signCount()).To(Equal(1), "a throttled 403 must not be retried")
			})
		})

		Context("when the previous login was longer than the minimum interval ago", func() {
			It("logs in again and retries the request with the new token", func() {
				tm := start(openbao.AuthAppRole)
				signer := load(tm)
				fake.refuseSignsWith(tm.Client().Token())
				openbao.ExpireReauthThrottleForTest(tm)

				sig, err := signer.Sign(nil, digest, crypto.SHA256)

				Expect(err).NotTo(HaveOccurred())
				Expect(verifies(signer, sig)).To(BeTrue())
				Expect(fake.loginCount()).To(Equal(2))
			})
		})

		Context("when several requests are refused with the same token at once", func() {
			It("logs in once, and every request succeeds with the new token", func() {
				const n = 8
				tm := start(openbao.AuthAppRole)
				signer := load(tm)
				fake.refuseSignsWith(tm.Client().Token())
				fake.holdRefused = n
				openbao.ExpireReauthThrottleForTest(tm)

				errs := make([]error, n)
				var wg sync.WaitGroup
				for i := range n {
					wg.Add(1)
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						_, errs[i] = signer.Sign(nil, digest, crypto.SHA256)
					}()
				}
				wg.Wait()

				Expect(errs).To(HaveEach(BeNil()))
				Expect(fake.loginCount()).To(Equal(2), "the initial login plus exactly one re-login")
			})
		})

		Context("after a request-path re-login", func() {
			It("starts renewing the new token without the background loop logging in again", func() {
				tm := start(openbao.AuthAppRole)
				signer := load(tm)
				first := tm.Client().Token()
				fake.refuseSignsWith(first)
				openbao.ExpireReauthThrottleForTest(tm)

				_, err := signer.Sign(nil, digest, crypto.SHA256)
				Expect(err).NotTo(HaveOccurred())
				second := tm.Client().Token()
				Expect(second).NotTo(Equal(first))

				// A LifetimeWatcher renews as soon as it starts, so the new
				// token being renewed is the sign that its watcher is running.
				Eventually(fake.renewedTokens).WithTimeout(5 * time.Second).Should(ContainElement(second))
				Expect(fake.loginCount()).To(Equal(2))
			})
		})
	})
})
