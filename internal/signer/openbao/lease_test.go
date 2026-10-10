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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/openbao/openbao/api/v2"

	"github.com/voxpupuli/openvox-ca/internal/signer/openbao"
)

// revokeMode selects how lifecycleFake answers auth/token/revoke-self.
type revokeMode int

const (
	revokeAccept revokeMode = iota
	revokeRefuse
	revokeHang
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
	revoked   []string

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

	revoke  revokeMode
	unblock chan struct{} // closed to free a revokeHang handler

	// shortLived makes logins issue a token with a 1-second lease, renewable
	// or not as shortRenewable says. A non-renewable one's watcher ends on its
	// own almost at once.
	shortLived     bool
	shortRenewable bool

	// batch makes logins issue batch tokens, which carry no accessor.
	batch bool

	// slowRenewalRefusals makes renew-self wait longer than a short lease
	// before refusing, so the watcher gives up with an error.
	slowRenewalRefusals bool

	// refuseLogins makes every login fail; holdLogins makes each one wait
	// until releaseLogins is called. These, like every switch on the fake,
	// are set through its methods, because the server is already running by
	// the time a spec sets them.
	refuseLogins bool
	holdLogins   bool
	loginRelease chan struct{}
	releaseOnce  sync.Once
}

func newLifecycleFake() *lifecycleFake {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	return &lifecycleFake{
		key:          key,
		valid:        map[string]bool{operatorToken: true},
		refuseSign:   map[string]bool{},
		released:     make(chan struct{}),
		unblock:      make(chan struct{}),
		loginRelease: make(chan struct{}),
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

func (f *lifecycleFake) revokedTokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
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

// refuseEverySign makes Transit sign answer 403 for every token from now on.
func (f *lifecycleFake) refuseEverySign() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refuseAllSigns = true
}

// answerRevocations sets how revoke-self is answered from now on.
func (f *lifecycleFake) answerRevocations(mode revokeMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoke = mode
}

// issueShortLivedTokens makes every later login issue a short-lived token.
func (f *lifecycleFake) issueShortLivedTokens(renewable bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shortLived, f.shortRenewable = true, renewable
}

// refuseRenewalsSlowly makes every later renew-self outlast a short lease and
// then fail with 403.
func (f *lifecycleFake) refuseRenewalsSlowly() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.slowRenewalRefusals = true
}

// holdRefusedSigns makes refused signs wait until n of them are outstanding.
func (f *lifecycleFake) holdRefusedSigns(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.holdRefused = n
}

// refuseLoginsFromNow makes every later login fail with 403.
func (f *lifecycleFake) refuseLoginsFromNow() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refuseLogins = true
}

// acceptLoginsFromNow undoes refuseLoginsFromNow.
func (f *lifecycleFake) acceptLoginsFromNow() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refuseLogins = false
}

// issueBatchTokens makes every later login issue a batch token.
func (f *lifecycleFake) issueBatchTokens() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batch = true
}

// holdLoginsFromNow makes every later login wait for releaseLogins.
func (f *lifecycleFake) holdLoginsFromNow() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.holdLogins = true
}

func (f *lifecycleFake) releaseLogins() {
	f.releaseOnce.Do(func() { close(f.loginRelease) })
}

func (f *lifecycleFake) login(w http.ResponseWriter) {
	f.mu.Lock()
	f.logins++
	refuse, hold := f.refuseLogins, f.holdLogins
	f.mu.Unlock()
	if hold {
		select {
		case <-f.loginRelease:
		case <-time.After(5 * time.Second):
		}
	}
	if refuse {
		writeError(w, http.StatusForbidden, "invalid credentials")
		return
	}
	f.mu.Lock()
	f.nextToken++
	tok := fmt.Sprintf("minted-%d", f.nextToken)
	f.valid[tok] = true
	lease, renewable := 3600, true
	if f.shortLived {
		lease, renewable = 1, f.shortRenewable
	}
	accessor := "accessor-" + tok
	if f.batch {
		accessor = ""
	}
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"auth": map[string]interface{}{
			"client_token": tok, "accessor": accessor, "lease_duration": lease, "renewable": renewable,
		},
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
		ok, slow := f.valid[tok], f.slowRenewalRefusals
		f.mu.Unlock()
		if slow {
			select {
			case <-time.After(1500 * time.Millisecond):
			case <-r.Context().Done():
			}
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
		if !ok {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"auth": map[string]interface{}{"client_token": tok, "lease_duration": 3600, "renewable": true},
		})
	})
	mux.HandleFunc("/v1/auth/token/revoke-self", func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Vault-Token")
		f.mu.Lock()
		f.revoked = append(f.revoked, tok)
		mode := f.revoke
		if mode == revokeAccept {
			delete(f.valid, tok)
		}
		f.mu.Unlock()
		switch mode {
		case revokeAccept:
			w.WriteHeader(http.StatusNoContent)
		case revokeRefuse:
			writeError(w, http.StatusForbidden, "permission denied")
		case revokeHang:
			select {
			case <-f.unblock:
			case <-r.Context().Done():
			}
		}
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
		// Registered before any TokenManager's Close, so it runs after them:
		// a hung revoke or login handler is freed before the server waits for
		// it.
		DeferCleanup(func() {
			close(fake.unblock)
			fake.releaseLogins()
			srv.Close()
		})
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

	// captureLogs sends the default logger to a buffer for the rest of the
	// spec, at Debug so nothing a spec looks for is filtered out.
	captureLogs := func() *gbytes.Buffer {
		logs := gbytes.NewBuffer()
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
		DeferCleanup(slog.SetDefault, previous)
		return logs
	}

	verifies := func(signer crypto.Signer, sig []byte) bool {
		return ecdsa.VerifyASN1(signer.Public().(*ecdsa.PublicKey), digest, sig)
	}

	Describe("re-authentication after a 403 from Transit", func() {
		Context("when the previous login was less than the minimum interval ago", func() {
			It("fails with the 403 and a throttling error, without logging in again", func() {
				fake.refuseEverySign()
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
				fake.holdRefusedSigns(n)
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

		Context("when the 403 persists after a re-login", func() {
			DescribeTable("throttles the next 403 rather than logging in again",
				func(refuseRelogin bool, wantSigns int) {
					fake.refuseEverySign()
					tm := start(openbao.AuthAppRole)
					signer := load(tm)
					if refuseRelogin {
						fake.refuseLoginsFromNow()
					}
					openbao.ExpireReauthThrottleForTest(tm)

					_, err := signer.Sign(nil, digest, crypto.SHA256)
					Expect(err).To(HaveOccurred())
					Expect(err).NotTo(MatchError(openbao.ErrReauthThrottled), "the first 403 past the interval should try to log in")
					Expect(fake.loginCount()).To(Equal(2))

					_, err = signer.Sign(nil, digest, crypto.SHA256)

					Expect(err).To(MatchError(openbao.ErrReauthThrottled))
					Expect(fake.loginCount()).To(Equal(2), "the re-login attempt, successful or not, starts a new interval")
					Expect(fake.signCount()).To(Equal(wantSigns))
					// While the credential is bad, the throttle has to say
					// why the last login failed, or every issuance error would
					// read as a policy problem.
					Expect(strings.Contains(err.Error(), "invalid credentials")).To(Equal(refuseRelogin))
				},
				// A successful re-login retries the sign once; a failed one does
				// not, so the second Sign is the third or the second request.
				Entry("when the re-login succeeds", false, 3),
				Entry("when the re-login fails", true, 2),
			)
		})

		Context("when a failed re-login is followed by a successful one", func() {
			It("stops reporting the old login failure when it throttles", func() {
				fake.refuseEverySign()
				tm := start(openbao.AuthAppRole)
				signer := load(tm)

				fake.refuseLoginsFromNow()
				openbao.ExpireReauthThrottleForTest(tm)
				_, err := signer.Sign(nil, digest, crypto.SHA256)
				Expect(err).To(MatchError(ContainSubstring("invalid credentials")), "the re-login should have failed")

				fake.acceptLoginsFromNow()
				openbao.ExpireReauthThrottleForTest(tm)
				_, err = signer.Sign(nil, digest, crypto.SHA256)
				Expect(err).NotTo(MatchError(openbao.ErrReauthThrottled), "the re-login should have gone ahead")
				Expect(fake.loginCount()).To(Equal(3))

				_, err = signer.Sign(nil, digest, crypto.SHA256)

				Expect(err).To(MatchError(openbao.ErrReauthThrottled))
				Expect(err.Error()).NotTo(ContainSubstring("invalid credentials"), "a login that has since succeeded is not why this was throttled")
			})
		})

		Context("after a request-path re-login", func() {
			It("starts renewing the new token without the background loop logging in again", func() {
				logs := captureLogs()
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

				// The log has to say why the CA logged in, so it can be matched
				// against OpenBao's audit log, and must not claim a renewal
				// ended when the request path replaced the token.
				Expect(string(logs.Contents())).To(ContainSubstring(`msg="OpenBao refused a request with 403, re-authenticating"`))
				Expect(string(logs.Contents())).NotTo(ContainSubstring("renewal window closed"))
			})
		})
	})

	Describe("background re-authentication", func() {
		Context("when a watcher ends on its own", func() {
			It("logs that the renewal window closed and logs in again from the background loop", func() {
				logs := captureLogs()
				fake.issueShortLivedTokens(false)
				start(openbao.AuthAppRole)

				// The twin of "after a request-path re-login" above: a watcher
				// that was not replaced must still lead to a fresh login, and
				// say why.
				Eventually(fake.loginCount).WithTimeout(5 * time.Second).Should(Equal(2))
				Expect(string(logs.Contents())).To(ContainSubstring(`msg="OpenBao token renewal window closed, re-authenticating"`))
				Expect(string(logs.Contents())).NotTo(ContainSubstring(`msg="OpenBao refused a request with 403, re-authenticating"`))
			})
		})

		Context("when a watcher ends because renewal failed", func() {
			It("warns with the renewal error and logs in again from the background loop", func() {
				logs := captureLogs()
				fake.issueShortLivedTokens(true)
				fake.refuseRenewalsSlowly()
				start(openbao.AuthAppRole)

				// The watcher gives up with an error only once a failed
				// renewal has outlasted the lease, hence the slow refusal.
				Eventually(fake.loginCount).WithTimeout(5 * time.Second).Should(Equal(2))
				Expect(string(logs.Contents())).To(MatchRegexp(`level=WARN msg="OpenBao token renewal ended, re-authenticating" error=.*permission denied`))
			})
		})
	})

	Describe("Close", func() {
		DescribeTable("revokes a token this process logged in for",
			func(method openbao.AuthMethodKind) {
				tm := start(method)
				minted := tm.Client().Token()

				Expect(tm.Close()).To(Succeed())

				Expect(fake.revokedTokens()).To(ConsistOf(minted))
				Expect(fake.isValid(minted)).To(BeFalse())

				Expect(tm.Close()).To(Succeed())
				Expect(fake.revokedTokens()).To(ConsistOf(minted), "a second Close should not revoke again")
			},
			Entry("AppRole", openbao.AuthAppRole),
			Entry("Kubernetes", openbao.AuthKubernetes),
		)

		It("does not revoke an operator-supplied token from a token file", func() {
			tm := start(openbao.AuthToken)
			Expect(tm.Client().Token()).To(Equal(operatorToken))

			Expect(tm.Close()).To(Succeed())

			Expect(fake.revokedTokens()).To(BeEmpty())
			Expect(fake.isValid(operatorToken)).To(BeTrue())
		})

		It("does not try to revoke a batch token, which OpenBao cannot revoke", func() {
			logs := captureLogs()
			fake.issueBatchTokens()
			tm := start(openbao.AuthAppRole)

			Expect(tm.Close()).To(Succeed())

			Expect(fake.revokedTokens()).To(BeEmpty())
			Expect(string(logs.Contents())).NotTo(ContainSubstring("level=WARN"))
		})

		Context("when OpenBao refuses the revocation", func() {
			It("still succeeds, and warns without logging the token", func() {
				logs := captureLogs()
				fake.answerRevocations(revokeRefuse)
				tm := start(openbao.AuthAppRole)
				minted := tm.Client().Token()

				Expect(tm.Close()).To(Succeed())

				Expect(fake.revokedTokens()).To(ConsistOf(minted), "the revocation should have been attempted")
				Expect(string(logs.Contents())).To(MatchRegexp(`level=WARN msg="Failed to revoke the OpenBao token`))
				Expect(string(logs.Contents())).NotTo(ContainSubstring(minted))
			})
		})

		Context("when OpenBao does not answer the revocation", func() {
			It("gives up within about 2 seconds and still succeeds", func() {
				fake.answerRevocations(revokeHang)
				tm := start(openbao.AuthAppRole)

				began := time.Now()
				Expect(tm.Close()).To(Succeed())

				Expect(fake.revokedTokens()).To(HaveLen(1), "the revocation should have been attempted")
				// A literal, not revokeTimeout: the docs promise a revocation
				// gives up after 2 seconds, well inside the launcher's 5-second
				// budget for a surviving child, and raising the constant past
				// that has to fail here.
				Expect(time.Since(began)).To(BeNumerically("<", 3*time.Second))
			})
		})

		It("waits for a re-login in flight, then revokes the token that re-login minted", func() {
			tm := start(openbao.AuthAppRole)
			first := tm.Client().Token()
			fake.holdLoginsFromNow()
			openbao.ExpireReauthThrottleForTest(tm)

			reauthed := make(chan error, 1)
			go func() { reauthed <- tm.Reauth(context.Background(), first) }()
			Eventually(fake.loginCount).Should(Equal(2), "the re-login should be held at the server")

			closed := make(chan error, 1)
			go func() { closed <- tm.Close() }()
			Consistently(closed).WithTimeout(200*time.Millisecond).ShouldNot(Receive(), "Close should wait for the re-login")

			fake.releaseLogins()
			Eventually(reauthed).Should(Receive(BeNil()))
			Eventually(closed).Should(Receive(BeNil()))

			second := tm.Client().Token()
			Expect(second).NotTo(Equal(first))
			Expect(fake.revokedTokens()).To(ConsistOf(second))
			Expect(fake.isValid(first)).To(BeTrue(), "the replaced token is not this Close's to revoke")
		})

		It("refuses a later re-authentication rather than minting a token nothing would revoke", func() {
			tm := start(openbao.AuthAppRole)
			minted := tm.Client().Token()
			Expect(tm.Close()).To(Succeed())
			openbao.ExpireReauthThrottleForTest(tm)

			Expect(tm.Reauth(context.Background(), minted)).NotTo(Succeed())

			Expect(fake.loginCount()).To(Equal(1))
		})
	})
})
