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

package api_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"mime"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The Puppet CA API contract (#405): openvox-ca's responses checked against
// responses recorded from a real OpenVox Server (test/contract/record).
//
// openvox-ca may add to a response but may not take anything away or change
// its shape:
//   - the status code must match;
//   - where upstream sent a body, the media type must match, parameters
//     such as charset aside;
//   - every JSON field upstream sent must be present, recursively, with
//     the same JSON type;
//   - with compare "exact", every value must match as well. The store is
//     seeded with the CA and certificates the fixtures were recorded
//     against, so certificate-derived values (fingerprints, SANs, serials,
//     dates, auth extensions) can be compared exactly, which also pins
//     their formatting;
//   - extra fields are allowed, except in authorization_extensions, whose
//     keys are data: an extension upstream does not list is a difference.
//
// Error-body wording, full Content-Type headers and the order of
// certificate_statuses are recorded but not enforced.

const contractDir = "testdata/contract"

// contractFixture mirrors test/contract/record's fixture format.
type contractFixture struct {
	Name    string `json:"name"`
	Compare string `json:"compare"`
	Request struct {
		Method          string `json:"method"`
		Path            string `json:"path"`
		ContentType     string `json:"content_type"`
		Body            string `json:"body"`
		IfModifiedSince string `json:"if_modified_since"`
		Client          string `json:"client"`
	} `json:"request"`
	Response contractResponse `json:"response"`
}

type contractResponse struct {
	Status      int             `json:"status"`
	ContentType string          `json:"content_type"`
	JSON        json.RawMessage `json:"json"`
	Text        *string         `json:"text"`
}

// contractException is a known difference from the recorded response. Each
// names the difference it covers and why it is allowed: an open issue it is
// tracked under, or a ruling to keep openvox-ca's behaviour. A fixture's
// differences must all be covered, and every exception must still cover
// one, so fixing a difference forces its exception out.
type contractException struct {
	// Prefix matches the start of a difference as checkContract reports it.
	Prefix string
	Reason string
}

var contractExceptions = map[string][]contractException{
	"status-signed-dns":   {fingerprintsSHA1SHA512("$")},
	"status-signed-nosan": {fingerprintsSHA1SHA512("$")},
	"status-revoked":      {fingerprintsSHA1SHA512("$")},
	"status-requested":    {fingerprintsSHA1SHA512("$")},
	"status-cert-and-csr": {fingerprintsSHA1SHA512("$")},
	"status-signed-ip": {
		fingerprintsSHA1SHA512("$"),
		{"$.subject_alt_names", "#407: IP SANs are not listed"},
	},
	"status-signed-ext": {
		fingerprintsSHA1SHA512("$"),
		{`$.authorization_extensions["1.3.6.1.4.1.34380.1.3.2"]: missing`, "#408: keyed pp_auth_auto_renew, upstream keys it by OID"},
		{`$.authorization_extensions.pp_auth_auto_renew: not in upstream`, "#408: keyed pp_auth_auto_renew, upstream keys it by OID"},
		{`$.authorization_extensions["1.3.6.1.4.1.34380.1.3"]: not in upstream`, "#409: the bare auth arc OID is listed"},
		{`$.authorization_extensions["1.3.6.1.4.1.34380.1.3.98"]: value`, "kept: a non-DER value renders as hex (survey 16)"},
	},
	"status-unknown": {{"media type", "kept: the 404 is text/plain where upstream's header says JSON (survey 44)"}},
	"statuses-all": {
		fingerprintsSHA1SHA512("$[*]"),
		{`$[name=corner-ip,state=signed].subject_alt_names`, "#407: IP SANs are not listed"},
		{`$[name=corner-ext,state=signed].authorization_extensions["1.3.6.1.4.1.34380.1.3.2"]: missing`, "#408"},
		{`$[name=corner-ext,state=signed].authorization_extensions.pp_auth_auto_renew: not in upstream`, "#408"},
		{`$[name=corner-ext,state=signed].authorization_extensions["1.3.6.1.4.1.34380.1.3"]: not in upstream`, "#409"},
		{`$[name=corner-ext,state=signed].authorization_extensions["1.3.6.1.4.1.34380.1.3.98"]: value`, "kept (survey 16)"},
		{`$[name=corner-both,state=requested]: missing`, "kept: a CSR behind a live certificate is not listed (survey 6)"},
	},
	"statuses-requested": {
		fingerprintsSHA1SHA512("$[*]"),
		{`$[name=corner-both,state=requested]: missing`, "kept (survey 6)"},
	},
	"statuses-signed": {
		fingerprintsSHA1SHA512("$[*]"),
		{`$[name=corner-ip,state=signed].subject_alt_names`, "#407"},
		{`$[name=corner-ext,state=signed].authorization_extensions["1.3.6.1.4.1.34380.1.3.2"]: missing`, "#408"},
		{`$[name=corner-ext,state=signed].authorization_extensions.pp_auth_auto_renew: not in upstream`, "#408"},
		{`$[name=corner-ext,state=signed].authorization_extensions["1.3.6.1.4.1.34380.1.3"]: not in upstream`, "#409"},
		{`$[name=corner-ext,state=signed].authorization_extensions["1.3.6.1.4.1.34380.1.3.98"]: value`, "kept (survey 16)"},
	},
	"statuses-revoked":                      {fingerprintsSHA1SHA512("$[*]")},
	"certificate-get-not-modified":          {{"status", "#414: If-Modified-Since is not honoured"}},
	"status-put-revoke-unknown":             {{"status", "#358 (PR #372): revoking an unknown subject answers 409"}},
	"status-put-sign-without-csr":           {{"status", "#411: signing without a CSR answers 404"}},
	"certificate-request-put-existing-cert": {{"status", "#410: a CSR over a live certificate is accepted"}},
	"sign-empty":                            {{"status", "#412: an empty certnames answers 400"}},
	"sign-missing-certnames":                {{"status", "#412: a missing certnames answers 400"}},
	"sign-non-list":                         {{"status", "#412: a non-list certnames answers 400"}},
	"clean":                                 {{"media type", "kept: PUT /clean answers JSON (survey 2)"}},
}

func fingerprintsSHA1SHA512(at string) contractException {
	return contractException{at + ".fingerprints", "#406: fingerprints lacks SHA1 and SHA512"}
}

// --- the checker ---------------------------------------------------------------

// checkContract compares a response with the recorded one and returns every
// difference the contract forbids, each beginning with where it is.
func checkContract(f contractFixture, status int, contentType string, body []byte) []string {
	// A different status is a different outcome, whose body cannot be
	// compared with upstream's; report that alone.
	if status != f.Response.Status {
		return []string{fmt.Sprintf("status: %d, upstream %d", status, f.Response.Status)}
	}
	var diffs []string
	upstreamHasBody := len(f.Response.JSON) > 0 || (f.Response.Text != nil && *f.Response.Text != "")
	if upstreamHasBody && mediaType(contentType) != mediaType(f.Response.ContentType) {
		diffs = append(diffs, fmt.Sprintf("media type: %q, upstream %q", mediaType(contentType), mediaType(f.Response.ContentType)))
	}
	if f.Compare == "none" {
		return diffs
	}
	if len(f.Response.JSON) > 0 {
		var want, got any
		mustDecode(f.Response.JSON, &want)
		if err := decodeNumbers(body, &got); err != nil {
			return append(diffs, "body: not JSON")
		}
		diffs = append(diffs, compareJSON("$", want, got, f.Compare == "exact")...)
	} else if f.Response.Text != nil && f.Compare == "exact" && string(body) != *f.Response.Text {
		diffs = append(diffs, "body: text differs")
	}
	return diffs
}

func mediaType(ct string) string {
	if ct == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return ct
	}
	return mt
}

func mustDecode(b []byte, v any) {
	Expect(decodeNumbers(b, v)).To(Succeed())
}

// decodeNumbers keeps numbers as their literal digits, so a 128-bit serial is
// compared exactly rather than through a float64.
func decodeNumbers(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	return d.Decode(v)
}

func jsonType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case json.Number:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

// closedMaps are objects whose keys are data rather than fields, so an extra
// key is a difference too.
var closedMaps = map[string]bool{"authorization_extensions": true}

func compareJSON(at string, want, got any, exact bool) []string {
	if jsonType(want) != jsonType(got) {
		return []string{fmt.Sprintf("%s: type %s, upstream %s", at, jsonType(got), jsonType(want))}
	}
	switch w := want.(type) {
	case map[string]any:
		g := got.(map[string]any)
		var diffs []string
		for _, k := range sortedKeys(w) {
			gv, ok := g[k]
			if !ok {
				diffs = append(diffs, fmt.Sprintf("%s: missing", field(at, k)))
				continue
			}
			diffs = append(diffs, compareJSON(field(at, k), w[k], gv, exact)...)
		}
		if exact && closedMaps[lastField(at)] {
			for _, k := range sortedKeys(g) {
				if _, ok := w[k]; !ok {
					diffs = append(diffs, fmt.Sprintf("%s: not in upstream", field(at, k)))
				}
			}
		}
		return diffs
	case []any:
		g := got.([]any)
		if keyed, ok := keyByNameState(w); ok {
			if gk, ok := keyByNameState(g); ok {
				return compareKeyed(at, keyed, gk, exact)
			}
		}
		if !exact {
			var diffs []string
			for i := range min(len(w), len(g)) {
				diffs = append(diffs, compareJSON(fmt.Sprintf("%s[%d]", at, i), w[i], g[i], false)...)
			}
			return diffs
		}
		if len(w) != len(g) {
			return []string{fmt.Sprintf("%s: %d entries, upstream %d", at, len(g), len(w))}
		}
		var diffs []string
		for i := range w {
			diffs = append(diffs, compareJSON(fmt.Sprintf("%s[%d]", at, i), w[i], g[i], exact)...)
		}
		return diffs
	default:
		if exact && fmt.Sprint(want) != fmt.Sprint(got) {
			return []string{fmt.Sprintf("%s: value %v, upstream %v", at, got, want)}
		}
		return nil
	}
}

// keyByNameState indexes a certificate_statuses-style list by name and state,
// the pair that identifies an entry: upstream lists a subject twice when it
// holds both a certificate and a CSR.
func keyByNameState(list []any) (map[string]any, bool) {
	if len(list) == 0 {
		return nil, false
	}
	out := map[string]any{}
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, false
		}
		name, ok1 := m["name"].(string)
		state, ok2 := m["state"].(string)
		if !ok1 || !ok2 {
			return nil, false
		}
		out[fmt.Sprintf("name=%s,state=%s", name, state)] = m
	}
	return out, true
}

func compareKeyed(at string, want, got map[string]any, exact bool) []string {
	var diffs []string
	for _, k := range sortedKeys(want) {
		gv, ok := got[k]
		if !ok {
			diffs = append(diffs, fmt.Sprintf("%s[%s]: missing", at, k))
			continue
		}
		diffs = append(diffs, compareJSON(fmt.Sprintf("%s[%s]", at, k), want[k], gv, exact)...)
	}
	if exact {
		for _, k := range sortedKeys(got) {
			if _, ok := want[k]; !ok {
				diffs = append(diffs, fmt.Sprintf("%s[%s]: not in upstream", at, k))
			}
		}
	}
	return diffs
}

func field(at, k string) string {
	if strings.ContainsAny(k, ".-") {
		return fmt.Sprintf("%s[%q]", at, k)
	}
	return at + "." + k
}

func lastField(at string) string {
	i := strings.LastIndexAny(at, ".]")
	if i < 0 || at[i] == ']' {
		return ""
	}
	return at[i+1:]
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// covered reports whether diff is allowed by one of exceptions, and records
// which exceptions were used.
func covered(diff string, exceptions []contractException, used map[int]bool) bool {
	for i, e := range exceptions {
		if exceptionMatches(e.Prefix, diff) {
			used[i] = true
			return true
		}
	}
	return false
}

// exceptionMatches matches a difference by prefix. "[*]" in the prefix
// stands for any one list entry.
func exceptionMatches(prefix, diff string) bool {
	head, tail, wildcard := strings.Cut(prefix, "[*]")
	if !wildcard {
		return strings.HasPrefix(diff, prefix)
	}
	if !strings.HasPrefix(diff, head+"[") {
		return false
	}
	rest := diff[len(head)+1:]
	end := strings.Index(rest, "]")
	return end >= 0 && strings.HasPrefix(rest[end+1:], tail)
}

// --- the openvox-ca under test ---------------------------------------------

// loadContractFixtures runs while the spec tree is built, where Gomega cannot,
// so a fixture that will not load panics instead.
func loadContractFixtures() []contractFixture {
	paths, err := filepath.Glob(filepath.Join(contractDir, "fixtures", "*.json"))
	if err != nil || len(paths) == 0 {
		panic(fmt.Sprintf("no contract fixtures in %s (run go run ./test/contract/record): %v", contractDir, err))
	}
	var fs []contractFixture
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			panic(err)
		}
		var f contractFixture
		if err := json.Unmarshal(b, &f); err != nil {
			panic(fmt.Sprintf("%s: %v", p, err))
		}
		fs = append(fs, f)
	}
	return fs
}

// seedContractCA gives a fresh openvox-ca the store the fixtures were
// recorded against: OpenVox Server's own CA bundle, key and CRL chain, and
// every certificate and CSR it held.
func seedContractCA(dir string) *api.Server {
	ctx := context.Background()
	src := filepath.Join(contractDir, "cadir")
	read := func(rel string) []byte {
		b, err := os.ReadFile(filepath.Join(src, rel))
		Expect(err).NotTo(HaveOccurred())
		return b
	}

	store := storage.New(dir)
	Expect(store.EnsureDirs(ctx)).To(Succeed())
	Expect(store.SaveCACert(ctx, read("ca_crt.pem"))).To(Succeed())
	Expect(store.SaveCAKey(ctx, read("ca_key.pem"))).To(Succeed())
	Expect(store.UpdateCRL(ctx, read("ca_crl.pem"))).To(Succeed())
	Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
	Expect(store.TouchInventory(ctx)).To(Succeed())

	signed, err := os.ReadDir(filepath.Join(src, "signed"))
	Expect(err).NotTo(HaveOccurred())
	for _, e := range signed {
		subject := strings.TrimSuffix(e.Name(), ".pem")
		certPEM := read(filepath.Join("signed", e.Name()))
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCert(ctx, subject, certPEM)).To(Succeed())
		Expect(store.AppendInventory(ctx, fmt.Sprintf("%X %s %s /%s", cert.SerialNumber,
			cert.NotBefore.UTC().Format(storage.InventoryTimeFormat),
			cert.NotAfter.UTC().Format(storage.InventoryTimeFormat), subject))).To(Succeed())
	}
	requests, err := os.ReadDir(filepath.Join(src, "requests"))
	Expect(err).NotTo(HaveOccurred())
	for _, e := range requests {
		Expect(store.SaveCSR(ctx, strings.TrimSuffix(e.Name(), ".pem"), read(filepath.Join("requests", e.Name())))).To(Succeed())
	}

	myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet")
	Expect(myCA.Init(ctx)).To(Succeed())
	srv := api.New(myCA)
	// Upstream's date layout is openvox-ca's opt-in (survey 13).
	srv.PuppetDateTimeFormat = true
	return srv
}

// serveContract drives openvox-ca with a fixture's request.
func serveContract(srv *api.Server, f contractFixture) *httptest.ResponseRecorder {
	var body *strings.Reader
	if f.Request.Body != "" {
		body = strings.NewReader(f.Request.Body)
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(f.Request.Method, f.Request.Path, body)
	if f.Request.ContentType != "" {
		req.Header.Set("Content-Type", f.Request.ContentType)
	}
	if f.Request.IfModifiedSince != "" {
		req.Header.Set("If-Modified-Since", f.Request.IfModifiedSince)
	}
	if f.Request.Client == "renewer" {
		certPEM, err := os.ReadFile(filepath.Join(contractDir, "cadir", "signed", "renew-me.pem"))
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	return rr
}

// --- the specs -------------------------------------------------------------

var _ = Describe("Puppet CA API contract", func() {
	for _, f := range loadContractFixtures() {
		It("answers "+f.Name+" as OpenVox Server does", func() {
			srv := seedContractCA(GinkgoT().TempDir())
			rr := serveContract(srv, f)
			diffs := checkContract(f, rr.Code, rr.Header().Get("Content-Type"), rr.Body.Bytes())

			exceptions := contractExceptions[f.Name]
			used := map[int]bool{}
			var unexplained []string
			for _, d := range diffs {
				if !covered(d, exceptions, used) {
					unexplained = append(unexplained, d)
				}
			}
			Expect(unexplained).To(BeEmpty(),
				"differences from OpenVox Server with no exception; body:\n%s", rr.Body.String())

			var stale []string
			for i, e := range exceptions {
				if !used[i] {
					stale = append(stale, e.Prefix+" ("+e.Reason+")")
				}
			}
			Expect(stale).To(BeEmpty(),
				"exceptions that no longer match a difference; remove them")
		})
	}

	It("has an exception list only for fixtures that exist", func() {
		names := map[string]bool{}
		for _, f := range loadContractFixtures() {
			names[f.Name] = true
		}
		for name := range contractExceptions {
			Expect(names).To(HaveKey(name))
		}
	})
})

// The checker must be able to fail: a checker that accepted everything would
// pass every spec above. Each twin takes a response that satisfies the
// contract and breaks it one way.
var _ = Describe("the contract checker", func() {
	text := "PEM\n"
	upstream := contractFixture{Compare: "exact"}
	upstream.Response = contractResponse{
		Status:      200,
		ContentType: "application/json;charset=UTF-8",
		JSON: json.RawMessage(`{"name":"n","serial_number":211659643165621965746051058369188784120,
			"fingerprints":{"SHA256":"AA:BB"},"dns_alt_names":["DNS:n"],
			"authorization_extensions":{"pp_cli_auth":"true"}}`),
	}
	conforming := `{"name":"n","serial_number":211659643165621965746051058369188784120,
		"fingerprints":{"SHA256":"AA:BB","extra":"x"},"dns_alt_names":["DNS:n"],
		"authorization_extensions":{"pp_cli_auth":"true"},"added":true}`

	It("accepts a conforming response, extra fields included", func() {
		Expect(checkContract(upstream, 200, "application/json", []byte(conforming))).To(BeEmpty())
	})

	DescribeTable("rejects a response that breaks the contract",
		func(status int, contentType, body, want string) {
			Expect(checkContract(upstream, status, contentType, []byte(body))).To(
				ContainElement(HavePrefix(want)))
		},
		Entry("a different status", 404, "application/json", conforming, "status"),
		Entry("a different media type", 200, "text/plain", conforming, "media type"),
		Entry("a removed field", 200, "application/json",
			strings.Replace(conforming, `"name":"n",`, "", 1), "$.name: missing"),
		Entry("a removed nested field", 200, "application/json",
			strings.Replace(conforming, `"SHA256":"AA:BB",`, "", 1), "$.fingerprints.SHA256: missing"),
		Entry("a changed type", 200, "application/json",
			strings.Replace(conforming, `211659643165621965746051058369188784120`, `"211659643165621965746051058369188784120"`, 1),
			"$.serial_number: type string, upstream number"),
		Entry("a changed value", 200, "application/json",
			strings.Replace(conforming, `"DNS:n"`, `"n"`, 1), "$.dns_alt_names[0]: value"),
		Entry("a changed digit in a large number", 200, "application/json",
			strings.Replace(conforming, `120,`, `121,`, 1), "$.serial_number: value"),
		Entry("an authorisation extension upstream does not list", 200, "application/json",
			strings.Replace(conforming, `{"pp_cli_auth":"true"}`, `{"pp_cli_auth":"true","pp_auth_role":"x"}`, 1),
			`$.authorization_extensions.pp_auth_role: not in upstream`),
		Entry("a body that is not JSON", 200, "application/json", "nope", "body: not JSON"),
	)

	It("compares an exact text body", func() {
		f := contractFixture{Compare: "exact", Response: contractResponse{Status: 200, ContentType: "text/plain", Text: &text}}
		Expect(checkContract(f, 200, "text/plain", []byte(text))).To(BeEmpty())
		Expect(checkContract(f, 200, "text/plain", []byte("other\n"))).To(ContainElement("body: text differs"))
	})

	It("binds only types under compare types", func() {
		f := upstream
		f.Compare = "types"
		Expect(checkContract(f, 200, "application/json",
			[]byte(strings.Replace(conforming, `"DNS:n"`, `"n"`, 1)))).To(BeEmpty())
		Expect(checkContract(f, 200, "application/json",
			[]byte(strings.Replace(conforming, `"name":"n"`, `"name":1`, 1)))).To(
			ContainElement(HavePrefix("$.name: type number")))
	})

	It("matches a list of statuses by name and state, not by order", func() {
		f := contractFixture{Compare: "exact", Response: contractResponse{Status: 200, ContentType: "application/json",
			JSON: json.RawMessage(`[{"name":"a","state":"signed"},{"name":"a","state":"requested"},{"name":"b","state":"signed"}]`)}}
		Expect(checkContract(f, 200, "application/json",
			[]byte(`[{"name":"b","state":"signed"},{"name":"a","state":"requested"},{"name":"a","state":"signed"}]`))).To(BeEmpty())
		Expect(checkContract(f, 200, "application/json",
			[]byte(`[{"name":"b","state":"signed"},{"name":"a","state":"signed"}]`))).To(
			ConsistOf("$[name=a,state=requested]: missing"))
	})

	It("ignores the media type of an empty upstream body", func() {
		empty := ""
		f := contractFixture{Compare: "none", Response: contractResponse{Status: 204, ContentType: "text/plain", Text: &empty}}
		Expect(checkContract(f, 204, "", nil)).To(BeEmpty())
	})

	It("matches an exception's [*] against any one list entry", func() {
		Expect(exceptionMatches("$[*].fingerprints", "$[name=a,state=signed].fingerprints.SHA1: missing")).To(BeTrue())
		Expect(exceptionMatches("$[*].fingerprints", "$[name=a,state=signed].dns_alt_names[0]: value")).To(BeFalse())
	})
})
