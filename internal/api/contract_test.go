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
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"mime"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

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
// Error-body wording, the response headers other than the media type, and
// the order of certificate_statuses are recorded but not enforced, as is
// the media type of a request no route serves. Who may reach a route is the
// authorisation baseline's business (authbaseline_test.go), so the fixtures
// are recorded past upstream's authorisation and replayed without ours.
//
// Every exception below has a counterpart in docs/api.md's "Differences from
// OpenVox Server"; add or remove both in the same commit.

const contractDir = "testdata/contract"

// contractCompareModes is how much of a response a fixture can bind; see
// test/contract/record's fixture type.
var contractCompareModes = map[string]bool{"exact": true, "types": true, "none": true, "status": true}

// contractClients are the identities serveContract knows how to replay:
// "renewer" presents renew-me's certificate, and the others present none,
// since openvox-ca's own authorisation is not part of the contract.
var contractClients = map[string]bool{"admin": true, "anonymous": true, "renewer": true}

// contractRequestFields are the request fields serveContract replays. The
// recorder's request type is a separate copy, so a field it gains has to be
// added here too, or it would be dropped and openvox-ca asked something
// OpenVox Server was not.
var contractRequestFields = map[string]bool{
	"method": true, "path": true, "content_type": true, "body": true,
	"if_modified_since": true, "accept": true, "client": true,
}

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
		Accept          string `json:"accept"`
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
	// Diff is a difference exactly as checkContract reports it, except that
	// "[*]" stands for any one list entry.
	Diff   string
	Reason string
}

var contractExceptions = map[string][]contractException{
	"status-signed-dns":   missingFingerprints("$"),
	"status-signed-nosan": missingFingerprints("$"),
	"status-revoked":      missingFingerprints("$"),
	"status-requested":    missingFingerprints("$"),
	"status-cert-and-csr": missingFingerprints("$"),
	"status-signed-ip":    append(missingFingerprints("$"), unlistedIPSANs("$")),
	"status-signed-ext":   append(missingFingerprints("$"), cornerExtExtensions("$")...),
	"status-unknown": {{`media type: "text/plain", upstream "application/json"`,
		"kept: the 404 body is plain text, as upstream's is, and says so where upstream's header claims JSON"}},
	"status-signed-mapped": append(missingFingerprints("$"), degradedMapped("$")...),
	"statuses-all": append(append(append(missingFingerprints("$[*]"),
		unlistedIPSANs("$[name=corner-ip,state=signed]"), hiddenCSR),
		cornerExtExtensions("$[name=corner-ext,state=signed]")...),
		degradedMapped("$[name=corner-mapped,state=signed]")...),
	"statuses-requested": append(missingFingerprints("$[*]"), hiddenCSR),
	"statuses-signed": append(append(append(missingFingerprints("$[*]"),
		unlistedIPSANs("$[name=corner-ip,state=signed]")),
		cornerExtExtensions("$[name=corner-ext,state=signed]")...),
		degradedMapped("$[name=corner-mapped,state=signed]")...),
	"statuses-revoked": missingFingerprints("$[*]"),
	"statuses-unknown-state": {{"$: 0 entries, upstream 18",
		"kept: an unknown ?state= matches no subject, where upstream ignores the filter and lists them all"}},
	"statuses-empty-segment": {{"status: 404, upstream 400",
		"kept: certificate_statuses without its segment is not a route"}},
	"status-invalid-subject": {{"status: 400, upstream 404",
		"kept: a subject that is not a valid certname is the client's error"}},
	"status-put-revoke-unknown": {{"status: 409, upstream 404",
		"#358 (PR #372): revoking a subject the CA never signed answers 409"}},
	"status-put-sign-without-csr": {{"status: 404, upstream 409",
		"#411: signing a subject with no CSR answers 404"}},
	"certificate-get-not-modified": {{"status: 200, upstream 304",
		"#414: GET /certificate ignores If-Modified-Since"}},
	"certificate-request-put-existing-cert": {{"status: 200, upstream 400",
		"#410: a CSR for a subject with a live certificate is accepted"}},
	"certificate-request-put-unparseable": {{"status: 400, upstream 500",
		"kept: a body that is not a CSR is the client's error, where upstream fails with an exception"}},
	"certificate-wrong-method": {{"status: 405, upstream 404",
		"kept: a method the route does not serve answers 405 Method Not Allowed"}},
	"certificate-renewal-no-client-cert": {{"status: 403, upstream 400",
		"kept: a renewal with no client certificate is refused as unauthorised"}},
	"crl-get-other-segment": {{"status: 404, upstream 200",
		"kept: the CRL is served only at certificate_revocation_list/ca, the path agents ask for"}},
	"crl-get-not-modified-no-weekday": {{"status: 200, upstream 304",
		"kept: an If-Modified-Since that is not an HTTP date, which names the weekday, is ignored and the CRL served in full"}},
	"crl-put-rejected": {{"status: 404, upstream 400",
		"#413: PUT /certificate_revocation_list (CRL upload) is not implemented"}},
	"sign-empty": {{"status: 400, upstream 200",
		"#412: POST /sign with an empty certnames answers 400"}},
	"sign-missing-certnames": {{"status: 400, upstream 200",
		"#412: POST /sign without certnames answers 400"}},
	"sign-non-list": {{"status: 400, upstream 422",
		"#412: POST /sign with a certnames that is not a list answers 400"}},
	"clean": {{`media type: "application/json", upstream "text/plain"`,
		"kept: PUT /clean reports what it did to each subject, as JSON"}},
	"status-get-pson": {{`media type: "application/json", upstream "text/pson"`,
		"kept: responses are JSON only; pson is not offered"}},
	"status-put-sign-authext": {{"status: 204, upstream 409",
		"kept: a CSR asking for authorisation extensions is signed with them stripped, rather than refused"}},
}

// degradedMapped is corner-mapped's status: crypto/x509 refuses to parse a
// certificate with an IPv4-mapped IPv6 SAN, so openvox-ca serves what it can
// without parsing it.
func degradedMapped(at string) []contractException {
	const reason = "kept: a stored certificate that cannot be parsed degrades to a partial status; Go refuses an IPv4-mapped IPv6 SAN"
	return []contractException{
		{at + ".dns_alt_names: 0 entries, upstream 1", reason},
		{at + ".not_after: missing", reason},
		{at + ".not_before: missing", reason},
		{at + ".serial_number: missing", reason},
		{at + ".subject_alt_names: 0 entries, upstream 2", reason},
	}
}

// hiddenCSR is corner-both's CSR, filed behind its live certificate.
var hiddenCSR = contractException{"$[name=corner-both,state=requested]: missing",
	"kept: a CSR for a subject with a live certificate is not listed"}

func missingFingerprints(at string) []contractException {
	const reason = "#406: fingerprints has SHA256 and default only"
	return []contractException{
		{at + ".fingerprints.SHA1: missing", reason},
		{at + ".fingerprints.SHA512: missing", reason},
	}
}

// unlistedIPSANs is corner-ip's two DNS names listed without its two IP
// addresses.
func unlistedIPSANs(at string) contractException {
	return contractException{at + ".subject_alt_names: 2 entries, upstream 4",
		"#407: subject_alt_names leaves out IP addresses"}
}

// cornerExtExtensions are the differences in corner-ext's authorisation
// extensions.
func cornerExtExtensions(at string) []contractException {
	const autoRenew = "#408: pp_auth_auto_renew is keyed by name, where upstream keys it by OID"
	return []contractException{
		{at + `.authorization_extensions["1.3.6.1.4.1.34380.1.3.2"]: missing`, autoRenew},
		{at + ".authorization_extensions.pp_auth_auto_renew: not in upstream", autoRenew},
		{at + `.authorization_extensions["1.3.6.1.4.1.34380.1.3"]: not in upstream`,
			"#409: an extension with the authorisation arc's own OID is listed"},
		{at + `.authorization_extensions["1.3.6.1.4.1.34380.1.3.98"]: value 6c6567616379, upstream legacy`,
			"kept: a value that is not a DER string renders as hex"},
	}
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
	if f.Compare == "status" {
		return nil
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
		if keyed, _, ok := keyByNameState(w); ok {
			if gk, repeated, ok := keyByNameState(g); ok {
				// Keying by name and state would hide an entry listed twice,
				// which is never a right answer, so say so.
				diffs := compareKeyed(at, keyed, gk, exact)
				for _, k := range repeated {
					diffs = append(diffs, fmt.Sprintf("%s[%s]: listed more than once", at, k))
				}
				return diffs
			}
		}
		if !exact {
			// Under types a list's length is not bound, only its entries'
			// types: a types fixture answers a state that differs from the
			// snapshot (sign-all) or lists what the request happened to name.
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
// holds both a certificate and a CSR. repeated lists the keys that appear more
// than once, in order.
func keyByNameState(list []any) (keyed map[string]any, repeated []string, ok bool) {
	if len(list) == 0 {
		return nil, nil, false
	}
	keyed = map[string]any{}
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, nil, false
		}
		name, ok1 := m["name"].(string)
		state, ok2 := m["state"].(string)
		if !ok1 || !ok2 {
			return nil, nil, false
		}
		k := fmt.Sprintf("name=%s,state=%s", name, state)
		if _, seen := keyed[k]; seen {
			repeated = append(repeated, k)
		}
		keyed[k] = m
	}
	return keyed, repeated, true
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

// lastField is the key at the end of a path field wrote, quoted or not, or ""
// when the path ends in a list entry.
func lastField(at string) string {
	if strings.HasSuffix(at, `"]`) {
		if i := strings.LastIndex(at, `["`); i >= 0 {
			if k, err := strconv.Unquote(at[i+1 : len(at)-1]); err == nil {
				return k
			}
		}
	}
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

// judge splits a fixture's differences against its exceptions: unexplained
// are differences no exception covers, and stale are exceptions that cover
// no difference. Both must be empty.
func judge(diffs []string, exceptions []contractException) (unexplained, stale []string) {
	used := map[int]bool{}
	for _, d := range diffs {
		matched := false
		for i, e := range exceptions {
			if exceptionMatches(e.Diff, d) {
				used[i] = true
				matched = true
			}
		}
		if !matched {
			unexplained = append(unexplained, d)
		}
	}
	for i, e := range exceptions {
		if !used[i] {
			stale = append(stale, e.Diff+" ("+e.Reason+")")
		}
	}
	return unexplained, stale
}

// exceptionMatches matches a difference exactly, except that "[*]" in the
// exception stands for any one list entry.
func exceptionMatches(exception, diff string) bool {
	head, tail, wildcard := strings.Cut(exception, "[*]")
	if !wildcard {
		return diff == exception
	}
	if !strings.HasPrefix(diff, head+"[") {
		return false
	}
	rest := diff[len(head)+1:]
	end := strings.Index(rest, "]")
	return end >= 0 && rest[end+1:] == tail
}

// --- the openvox-ca under test ---------------------------------------------

// checkReplayable refuses a fixture whose request names a client or carries a
// field that serveContract does not replay.
func checkReplayable(fixture []byte) error {
	var raw struct {
		Request map[string]json.RawMessage `json:"request"`
	}
	if err := json.Unmarshal(fixture, &raw); err != nil {
		return err
	}
	for _, k := range sortedKeys(raw.Request) {
		if !contractRequestFields[k] {
			return fmt.Errorf("request field %q is not replayed", k)
		}
	}
	var client string
	if err := json.Unmarshal(raw.Request["client"], &client); err != nil || !contractClients[client] {
		return fmt.Errorf("request client %s is not one serveContract replays", raw.Request["client"])
	}
	return nil
}

// loadContractFixtures runs while the spec tree is built, where Gomega cannot,
// so a fixture that will not load panics instead.
func loadContractFixtures() []contractFixture {
	paths, err := filepath.Glob(filepath.Join(contractDir, "fixtures", "*.json"))
	if err != nil || len(paths) == 0 {
		panic(fmt.Sprintf("no contract fixtures in %s (run go run ./test/contract/record): %v", contractDir, err))
	}
	var fixtures []contractFixture
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			panic(err)
		}
		var f contractFixture
		if err := json.Unmarshal(b, &f); err != nil {
			panic(fmt.Sprintf("%s: %v", p, err))
		}
		// An unknown mode would fall through checkContract as a loose
		// comparison, binding less than whoever wrote it intended.
		if !contractCompareModes[f.Compare] {
			panic(fmt.Sprintf("%s: unknown compare mode %q", p, f.Compare))
		}
		// For the same reason, a client or a request field the replay does
		// not know would replay a different request from the one recorded.
		if err := checkReplayable(b); err != nil {
			panic(fmt.Sprintf("%s: %v", p, err))
		}
		fixtures = append(fixtures, f)
	}
	return fixtures
}

// seedContractCA gives a fresh openvox-ca the store the fixtures were
// recorded against: OpenVox Server's own CA bundle, key and CRL chain, and
// every certificate and CSR it held.
func seedContractCA(dir string) *api.Server {
	return seedContractStore(storage.New(dir))
}

// seedContractStore is seedContractCA on a store the caller built, such as
// one over a fault-injecting backend.
func seedContractStore(store *storage.StorageService) *api.Server {
	ctx := context.Background()
	src := filepath.Join(contractDir, "cadir")
	read := func(rel string) []byte {
		b, err := os.ReadFile(filepath.Join(src, rel))
		Expect(err).NotTo(HaveOccurred())
		return b
	}

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
		serial, notBefore, notAfter, err := certSerialAndValidity(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCert(ctx, subject, certPEM)).To(Succeed())
		Expect(store.AppendInventory(ctx, fmt.Sprintf("%X %s %s /%s", serial,
			notBefore.UTC().Format(storage.InventoryTimeFormat),
			notAfter.UTC().Format(storage.InventoryTimeFormat), subject))).To(Succeed())
	}
	requests, err := os.ReadDir(filepath.Join(src, "requests"))
	Expect(err).NotTo(HaveOccurred())
	for _, e := range requests {
		Expect(store.SaveCSR(ctx, strings.TrimSuffix(e.Name(), ".pem"), read(filepath.Join("requests", e.Name())))).To(Succeed())
	}

	myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet")
	Expect(myCA.Init(ctx)).To(Succeed())
	srv := api.New(myCA)
	// Upstream's date layout is openvox-ca's opt-in; see docs/api.md's
	// "Differences from OpenVox Server".
	srv.PuppetDateTimeFormat = true
	return srv
}

// certSerialAndValidity reads a certificate's serial and validity straight
// from its DER. crypto/x509 refuses some certificates OpenVox Server signs,
// such as one with an IPv4-mapped IPv6 SAN, and the snapshot holds one, but
// the store still needs its inventory line.
func certSerialAndValidity(der []byte) (serial *big.Int, notBefore, notAfter time.Time, err error) {
	var cert struct {
		TBS struct {
			Version  int `asn1:"optional,explicit,default:0,tag:0"`
			Serial   *big.Int
			SigAlg   asn1.RawValue
			Issuer   asn1.RawValue
			Validity struct{ NotBefore, NotAfter time.Time }
			Subject  asn1.RawValue
			Key      asn1.RawValue
			Rest     asn1.RawValue `asn1:"optional,explicit,tag:3"`
		}
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		return nil, time.Time{}, time.Time{}, err
	}
	return cert.TBS.Serial, cert.TBS.Validity.NotBefore, cert.TBS.Validity.NotAfter, nil
}

// serveContract drives openvox-ca with a fixture's request.
func serveContract(srv *api.Server, f contractFixture) *httptest.ResponseRecorder {
	req := httptest.NewRequest(f.Request.Method, f.Request.Path, strings.NewReader(f.Request.Body))
	if f.Request.ContentType != "" {
		req.Header.Set("Content-Type", f.Request.ContentType)
	}
	if f.Request.IfModifiedSince != "" {
		req.Header.Set("If-Modified-Since", f.Request.IfModifiedSince)
	}
	if f.Request.Accept != "" {
		req.Header.Set("Accept", f.Request.Accept)
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

			GinkgoWriter.Printf("differences: %q\n", diffs)
			unexplained, stale := judge(diffs, contractExceptions[f.Name])
			Expect(unexplained).To(BeEmpty(),
				"differences from OpenVox Server with no exception; body:\n%s", rr.Body.String())
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

	// The fixtures are a snapshot of a live CA, and certificate status
	// changes when its certificates expire. Fail well before that, so the
	// re-record is a chore rather than an outage.
	It("holds certificates and CRLs that stay valid for another 180 days", func() {
		horizon := time.Now().AddDate(0, 0, 180)
		var expiring []string
		root, err := os.OpenRoot(filepath.Join(contractDir, "cadir"))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(root.Close)
		Expect(fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || path == "ca_key.pem" {
				return err
			}
			rest, err := fs.ReadFile(root.FS(), path)
			if err != nil {
				return err
			}
			for {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					return nil
				}
				switch block.Type {
				case "CERTIFICATE":
					_, _, notAfter, err := certSerialAndValidity(block.Bytes)
					if err != nil {
						return err
					}
					if notAfter.Before(horizon) {
						expiring = append(expiring, fmt.Sprintf("%s: a certificate expires %s", path, notAfter))
					}
				case "X509 CRL":
					crl, err := x509.ParseRevocationList(block.Bytes)
					if err != nil {
						return err
					}
					if crl.NextUpdate.Before(horizon) {
						expiring = append(expiring, fmt.Sprintf("%s: CRL from %s is due %s", path, crl.Issuer, crl.NextUpdate))
					}
				}
			}
		})).To(Succeed())
		Expect(expiring).To(BeEmpty(), "re-record the contract: go run ./test/contract/record")
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

	It("binds a list entry's type under compare types", func() {
		f := upstream
		f.Compare = "types"
		Expect(checkContract(f, 200, "application/json",
			[]byte(strings.Replace(conforming, `["DNS:n"]`, `[1]`, 1)))).To(
			ContainElement("$.dns_alt_names[0]: type number, upstream string"))
	})

	It("leaves a list's length unbound under compare types", func() {
		f := upstream
		f.Compare = "types"
		Expect(checkContract(f, 200, "application/json",
			[]byte(strings.Replace(conforming, `["DNS:n"]`, `[]`, 1)))).To(BeEmpty())
		Expect(checkContract(f, 200, "application/json",
			[]byte(strings.Replace(conforming, `["DNS:n"]`, `["DNS:n","DNS:m"]`, 1)))).To(BeEmpty())
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

	It("reports a status upstream does not list", func() {
		f := contractFixture{Compare: "exact", Response: contractResponse{Status: 200, ContentType: "application/json",
			JSON: json.RawMessage(`[{"name":"a","state":"signed"}]`)}}
		Expect(checkContract(f, 200, "application/json",
			[]byte(`[{"name":"a","state":"signed"},{"name":"c","state":"signed"}]`))).To(
			ConsistOf("$[name=c,state=signed]: not in upstream"))
	})

	It("reports a status listed twice, which keying by name and state would hide", func() {
		f := contractFixture{Compare: "exact", Response: contractResponse{Status: 200, ContentType: "application/json",
			JSON: json.RawMessage(`[{"name":"a","state":"signed"},{"name":"b","state":"signed"}]`)}}
		Expect(checkContract(f, 200, "application/json",
			[]byte(`[{"name":"a","state":"signed"},{"name":"b","state":"signed"},{"name":"a","state":"signed"}]`))).To(
			ConsistOf("$[name=a,state=signed]: listed more than once"))
	})

	It("ignores the media type of an empty upstream body", func() {
		empty := ""
		f := contractFixture{Compare: "none", Response: contractResponse{Status: 204, ContentType: "text/plain", Text: &empty}}
		Expect(checkContract(f, 204, "", nil)).To(BeEmpty())
	})

	It("reports a difference no exception covers", func() {
		unexplained, stale := judge([]string{"status: 404, upstream 200", "$.name: missing"},
			[]contractException{{"status: 404, upstream 200", "r"}})
		Expect(unexplained).To(ConsistOf("$.name: missing"))
		Expect(stale).To(BeEmpty())
	})

	It("reports an exception that covers no difference", func() {
		unexplained, stale := judge([]string{"$.name: missing"},
			[]contractException{{"$.name: missing", "r"}, {"status: 404, upstream 200", "gone"}})
		Expect(unexplained).To(BeEmpty())
		Expect(stale).To(ConsistOf("status: 404, upstream 200 (gone)"))
	})

	DescribeTable("refuses a fixture the replay would not ask as recorded",
		func(request, want string) {
			Expect(checkReplayable([]byte(`{"request":` + request + `}`))).To(MatchError(ContainSubstring(want)))
		},
		Entry("a client serveContract does not know", `{"method":"GET","path":"/x","client":"agent"}`, `client "agent"`),
		Entry("no client at all", `{"method":"GET","path":"/x"}`, "client"),
		Entry("a request field serveContract does not replay", `{"method":"GET","path":"/x","client":"admin","cookie":"c"}`, `"cookie"`),
	)

	It("accepts a fixture with every field and client it does replay", func() {
		Expect(checkReplayable([]byte(`{"request":{"method":"PUT","path":"/x","content_type":"text/plain","body":"b",
			"if_modified_since":"d","accept":"a","client":"renewer"}}`))).To(Succeed())
	})

	DescribeTable("finds the key at the end of a path, quoted or not",
		func(at, want string) {
			Expect(lastField(at)).To(Equal(want))
		},
		Entry("a plain key", "$.a.authorization_extensions", "authorization_extensions"),
		Entry("a key field quoted for its hyphen", `$["ca-certs"]`, "ca-certs"),
		Entry("a key field quoted for its dot", `$.x["1.3.6.1"]`, "1.3.6.1"),
		Entry("a list entry", "$[name=a,state=signed]", ""),
	)

	It("matches an exception exactly, not as a prefix", func() {
		Expect(exceptionMatches("status: 404, upstream 200", "status: 404, upstream 200")).To(BeTrue())
		Expect(exceptionMatches("status: 404", "status: 404, upstream 200")).To(BeFalse())
	})

	It("matches an exception's [*] against any one list entry", func() {
		Expect(exceptionMatches("$[*].fingerprints.SHA1: missing", "$[name=a,state=signed].fingerprints.SHA1: missing")).To(BeTrue())
		Expect(exceptionMatches("$[*].fingerprints", "$[name=a,state=signed].fingerprints.SHA1: missing")).To(BeFalse())
		Expect(exceptionMatches("$[*].fingerprints.SHA1: missing", "$[name=a,state=signed].dns_alt_names[0]: value")).To(BeFalse())
	})
})
