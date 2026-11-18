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

package ca

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// FingerprintAlgorithm is a digest the status API can report a fingerprint
// in, spelled as its key in a response's fingerprints object.
type FingerprintAlgorithm string

const (
	FingerprintSHA1   FingerprintAlgorithm = "SHA1"
	FingerprintSHA256 FingerprintAlgorithm = "SHA256"
	FingerprintSHA512 FingerprintAlgorithm = "SHA512"
)

// fingerprintDigest is the digest behind a FingerprintAlgorithm.
type fingerprintDigest struct {
	alg    FingerprintAlgorithm
	digest func([]byte) []byte
}

// fingerprintDigests are the digests behind each FingerprintAlgorithm, in the
// order ParseFingerprintAlgorithms returns them. SHA-1 here names a
// certificate; it signs nothing.
var fingerprintDigests = []fingerprintDigest{
	{FingerprintSHA1, func(b []byte) []byte { s := sha1.Sum(b); return s[:] }},
	{FingerprintSHA256, func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }},
	{FingerprintSHA512, func(b []byte) []byte { s := sha512.Sum512(b); return s[:] }},
}

// sha1Usable reports whether crypto/sha1 will hash at all. Under
// GODEBUG=fips140=only it panics instead. crypto/fips140.Enforced reports that
// mode, but not what crypto/sha1 does in it: a boringcrypto build, which the
// FIPS release builds are, hashes SHA-1 before it ever checks. So the hash is
// tried rather than the mode asked about. A variable so that a spec can stand
// in for that mode, which a process cannot enter once it has started.
var sha1Usable = func() bool {
	return hashes(func() { sha1.Sum(nil) })
}

// hashes reports whether sum returns rather than panics.
func hashes(sum func()) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	sum()
	return true
}

// ParseFingerprintAlgorithms reads status_fingerprint_algorithms: the digests
// the status API reports fingerprints in, besides SHA-256, which it always
// reports because it is also the fingerprint and the default. Names are
// matched without regard to case and may repeat. It returns the other digests
// named, in a fixed order, or none.
//
// SHA1 is refused where crypto/sha1 cannot hash, rather than left to panic in
// the startup index repair or on the first signing. Computing a fingerprint is not a signature, but a
// process running under GODEBUG=fips140=only has asked for no SHA-1 at all.
func ParseFingerprintAlgorithms(names []string) ([]FingerprintAlgorithm, error) {
	want := map[FingerprintAlgorithm]bool{}
	for _, name := range names {
		alg := FingerprintAlgorithm(strings.ToUpper(strings.TrimSpace(name)))
		if !slices.ContainsFunc(fingerprintDigests, func(d fingerprintDigest) bool { return d.alg == alg }) {
			return nil, fmt.Errorf("unknown fingerprint algorithm %q (accepted: SHA1, SHA256, SHA512)", name)
		}
		want[alg] = true
	}
	if want[FingerprintSHA1] && !sha1Usable() {
		return nil, fmt.Errorf("fingerprint algorithm SHA1 is not available: crypto/sha1 is refused under GODEBUG=fips140=only")
	}
	var algs []FingerprintAlgorithm
	for _, d := range fingerprintDigests {
		if want[d.alg] && d.alg != FingerprintSHA256 {
			algs = append(algs, d.alg)
		}
	}
	return algs, nil
}

// ColonFingerprint renders alg's digest of der as colon-separated lower-case
// hex pairs, the form SHA256ColonFingerprint renders SHA-256 in. It returns ""
// for an algorithm it does not know.
func ColonFingerprint(alg FingerprintAlgorithm, der []byte) string {
	for _, d := range fingerprintDigests {
		if d.alg == alg {
			return colonHex(d.digest(der))
		}
	}
	return ""
}

// OtherFingerprints renders der's fingerprints in algs, keyed by algorithm,
// as the certificate index projection stores them. nil when algs is empty.
func OtherFingerprints(algs []FingerprintAlgorithm, der []byte) map[string]string {
	if len(algs) == 0 {
		return nil
	}
	out := make(map[string]string, len(algs))
	for _, alg := range algs {
		out[string(alg)] = ColonFingerprint(alg, der)
	}
	return out
}

// colonHex renders sum as colon-separated lower-case hex pairs.
func colonHex(sum []byte) string {
	raw := hex.EncodeToString(sum)
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(raw); i += 2 {
		parts = append(parts, raw[i:i+2])
	}
	return strings.Join(parts, ":")
}
