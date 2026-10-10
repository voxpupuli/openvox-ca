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

package signer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/rpc"
	"os"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// serveOverPipe serves svc over an in-memory connection and returns a
// RemoteSigner for it, publishing pub, the same pairing the launcher builds over
// the socketpair once the handshake is done.
func serveOverPipe(svc *Service, pub crypto.PublicKey) *RemoteSigner {
	serverConn, clientConn := net.Pipe()
	server := rpc.NewServer()
	Expect(server.RegisterName("Signer", svc)).To(Succeed())
	go server.ServeConn(serverConn)

	rs := &RemoteSigner{client: rpc.NewClient(clientConn), pub: pub}
	DeferCleanup(rs.Close)
	return rs
}

// digestOf hashes msg with h, so a spec asking for a given hash sends a real
// digest of the right length.
func digestOf(h crypto.Hash, msg []byte) []byte {
	hh := h.New()
	hh.Write(msg)
	return hh.Sum(nil)
}

// verifySignature checks sig over digest against pub, for the two key types
// the CA signs with.
func verifySignature(pub crypto.PublicKey, h crypto.Hash, digest, sig []byte) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, h, digest, sig)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return errors.New("ECDSA signature does not verify")
		}
		return nil
	default:
		Fail("unexpected key type")
		return nil
	}
}

// The first two refusals below are requests the key would otherwise have
// signed: an RSA key signs SHA-1 and crypto.Hash(0) without complaint. The
// third the key would refuse on its own, so that spec asserts the signer's own
// error rather than any error at all.
var _ = Describe("Signer request checks", func() {
	var (
		rsaKey *rsa.PrivateKey
		ecKey  *ecdsa.PrivateKey
	)

	BeforeEach(func() {
		var err error
		rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
	})

	It("refuses a hash function the CA never signs with", func() {
		digest := sha1.Sum([]byte("not a CA signature"))

		resp := &SignResponse{}
		err := (&Service{key: rsaKey}).Sign(&SignRequest{Digest: digest[:], HashFunc: crypto.SHA1}, resp)

		Expect(err).To(MatchError(ErrSignRequestRefused))
		Expect(err.Error()).To(ContainSubstring("hash function SHA-1 is not one the CA signs with"))
		Expect(resp.Signature).To(BeNil())
	})

	It("refuses crypto.Hash(0), which on an RSA key is a raw PKCS#1 v1.5 signature", func() {
		resp := &SignResponse{}
		err := (&Service{key: rsaKey}).Sign(&SignRequest{Digest: []byte("arbitrary bytes"), HashFunc: 0}, resp)

		Expect(err).To(MatchError(ErrSignRequestRefused))
		Expect(err.Error()).To(ContainSubstring("hash function unknown hash value 0 is not one the CA signs with"))
		Expect(resp.Signature).To(BeNil())
	})

	It("refuses a digest whose length does not match its hash function", func() {
		// Labelled SHA-256 but 48 bytes long, as a SHA-384 digest is.
		digest := digestOf(crypto.SHA384, []byte("mislabelled"))

		resp := &SignResponse{}
		err := (&Service{key: ecKey}).Sign(&SignRequest{Digest: digest, HashFunc: crypto.SHA256}, resp)

		Expect(err).To(MatchError(ErrSignRequestRefused))
		Expect(err.Error()).To(ContainSubstring("a SHA-256 digest is 32 bytes, not 48"))
		Expect(resp.Signature).To(BeNil())
	})

	It("logs a refusal as a warning in the signer's own log", func() {
		// The refusal goes back to the frontend, which by this threat model
		// may be the party making it. The warning is what the operator sees.
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		DeferCleanup(slog.SetDefault, orig)

		err := (&Service{key: rsaKey}).Sign(&SignRequest{Digest: []byte("arbitrary bytes"), HashFunc: 0}, &SignResponse{})
		Expect(err).To(MatchError(ErrSignRequestRefused))

		Expect(buf.String()).To(ContainSubstring("level=WARN"))
		Expect(buf.String()).To(ContainSubstring(`msg="Refused a signing request"`))
		Expect(buf.String()).To(ContainSubstring("hash function unknown hash value 0 is not one the CA signs with"))
	})

	It("reports a refusal to the frontend across the RPC", func() {
		rs := serveOverPipe(&Service{key: rsaKey}, rsaKey.Public())

		sig, err := rs.Sign(rand.Reader, []byte("arbitrary bytes"), crypto.Hash(0))

		Expect(err).To(MatchError(ContainSubstring("remote sign: signing request refused")))
		Expect(sig).To(BeNil())
	})

	DescribeTable("still signs every hash the CA uses, through the RPC",
		func(useRSA bool, h crypto.Hash) {
			var key crypto.Signer = ecKey
			if useRSA {
				key = rsaKey
			}
			rs := serveOverPipe(&Service{key: key}, key.Public())
			digest := digestOf(h, []byte("a CA signature"))

			sig, err := rs.Sign(rand.Reader, digest, h)

			Expect(err).NotTo(HaveOccurred())
			Expect(verifySignature(key.Public(), h, digest, sig)).To(Succeed())
		},
		Entry("RSA, SHA-256", true, crypto.SHA256),
		Entry("RSA, SHA-384", true, crypto.SHA384),
		Entry("RSA, SHA-512", true, crypto.SHA512),
		Entry("ECDSA, SHA-256", false, crypto.SHA256),
		Entry("ECDSA, SHA-384", false, crypto.SHA384),
		Entry("ECDSA, SHA-512", false, crypto.SHA512),
	)
})

// countingSigner counts the signatures its key makes, so a spec can tell that
// an operation really signed through the isolated signer rather than somewhere
// else.
type countingSigner struct {
	crypto.Signer
	calls atomic.Int64
}

func (c *countingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	c.calls.Add(1)
	return c.Signer.Sign(r, digest, opts)
}

// The allow-list is only safe if it covers every hash the CA actually signs
// with. These drive each operation that signs with the CA key -- issuance, the
// CRL and OCSP -- through the RPC the default topology uses, for every CA key
// ca_key_algo and ca_key_size can create, so a list too narrow for one of them
// fails here rather than in production. The signature algorithm is asserted as
// well, which records the hash each one needs.
var _ = Describe("CA signing through the isolated signer", func() {
	DescribeTable("issues, revokes and answers OCSP for each CA key type",
		func(keyCfg ca.KeyConfig, want x509.SignatureAlgorithm) {
			ctx := context.Background()
			tmpDir, err := os.MkdirTemp("", "openvox-ca-signer-paths")
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(os.RemoveAll, tmpDir)
			store := storage.New(tmpDir)

			// The signer process: bootstraps the CA and holds its key.
			signerCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			signerCA.CAKeyConfig = keyCfg
			Expect(signerCA.Init(ctx)).To(Succeed())
			key := &countingSigner{Signer: signerCA.CAKey}

			// The frontend: the same store, with every signature proxied.
			frontend := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			frontend.ExternalSigner = serveOverPipe(&Service{key: key}, signerCA.CACert.PublicKey)
			Expect(frontend.Init(ctx)).To(Succeed())
			caCert := frontend.CACert

			By("issuing a certificate")
			before := key.calls.Load()
			csrPEM, err := testutil.GenerateCSR("agent.test")
			Expect(err).NotTo(HaveOccurred())
			_, err = frontend.SaveRequest(ctx, "agent.test", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			certPEM, err := frontend.Sign(ctx, "agent.test")
			Expect(err).NotTo(HaveOccurred())
			Expect(key.calls.Load()).To(BeNumerically(">", before))
			block, _ := pem.Decode(certPEM)
			Expect(block).NotTo(BeNil())
			cert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(cert.CheckSignatureFrom(caCert)).To(Succeed())
			Expect(cert.SignatureAlgorithm).To(Equal(want))

			By("signing a CRL that revokes it")
			before = key.calls.Load()
			Expect(frontend.Revoke(ctx, "agent.test")).To(Succeed())
			Expect(key.calls.Load()).To(BeNumerically(">", before))
			crlPEM, err := store.GetCRL(ctx)
			Expect(err).NotTo(HaveOccurred())
			block, _ = pem.Decode(crlPEM)
			Expect(block).NotTo(BeNil())
			crl, err := x509.ParseRevocationList(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(crl.CheckSignatureFrom(caCert)).To(Succeed())
			Expect(crl.SignatureAlgorithm).To(Equal(want))
			Expect(crl.RevokedCertificateEntries).To(ContainElement(
				HaveField("SerialNumber", Equal(cert.SerialNumber))))

			By("answering OCSP for it")
			before = key.calls.Load()
			reqDER, err := testutil.BuildOCSPRequest(cert, caCert)
			Expect(err).NotTo(HaveOccurred())
			respDER, err := frontend.OCSPResponse(ctx, reqDER)
			Expect(err).NotTo(HaveOccurred())
			Expect(key.calls.Load()).To(BeNumerically(">", before))
			resp, err := ocsp.ParseResponse(respDER, caCert) // verifies the signature
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.Status).To(Equal(ocsp.Revoked))
			Expect(resp.SignatureAlgorithm).To(Equal(want))
		},
		Entry("RSA 2048", ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 2048}, x509.SHA256WithRSA),
		Entry("RSA 3072", ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 3072}, x509.SHA256WithRSA),
		Entry("RSA 4096", ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 4096}, x509.SHA256WithRSA),
		Entry("ECDSA P-256", ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}, x509.ECDSAWithSHA256),
		Entry("ECDSA P-384", ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 384}, x509.ECDSAWithSHA384),
		Entry("ECDSA P-521", ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 521}, x509.ECDSAWithSHA512),
	)
})
