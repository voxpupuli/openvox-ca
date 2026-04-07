package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/tvaughan/puppet-ca/internal/storage"
)

var _ = Describe("Key encryption", func() {
	Describe("encryptKeyPEM / decryptKeyDER round-trip", func() {
		It("encrypts and decrypts an RSA key", func() {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())

			passphrase := []byte("test-passphrase-12345")
			encPEM, err := encryptAndMarshalKey(key, passphrase)
			Expect(err).NotTo(HaveOccurred())

			block, _ := pem.Decode(encPEM)
			Expect(block).NotTo(BeNil())
			Expect(block.Type).To(Equal(encryptedPEMType))

			pkcs8DER, err := decryptKeyDER(block.Bytes, passphrase)
			Expect(err).NotTo(HaveOccurred())

			parsed, err := x509.ParsePKCS8PrivateKey(pkcs8DER)
			Expect(err).NotTo(HaveOccurred())

			rsaKey, ok := parsed.(*rsa.PrivateKey)
			Expect(ok).To(BeTrue())
			Expect(rsaKey.D.Cmp(key.D)).To(Equal(0))
		})

		It("encrypts and decrypts an ECDSA key", func() {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())

			passphrase := []byte("another-passphrase")
			encPEM, err := encryptAndMarshalKey(key, passphrase)
			Expect(err).NotTo(HaveOccurred())

			block, _ := pem.Decode(encPEM)
			Expect(block).NotTo(BeNil())

			pkcs8DER, err := decryptKeyDER(block.Bytes, passphrase)
			Expect(err).NotTo(HaveOccurred())

			parsed, err := x509.ParsePKCS8PrivateKey(pkcs8DER)
			Expect(err).NotTo(HaveOccurred())

			ecKey, ok := parsed.(*ecdsa.PrivateKey)
			Expect(ok).To(BeTrue())
			Expect(ecKey.D.Cmp(key.D)).To(Equal(0))
		})

		It("fails decryption with wrong passphrase", func() {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())

			encPEM, err := encryptAndMarshalKey(key, []byte("correct"))
			Expect(err).NotTo(HaveOccurred())

			block, _ := pem.Decode(encPEM)
			_, err = decryptKeyDER(block.Bytes, []byte("wrong"))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("wrong passphrase"))
		})

		It("fails on truncated envelope", func() {
			_, err := decryptKeyDER([]byte{0x01, 0x02}, []byte("pass"))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("too short"))
		})

		It("fails on unsupported version", func() {
			envelope := make([]byte, keyEncMinLen+10)
			envelope[0] = 0xFF
			_, err := decryptKeyDER(envelope, []byte("pass"))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unsupported"))
		})
	})

	Describe("resolvePassphrase", func() {
		var tmpDir string

		BeforeEach(func() {
			var err error
			tmpDir, err = os.MkdirTemp("", "keyenc-test-*")
			Expect(err).NotTo(HaveOccurred())
			Expect(os.MkdirAll(filepath.Join(tmpDir, "private"), 0750)).To(Succeed())
		})

		AfterEach(func() {
			os.RemoveAll(tmpDir)
		})

		It("reads passphrase from explicit file", func() {
			ppFile := filepath.Join(tmpDir, "pp.txt")
			Expect(os.WriteFile(ppFile, []byte("my-secret\n"), 0600)).To(Succeed())

			pp, auto, err := resolvePassphrase(KeyPassphraseConfig{
				PassphraseFile: ppFile,
			}, tmpDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(auto).To(BeFalse())
			Expect(string(pp)).To(Equal("my-secret"))
		})

		It("reads passphrase from environment variable", func() {
			os.Setenv("PUPPET_CA_KEY_PASSPHRASE", "env-secret")
			defer os.Unsetenv("PUPPET_CA_KEY_PASSPHRASE")

			pp, auto, err := resolvePassphrase(KeyPassphraseConfig{}, tmpDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(auto).To(BeFalse())
			Expect(string(pp)).To(Equal("env-secret"))
		})

		It("auto-generates and persists passphrase when none provided", func() {
			pp, auto, err := resolvePassphrase(KeyPassphraseConfig{}, tmpDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(auto).To(BeTrue())
			Expect(len(pp)).To(BeNumerically(">", 0))

			// Verify the file was written.
			autoPath := autoPassphrasePath(tmpDir)
			data, err := os.ReadFile(autoPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(data).To(Equal(pp))

			// Verify permissions.
			info, err := os.Stat(autoPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0600)))
		})

		It("reuses existing auto-generated passphrase", func() {
			// First call generates.
			pp1, auto1, err := resolvePassphrase(KeyPassphraseConfig{}, tmpDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(auto1).To(BeTrue())

			// Second call reads existing.
			pp2, auto2, err := resolvePassphrase(KeyPassphraseConfig{}, tmpDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(auto2).To(BeFalse())
			Expect(pp2).To(Equal(pp1))
		})

		It("errors on empty passphrase file", func() {
			ppFile := filepath.Join(tmpDir, "empty.txt")
			Expect(os.WriteFile(ppFile, []byte(""), 0600)).To(Succeed())

			_, _, err := resolvePassphrase(KeyPassphraseConfig{
				PassphraseFile: ppFile,
			}, tmpDir)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("empty"))
		})
	})

	Describe("isEncryptedPEM", func() {
		It("returns true for encrypted PEM type", func() {
			Expect(isEncryptedPEM(&pem.Block{Type: encryptedPEMType})).To(BeTrue())
		})
		It("returns false for standard PEM types", func() {
			Expect(isEncryptedPEM(&pem.Block{Type: "RSA PRIVATE KEY"})).To(BeFalse())
			Expect(isEncryptedPEM(&pem.Block{Type: "PRIVATE KEY"})).To(BeFalse())
		})
		It("returns false for nil block", func() {
			Expect(isEncryptedPEM(nil)).To(BeFalse())
		})
	})
})

var _ = Describe("CA encrypted key integration", func() {
	It("bootstraps with encrypted key and reloads successfully", func() {
		tmpDir, err := os.MkdirTemp("", "puppet-ca-keyenc-*")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		store := storage.New(tmpDir)
		myCA := New(store, AutosignConfig{Mode: "off"}, "puppet-enc-test")
		myCA.EncryptCAKey = true
		// Let it auto-generate the passphrase.
		Expect(myCA.Init()).To(Succeed())
		Expect(myCA.CACert).NotTo(BeNil())
		Expect(myCA.CAKey).NotTo(BeNil())

		// Verify the key file on disk is encrypted PEM.
		keyPEM, err := os.ReadFile(store.CAKeyPath())
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(keyPEM)
		Expect(block).NotTo(BeNil())
		Expect(block.Type).To(Equal(encryptedPEMType))

		// Verify the auto-generated passphrase file exists.
		_, err = os.Stat(autoPassphrasePath(tmpDir))
		Expect(err).NotTo(HaveOccurred())

		// Reload the CA from disk; should succeed using the auto-generated passphrase.
		store2 := storage.New(tmpDir)
		myCA2 := New(store2, AutosignConfig{Mode: "off"}, "puppet-enc-test")
		myCA2.EncryptCAKey = true
		Expect(myCA2.Init()).To(Succeed())
		Expect(myCA2.CACert).NotTo(BeNil())
		Expect(myCA2.CAKey).NotTo(BeNil())

		// Sign a cert to verify the loaded key is functional.
		csrPEM, err := generateTestCSR("enc-test-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA2.SaveRequest("enc-test-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA2.Sign("enc-test-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(certPEM).NotTo(BeEmpty())
	})

	It("loads unencrypted key transparently (backward compat)", func() {
		tmpDir, err := os.MkdirTemp("", "puppet-ca-keyenc-compat-*")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		// Bootstrap without encryption.
		store := storage.New(tmpDir)
		myCA := New(store, AutosignConfig{Mode: "off"}, "puppet-compat")
		myCA.EncryptCAKey = false
		Expect(myCA.Init()).To(Succeed())

		// Verify key is unencrypted.
		keyPEM, err := os.ReadFile(store.CAKeyPath())
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(keyPEM)
		Expect(block).NotTo(BeNil())
		Expect(block.Type).NotTo(Equal(encryptedPEMType))

		// Reload: should work without encryption config.
		store2 := storage.New(tmpDir)
		myCA2 := New(store2, AutosignConfig{Mode: "off"}, "puppet-compat")
		Expect(myCA2.Init()).To(Succeed())
		Expect(myCA2.CACert).NotTo(BeNil())
	})

	It("fails to load encrypted key with wrong passphrase", func() {
		tmpDir, err := os.MkdirTemp("", "puppet-ca-keyenc-wrong-*")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		// Bootstrap with encryption.
		store := storage.New(tmpDir)
		myCA := New(store, AutosignConfig{Mode: "off"}, "puppet-wrong")
		myCA.EncryptCAKey = true
		Expect(myCA.Init()).To(Succeed())

		// Overwrite the auto-generated passphrase file with wrong value.
		Expect(os.WriteFile(autoPassphrasePath(tmpDir), []byte("wrong-passphrase"), 0600)).To(Succeed())

		// Reload should fail.
		store2 := storage.New(tmpDir)
		myCA2 := New(store2, AutosignConfig{Mode: "off"}, "puppet-wrong")
		err = myCA2.Init()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("wrong passphrase"))
	})
})

// generateTestCSR creates a CSR PEM for testing.
func generateTestCSR(cn string) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

func TestKeyEnc(t *testing.T) {
	// This test file uses the existing Ginkgo test runner from ca_test.go.
	// It's included via the package-level test runner.
}
