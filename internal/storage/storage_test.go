// Copyright (C) 2026 Trevor Vaughan
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

package storage_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/tvaughan/puppet-ca/internal/storage"
)

var _ = Describe("StorageService", func() {
	var (
		tmpDir string
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-storage-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	// --- Path helpers ---

	Describe("Path helpers", func() {
		It("returns paths rooted in baseDir", func() {
			Expect(store.CADir()).To(Equal(tmpDir))
			Expect(store.CACertPath()).To(Equal(filepath.Join(tmpDir, "ca_crt.pem")))
			Expect(store.CAKeyPath()).To(Equal(filepath.Join(tmpDir, "private", "ca_key.pem")))
			Expect(store.CAPubKeyPath()).To(Equal(filepath.Join(tmpDir, "ca_pub.pem")))
			Expect(store.CRLPath()).To(Equal(filepath.Join(tmpDir, "ca_crl.pem")))
			Expect(store.InventoryPath()).To(Equal(filepath.Join(tmpDir, "inventory.txt")))
			Expect(store.CSRDir()).To(Equal(filepath.Join(tmpDir, "requests")))
			Expect(store.SignedDir()).To(Equal(filepath.Join(tmpDir, "signed")))
		})
	})

	// --- EnsureDirs ---

	Describe("EnsureDirs", func() {
		It("creates all required subdirectories", func() {
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
			for _, sub := range []string{"signed", "requests", "private"} {
				info, err := os.Stat(filepath.Join(tmpDir, sub))
				Expect(err).NotTo(HaveOccurred(), "missing subdirectory: %s", sub)
				Expect(info.IsDir()).To(BeTrue())
			}
		})

		It("is idempotent", func() {
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
		})
	})

	// --- Serial ---

	Describe("Serial", func() {
		BeforeEach(func() {
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
		})

		It("WriteSerial persists the value and GetSerial reads it back", func() {
			Expect(store.WriteSerial(context.Background(), "DEADBEEF")).To(Succeed())
			data, err := store.GetSerial(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(string(data)).To(Equal("DEADBEEF"))
		})
	})

	// --- Inventory ---

	Describe("Inventory", func() {
		BeforeEach(func() {
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
			Expect(store.TouchInventory(context.Background())).To(Succeed())
		})

		It("AppendInventory and ReadInventory roundtrip", func() {
			Expect(store.AppendInventory(context.Background(), "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1")).To(Succeed())
			Expect(store.AppendInventory(context.Background(), "0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2")).To(Succeed())

			data, err := store.ReadInventory(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(string(data)).To(ContainSubstring("/node1"))
			Expect(string(data)).To(ContainSubstring("/node2"))
		})

		It("ReadInventory returns an error when inventory file is missing", func() {
			Expect(os.Remove(store.InventoryPath())).To(Succeed())
			_, err := store.ReadInventory(context.Background())
			Expect(err).To(HaveOccurred())
		})

		It("AppendInventory is safe under concurrent writes", func() {
			const n = 20
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					entry := fmt.Sprintf("%04X 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node-%d", idx, idx)
					Expect(store.AppendInventory(context.Background(), entry)).To(Succeed())
				}(i)
			}
			wg.Wait()

			data, err := store.ReadInventory(context.Background())
			Expect(err).NotTo(HaveOccurred())
			lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
			Expect(lines).To(HaveLen(n))
		})
	})

	// --- CRL ---

	Describe("CRL", func() {
		BeforeEach(func() {
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
		})

		It("UpdateCRL and GetCRL roundtrip", func() {
			data := []byte("-----BEGIN X509 CRL-----\nfakedata\n-----END X509 CRL-----\n")
			Expect(store.UpdateCRL(context.Background(), data)).To(Succeed())

			got, err := store.GetCRL(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(data))
		})

		It("GetCRL returns an error when no CRL file exists", func() {
			_, err := store.GetCRL(context.Background())
			Expect(err).To(HaveOccurred())
		})
	})

	// --- CSR operations ---

	Describe("CSR operations", func() {
		const subject = "test-node"
		csrData := []byte("-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n")

		BeforeEach(func() {
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
		})

		It("SaveCSR / GetCSR roundtrip", func() {
			Expect(store.SaveCSR(context.Background(), subject, csrData)).To(Succeed())
			got, err := store.GetCSR(context.Background(), subject)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(csrData))
		})

		It("HasCSR reflects presence on disk", func() {
			Expect(store.HasCSR(context.Background(), subject)).To(BeFalse())
			Expect(store.SaveCSR(context.Background(), subject, csrData)).To(Succeed())
			Expect(store.HasCSR(context.Background(), subject)).To(BeTrue())
			Expect(store.DeleteCSR(context.Background(), subject)).To(Succeed())
			Expect(store.HasCSR(context.Background(), subject)).To(BeFalse())
		})

		It("GetCSR returns an error for a missing subject", func() {
			_, err := store.GetCSR(context.Background(), subject)
			Expect(err).To(HaveOccurred())
		})

		It("DeleteCSR returns an error for a missing subject", func() {
			err := store.DeleteCSR(context.Background(), subject)
			Expect(err).To(HaveOccurred())
		})
	})

	// --- Certificate operations ---

	Describe("Certificate operations", func() {
		const subject = "test-node"
		certData := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")

		BeforeEach(func() {
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
		})

		It("SaveCert / GetCert roundtrip", func() {
			Expect(store.SaveCert(context.Background(), subject, certData)).To(Succeed())
			got, err := store.GetCert(context.Background(), subject)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(certData))
		})

		It("HasCert reflects presence on disk", func() {
			Expect(store.HasCert(context.Background(), subject)).To(BeFalse())
			Expect(store.SaveCert(context.Background(), subject, certData)).To(Succeed())
			Expect(store.HasCert(context.Background(), subject)).To(BeTrue())
			Expect(store.DeleteCert(context.Background(), subject)).To(Succeed())
			Expect(store.HasCert(context.Background(), subject)).To(BeFalse())
		})

		It("GetCert returns an error for a missing subject", func() {
			_, err := store.GetCert(context.Background(), subject)
			Expect(err).To(HaveOccurred())
		})

		It("DeleteCert returns an error for a missing subject", func() {
			err := store.DeleteCert(context.Background(), subject)
			Expect(err).To(HaveOccurred())
		})
	})

	// --- ListCSRs ---

	Describe("ListCSRs", func() {
		BeforeEach(func() {
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
		})

		It("returns an empty slice when no CSRs are present", func() {
			subjects, err := store.ListCSRs(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(subjects).To(BeEmpty())
		})

		It("returns subjects for all .pem files in the requests directory", func() {
			for _, sub := range []string{"alpha", "beta", "gamma"} {
				Expect(store.SaveCSR(context.Background(), sub, []byte("fake"))).To(Succeed())
			}
			subjects, err := store.ListCSRs(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(subjects).To(ConsistOf("alpha", "beta", "gamma"))
		})

		It("ignores non-.pem files in the requests directory", func() {
			Expect(store.SaveCSR(context.Background(), "real-node", []byte("fake"))).To(Succeed())
			// Write a stray non-PEM file directly into the directory.
			Expect(os.WriteFile(filepath.Join(store.CSRDir(), "ignore.txt"), []byte("x"), 0644)).To(Succeed())
			subjects, err := store.ListCSRs(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(subjects).To(ConsistOf("real-node"))
		})
	})

	// --- CheckKeyPermissions ---

	Describe("CheckKeyPermissions", func() {
		BeforeEach(func() {
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
		})

		It("returns nil when no key files exist", func() {
			warnings := store.CheckKeyPermissions()
			Expect(warnings).To(BeEmpty())
		})

		It("returns nil when all key files have 0600 permissions", func() {
			Expect(os.WriteFile(store.PrivateKeyPath("node-a"), []byte("fake"), storage.FilePermPrivate)).To(Succeed())
			Expect(os.WriteFile(store.PrivateKeyPath("node-b"), []byte("fake"), storage.FilePermPrivate)).To(Succeed())
			warnings := store.CheckKeyPermissions()
			Expect(warnings).To(BeEmpty())
		})

		It("reports files with group-readable permissions (0640)", func() {
			keyPath := store.PrivateKeyPath("loose-node")
			Expect(os.WriteFile(keyPath, []byte("fake"), 0640)).To(Succeed())
			warnings := store.CheckKeyPermissions()
			Expect(warnings).To(HaveLen(1))
			Expect(warnings[0].Path).To(Equal(keyPath))
			Expect(warnings[0].Mode).To(Equal(os.FileMode(0640)))
		})

		It("reports files with world-readable permissions (0644)", func() {
			keyPath := store.PrivateKeyPath("wide-open")
			Expect(os.WriteFile(keyPath, []byte("fake"), 0644)).To(Succeed())
			warnings := store.CheckKeyPermissions()
			Expect(warnings).To(HaveLen(1))
			Expect(warnings[0].Path).To(Equal(keyPath))
			Expect(warnings[0].Mode).To(Equal(os.FileMode(0644)))
		})

		It("only checks files ending in _key.pem", func() {
			// A loose-perm file that doesn't match the _key.pem pattern should be ignored.
			Expect(os.WriteFile(filepath.Join(store.CADir(), "private", "other.pem"), []byte("x"), 0644)).To(Succeed())
			Expect(os.WriteFile(store.PrivateKeyPath("good-node"), []byte("fake"), storage.FilePermPrivate)).To(Succeed())
			warnings := store.CheckKeyPermissions()
			Expect(warnings).To(BeEmpty())
		})

		It("returns warnings only for loose files in a mixed set", func() {
			Expect(os.WriteFile(store.PrivateKeyPath("ok-node"), []byte("fake"), 0600)).To(Succeed())
			loosePath := store.PrivateKeyPath("bad-node")
			Expect(os.WriteFile(loosePath, []byte("fake"), 0644)).To(Succeed())
			warnings := store.CheckKeyPermissions()
			Expect(warnings).To(HaveLen(1))
			Expect(warnings[0].Path).To(Equal(loosePath))
		})

		It("returns nil when the private directory does not exist", func() {
			noDir := storage.New("/nonexistent/path")
			warnings := noDir.CheckKeyPermissions()
			Expect(warnings).To(BeEmpty())
		})
	})

	// --- HMAC inventory integrity ---

	Describe("HMAC inventory integrity", func() {
		BeforeEach(func() {
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
		})

		Describe("EnsureHMACKey", func() {
			It("generates a key on first call and returns the same key on second call", func() {
				key1, err := store.EnsureHMACKey(context.Background())
				Expect(err).NotTo(HaveOccurred())
				Expect(key1).To(HaveLen(32))

				key2, err := store.EnsureHMACKey(context.Background())
				Expect(err).NotTo(HaveOccurred())
				Expect(key2).To(Equal(key1))
			})

			It("stores the key file with 0600 permissions", func() {
				_, err := store.EnsureHMACKey(context.Background())
				Expect(err).NotTo(HaveOccurred())

				info, err := os.Stat(store.HMACKeyPath())
				Expect(err).NotTo(HaveOccurred())
				Expect(info.Mode().Perm()).To(Equal(os.FileMode(0600)))
			})
		})

		Describe("InitHMAC", func() {
			It("succeeds on a fresh directory and creates the HMAC file", func() {
				Expect(store.InitHMAC(context.Background())).To(Succeed())

				hmacPath := filepath.Join(tmpDir, ".inventory.hmac")
				_, err := os.Stat(hmacPath)
				Expect(err).NotTo(HaveOccurred(), "HMAC file should exist after InitHMAC")
			})

			It("succeeds when inventory already has content", func() {
				// Pre-populate inventory before HMAC initialization.
				Expect(os.WriteFile(store.InventoryPath(), []byte("0001 2024-01-01 2029-01-01 /node1\n"), storage.FilePermPrivate)).To(Succeed())
				Expect(store.InitHMAC(context.Background())).To(Succeed())
			})
		})

		Describe("VerifyInventoryHMAC", func() {
			It("passes with a valid inventory", func() {
				key, err := store.EnsureHMACKey(context.Background())
				Expect(err).NotTo(HaveOccurred())

				// Write inventory and compute initial HMAC.
				Expect(os.WriteFile(store.InventoryPath(), []byte("0001 2024-01-01 2029-01-01 /node1\n"), storage.FilePermPrivate)).To(Succeed())
				Expect(store.UpdateInventoryHMAC(context.Background(), key)).To(Succeed())

				Expect(store.VerifyInventoryHMAC(context.Background(), key)).To(Succeed())
			})

			It("fails after the inventory has been tampered with", func() {
				key, err := store.EnsureHMACKey(context.Background())
				Expect(err).NotTo(HaveOccurred())

				Expect(os.WriteFile(store.InventoryPath(), []byte("0001 2024-01-01 2029-01-01 /node1\n"), storage.FilePermPrivate)).To(Succeed())
				Expect(store.UpdateInventoryHMAC(context.Background(), key)).To(Succeed())

				// Tamper with the inventory.
				Expect(os.WriteFile(store.InventoryPath(), []byte("0001 2024-01-01 2029-01-01 /evil-node\n"), storage.FilePermPrivate)).To(Succeed())

				err = store.VerifyInventoryHMAC(context.Background(), key)
				Expect(err).To(MatchError(storage.ErrInventoryTampered))
			})

			It("initializes HMAC baseline when no HMAC file exists yet", func() {
				key, err := store.EnsureHMACKey(context.Background())
				Expect(err).NotTo(HaveOccurred())

				// VerifyInventoryHMAC on first call should create the HMAC file (migration).
				Expect(store.VerifyInventoryHMAC(context.Background(), key)).To(Succeed())

				hmacPath := filepath.Join(tmpDir, ".inventory.hmac")
				_, err = os.Stat(hmacPath)
				Expect(err).NotTo(HaveOccurred(), "HMAC file should be created on first verify")
			})
		})

		Describe("AppendInventory + ReadInventory round-trip with HMAC", func() {
			It("works normally when HMAC is initialized", func() {
				Expect(store.InitHMAC(context.Background())).To(Succeed())

				Expect(store.AppendInventory(context.Background(), "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1")).To(Succeed())
				Expect(store.AppendInventory(context.Background(), "0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2")).To(Succeed())

				data, err := store.ReadInventory(context.Background())
				Expect(err).NotTo(HaveOccurred())
				Expect(string(data)).To(ContainSubstring("/node1"))
				Expect(string(data)).To(ContainSubstring("/node2"))
			})
		})

		Describe("Tamper detection end-to-end", func() {
			It("ReadInventory returns ErrInventoryTampered when inventory is modified after InitHMAC", func() {
				Expect(store.InitHMAC(context.Background())).To(Succeed())

				Expect(store.AppendInventory(context.Background(), "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /legit-node")).To(Succeed())

				// Tamper with the inventory file directly on disk.
				invPath := store.InventoryPath()
				Expect(os.WriteFile(invPath, []byte("0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /attacker-node\n"), storage.FilePermPrivate)).To(Succeed())

				_, err := store.ReadInventory(context.Background())
				Expect(err).To(MatchError(storage.ErrInventoryTampered))
			})
		})
	})

	// --- Inventory file permissions ---

	Describe("Inventory file permissions", func() {
		BeforeEach(func() {
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
		})

		It("AppendInventory creates inventory with 0600 permissions", func() {
			// Ensure no pre-existing inventory file.
			os.Remove(store.InventoryPath())

			Expect(store.AppendInventory(context.Background(), "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1")).To(Succeed())

			info, err := os.Stat(store.InventoryPath())
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0600)))
		})
	})

	// --- ListCerts ---

	Describe("ListCerts", func() {
		BeforeEach(func() {
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
		})

		It("returns an empty slice when no certs are present", func() {
			subjects, err := store.ListCerts(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(subjects).To(BeEmpty())
		})

		It("returns subjects for all .pem files in the signed directory", func() {
			for _, sub := range []string{"node-1", "node-2", "node-3"} {
				Expect(store.SaveCert(context.Background(), sub, []byte("fake"))).To(Succeed())
			}
			subjects, err := store.ListCerts(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(subjects).To(ConsistOf("node-1", "node-2", "node-3"))
		})

		It("ignores non-.pem files in the signed directory", func() {
			Expect(store.SaveCert(context.Background(), "real-cert", []byte("fake"))).To(Succeed())
			Expect(os.WriteFile(filepath.Join(store.SignedDir(), "stray.log"), []byte("x"), 0644)).To(Succeed())
			subjects, err := store.ListCerts(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(subjects).To(ConsistOf("real-cert"))
		})
	})
})
