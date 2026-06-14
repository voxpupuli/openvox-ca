// Copyright (C) 2026 Trevor Vaughan
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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

var _ = Describe("API security hardening", func() {
	Context("internal errors are not leaked to clients", func() {
		It("returns a generic 500 body that does not contain the on-disk path when storage listing fails", func() {
			// Build a CA whose signed-cert listing is guaranteed to fail with a
			// path-bearing error: the "signed" entry is a regular file, so
			// os.ReadDir returns a *PathError containing the temp directory path.
			tmpDir, err := os.MkdirTemp("", "openvox-ca-leak-test")
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(tmpDir)

			Expect(os.MkdirAll(filepath.Join(tmpDir, "requests"), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(tmpDir, "signed"), []byte("not a directory"), 0o644)).To(Succeed())

			store := storage.New(tmpDir)
			leakCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			leakServer := api.New(leakCA)
			leakMux := leakServer.Routes()

			req := httptest.NewRequest("GET", "/certificate_statuses/any", nil)
			rr := httptest.NewRecorder()
			leakMux.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusInternalServerError))
			// The raw error chain (including the temp directory path) must not
			// reach the client.
			Expect(rr.Body.String()).NotTo(ContainSubstring(tmpDir))
			Expect(rr.Body.String()).NotTo(ContainSubstring("not a directory"))
			Expect(rr.Body.String()).To(ContainSubstring("internal server error"))
		})

		It("returns a generic body on PUT /certificate_request when saving the CSR fails, without leaking the on-disk path", func() {
			// Unauthenticated endpoint. Force SaveCSR to fail with a path-bearing
			// error: make the "requests" directory a regular file so the atomic
			// write inside it returns a *PathError carrying the temp directory.
			tmpDir, err := os.MkdirTemp("", "openvox-ca-csr-leak-test")
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(tmpDir)

			Expect(os.MkdirAll(filepath.Join(tmpDir, "signed"), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(tmpDir, "requests"), []byte("not a directory"), 0o644)).To(Succeed())

			store := storage.New(tmpDir)
			leakCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			leakMux := api.New(leakCA).Routes()

			const subject = "leaknode.test"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())

			req := httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM))
			rr := httptest.NewRecorder()
			leakMux.ServeHTTP(rr, req)

			// The storage path must never reach this unauthenticated client.
			Expect(rr.Body.String()).NotTo(ContainSubstring(tmpDir))
			Expect(rr.Body.String()).NotTo(ContainSubstring("requests"))
			Expect(rr.Body.String()).NotTo(ContainSubstring("not a directory"))
		})
	})

	Context("JSON request bodies are size-capped", func() {
		var leakMux http.Handler

		BeforeEach(func() {
			tmpDir, err := os.MkdirTemp("", "openvox-ca-bodycap-test")
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { os.RemoveAll(tmpDir) })

			store := storage.New(tmpDir)
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
			capCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			leakMux = api.New(capCA).Routes()
		})

		It("rejects an oversize POST /sign body with 413", func() {
			// A syntactically valid JSON body that exceeds the 1 MiB cap, so the
			// decoder keeps reading until MaxBytesReader trips (rather than
			// failing early on a malformed token).
			huge := bytes.Repeat([]byte("a"), (1<<20)+16)
			oversize := append(append([]byte(`{"certnames":["`), huge...), []byte(`"]}`)...)
			req := httptest.NewRequest("POST", "/sign", bytes.NewReader(oversize))
			rr := httptest.NewRecorder()
			leakMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusRequestEntityTooLarge))
		})

		It("rejects an oversize PUT /clean body with 413", func() {
			// A syntactically valid JSON body that exceeds the 1 MiB cap, so the
			// decoder keeps reading until MaxBytesReader trips (rather than
			// failing early on a malformed token).
			huge := bytes.Repeat([]byte("a"), (1<<20)+16)
			oversize := append(append([]byte(`{"certnames":["`), huge...), []byte(`"]}`)...)
			req := httptest.NewRequest("PUT", "/clean", bytes.NewReader(oversize))
			rr := httptest.NewRecorder()
			leakMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusRequestEntityTooLarge))
		})
	})
})
