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

package ca_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// "CA private key encrypted at rest" is logged after a key has been written
// encrypted, by each path that writes one. The import path's specs are in
// caimportkey_test.go; these cover the two paths that create a key.
var _ = Describe("Logging a CA key created encrypted", func() {
	const line = "CA private key encrypted at rest"

	var (
		ctx    context.Context
		dir    string
		pp     ca.KeyPassphraseConfig
		logBuf *bytes.Buffer
	)

	BeforeEach(func() {
		ctx = context.Background()
		GinkgoT().Setenv(ca.DefaultPassphraseEnvVar, "")
		dir = GinkgoT().TempDir()
		ppFile := filepath.Join(dir, "passphrase")
		Expect(os.WriteFile(ppFile, []byte("log-passphrase\n"), 0o600)).To(Succeed())
		pp = ca.KeyPassphraseConfig{PassphraseFile: ppFile}

		logBuf = &bytes.Buffer{}
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelInfo})))
		DeferCleanup(func() { slog.SetDefault(orig) })
	})

	newCA := func(encrypt bool) *ca.CA {
		myCA := ca.New(storage.New(filepath.Join(dir, "cadir")), ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.EncryptCAKey = encrypt
		myCA.KeyPassphrase = pp
		return myCA
	}

	DescribeTable("bootstrap says so exactly when it wrote the key encrypted",
		func(encrypt bool, want int) {
			Expect(newCA(encrypt).Init(ctx)).To(Succeed())

			Expect(strings.Count(logBuf.String(), line)).To(Equal(want))
		},
		Entry("with encrypt_ca_key", true, 1),
		Entry("without it", false, 0),
	)

	DescribeTable("csr --create-key says so exactly when it wrote the key encrypted",
		func(encrypt bool, want int) {
			_, err := newCA(encrypt).LoadOrCreateCAKey(ctx, true)
			Expect(err).NotTo(HaveOccurred())

			Expect(strings.Count(logBuf.String(), line)).To(Equal(want))
		},
		Entry("with encrypt_ca_key", true, 1),
		Entry("without it", false, 0),
	)
})
