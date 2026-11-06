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

package main

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// A config file with a DSN but no storage_backend used to send migrate to the
// filesystem backend under its cadir (#484): reading an empty source, or
// writing the copy to a directory instead of the database the file describes.
var _ = Describe("migrate given another backend's settings but no storage_backend", func() {
	var srcCfg, dstCfg, srcDir, dstDir string

	BeforeEach(func() {
		cfgDir := GinkgoT().TempDir()
		srcCfg = filepath.Join(cfgDir, "src.yaml")
		dstCfg = filepath.Join(cfgDir, "dst.yaml")
		srcDir = GinkgoT().TempDir()
		dstDir = GinkgoT().TempDir()
		seedFilesystemCA(srcDir)
		fsConfig(srcCfg, srcDir)
		fsConfig(dstCfg, dstDir)
	})

	migrate := func() error {
		cmd := newMigrateCmd()
		cmd.SetArgs([]string{"--source-config", srcCfg, "--dest-config", dstCfg})
		return cmd.Execute()
	}

	It("refuses the source", func() {
		writeFile(srcCfg, "cadir: "+srcDir+"\nsql_dsn: postgres://ca@db/ca\n")

		Expect(migrate()).To(MatchError(And(
			HavePrefix("source backend: "),
			ContainSubstring("storage_backend is not set"),
			ContainSubstring("(sql_dsn)"),
		)))
	})

	// migrate reads its config files and nothing else, so naming a variable
	// would send the operator to the wrong place.
	It("names the setting by its config-file key alone", func() {
		writeFile(srcCfg, "cadir: "+srcDir+"\nsql_dsn: postgres://ca@db/ca\n")

		Expect(migrate()).To(MatchError(Not(ContainSubstring("OPENVOX_CA_"))))
	})

	It("refuses the destination, and writes nothing to its cadir", func() {
		writeFile(dstCfg, "cadir: "+dstDir+"\nsql_dsn_file: /run/secrets/dsn\n")

		Expect(migrate()).To(MatchError(And(
			HavePrefix("destination backend: "),
			ContainSubstring("storage_backend is not set"),
			ContainSubstring("(sql_dsn_file)"),
		)))
		entries, err := os.ReadDir(dstDir)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty())
	})
})
