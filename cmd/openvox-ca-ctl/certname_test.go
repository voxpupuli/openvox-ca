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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// SECURITY: every subcommand that puts --certname into a request path, and
// generate, which also builds its key file name from it.
//
// The certname is the operator's own input, so this is robustness rather than
// a defence against an attacker, but the two halves were reachable in
// different ways. A "/" or ".." in a request path needed nothing hostile: the
// server's router cleans the path and redirects, and the client followed the
// redirect to a different route. The key file name could leave --out-dir only
// once the server had answered 2xx for such a name, which needs a broken or
// hostile server. What the CLI owns is that neither can happen, and that
// generate never writes its key through a symlink.
//
// There is no spec for a valid certname arriving percent-escaped, because none
// can be written: every name ca.ValidateSubject accepts is made of unreserved
// characters, so url.PathEscape leaves it unchanged. The control table below
// pins that such a name still arrives verbatim, as one segment.
var _ = Describe("certname in request and file paths", func() {
	var (
		hits       int
		gotMethod  string
		gotRawPath string
		onRequest  func()
		srv        *httptest.Server
		cfg        string
		outDir     string
		escapeDir  string
		certFile   string
	)

	// One body that every subcommand here can parse: generate reads the key
	// and certificate, import-cert the summary, and the rest ignore it.
	const okBody = `{"private_key":"KEY","certificate":"CERT",` +
		`"subject":"x","serial":"01","imported":true}`

	// hostile climbs out of --out-dir into a sibling directory that exists, so
	// a key file built from it would land somewhere a spec can look.
	const hostile = "../sign/all"

	BeforeEach(func() {
		saveCtlGlobals()
		clearCtlEnv()
		cfg = writeTempCtlConfig("")
		root := GinkgoT().TempDir()
		outDir = filepath.Join(root, "out")
		escapeDir = filepath.Join(root, "sign")
		Expect(os.Mkdir(outDir, 0o700)).To(Succeed())
		Expect(os.Mkdir(escapeDir, 0o700)).To(Succeed())
		certFile = filepath.Join(GinkgoT().TempDir(), "cert.pem")
		Expect(os.WriteFile(certFile, []byte("PEM"), 0o600)).To(Succeed())

		hits, gotMethod, gotRawPath = 0, "", ""
		onRequest = nil
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits++
			gotMethod, gotRawPath = r.Method, r.URL.EscapedPath()
			if onRequest != nil {
				onRequest()
			}
			_, _ = w.Write([]byte(okBody))
		}))
		DeferCleanup(srv.Close)
	})

	// argsFor returns the arguments that drive one subcommand at certname.
	argsFor := func(subcommand, certname string) []string {
		args := []string{subcommand, "--config", cfg, "--server-url", srv.URL, "--certname", certname}
		switch subcommand {
		case "generate":
			args = append(args, "--out-dir", outDir)
		case "import-cert":
			args = append(args, "--cert-file", certFile)
		}
		return args
	}

	run := func(subcommand, certname string) error {
		GinkgoHelper()
		_, err := captureStdout(argsFor(subcommand, certname))
		return err
	}

	emptyDir := func(dir string) {
		GinkgoHelper()
		entries, err := os.ReadDir(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty(), "nothing is written to %s for a refused certname", dir)
	}

	// The empty name is here because it used to address the collection
	// route, /certificate_status/ with nothing after it. sign is absent from
	// those entries because it refuses an empty --certname with its own
	// message before reaching certnamePath.
	DescribeTable("refuses an invalid certname before sending any request",
		func(subcommand, certname string) {
			err := run(subcommand, certname)

			Expect(err).To(HaveOccurred(), "%s must refuse %q", subcommand, certname)
			Expect(hits).To(BeZero(),
				"%s sent a request for an invalid certname, to %s %s", subcommand, gotMethod, gotRawPath)
			Expect(err.Error()).To(ContainSubstring("--certname"), "the error names the flag")
			Expect(err.Error()).To(ContainSubstring(strconv.Quote(certname)), "the error names the certname, quoted")
			Expect(err.Error()).To(ContainSubstring("path traversal"), "the error says why")

			emptyDir(outDir)
			emptyDir(escapeDir)
		},
		Entry("sign", "sign", hostile),
		Entry("revoke", "revoke", hostile),
		Entry("clean", "clean", hostile),
		Entry("generate", "generate", hostile),
		Entry("import-cert", "import-cert", hostile),
		Entry("revoke, empty", "revoke", ""),
		Entry("clean, empty", "clean", ""),
		Entry("generate, empty", "generate", ""),
		Entry("import-cert, empty", "import-cert", ""),
	)

	// The control for the table above: validation must not refuse a valid
	// name, and the escape must not alter one. The name carries every
	// punctuation character a subject may contain.
	DescribeTable("sends a valid certname verbatim, as one path segment",
		func(subcommand, method, route string) {
			const valid = "node_1.example-a.com"
			Expect(run(subcommand, valid)).To(Succeed())

			Expect(hits).To(Equal(1))
			Expect(gotMethod).To(Equal(method))
			Expect(gotRawPath).To(Equal(route + valid))
		},
		Entry("sign", "sign", "PUT", "/puppet-ca/v1/certificate_status/"),
		Entry("revoke", "revoke", "PUT", "/puppet-ca/v1/certificate_status/"),
		Entry("clean", "clean", "DELETE", "/puppet-ca/v1/certificate_status/"),
		Entry("generate", "generate", "POST", "/puppet-ca/v1/generate/"),
		Entry("import-cert", "import-cert", "PUT", "/puppet-ca/v1/certificate/"),
	)

	Describe("generate's private key file", func() {
		const certname = "node1.example.com"
		var keyPath, target string

		BeforeEach(func() {
			keyPath = filepath.Join(outDir, certname+"_key.pem")
			target = filepath.Join(GinkgoT().TempDir(), "elsewhere.pem")
		})

		// What the symlink specs share: the key went nowhere, and the link is
		// as it was.
		notThroughLink := func() {
			GinkgoHelper()
			_, statErr := os.Lstat(target)
			Expect(statErr).To(MatchError(os.ErrNotExist),
				"the key must not land wherever the symlink points")
			fi, err := os.Lstat(keyPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(fi.Mode()&os.ModeSymlink).NotTo(BeZero(), "the symlink is left as it was")
		}

		It("creates the key file at 0600, holding the key the server returned", func() {
			Expect(run("generate", certname)).To(Succeed())

			fi, err := os.Stat(keyPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(fi.Mode().Perm()).To(Equal(os.FileMode(0o600)))
			Expect(os.ReadFile(keyPath)).To(Equal([]byte("KEY")))
		})

		It("overwrites an existing key file and narrows its mode to 0600", func() {
			// Overwriting is the documented case, not an accident: the
			// serving-certificate procedure points --out-dir at the server's
			// own key directory. The mode is the part that used to go wrong,
			// because os.WriteFile keeps an existing file's permissions. The
			// old contents are longer than the new key, so a write that did
			// not truncate would leave their tail behind.
			Expect(os.WriteFile(keyPath, []byte("OLD KEY MATERIAL"), 0o644)).To(Succeed())
			// Chmod as well: os.WriteFile's mode is filtered by the umask, and
			// under 077 the seed would already be 0600.
			Expect(os.Chmod(keyPath, 0o644)).To(Succeed())

			Expect(run("generate", certname)).To(Succeed())

			fi, err := os.Stat(keyPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(fi.Mode().Perm()).To(Equal(os.FileMode(0o600)),
				"a key must not inherit a world-readable mode from the file it replaced")
			Expect(os.ReadFile(keyPath)).To(Equal([]byte("KEY")))
		})

		It("refuses a symlink at the key path before asking the server for a key", func() {
			Expect(os.Symlink(target, keyPath)).To(Succeed())

			err := run("generate", certname)

			Expect(err).To(MatchError(ContainSubstring("symbolic link")))
			Expect(hits).To(BeZero(),
				"the server must not issue a certificate whose key the CLI will not write")
			notThroughLink()
		})

		It("refuses a symlink planted at the key path while the request is in flight", func() {
			// After the pre-flight check and before the write: the gap only
			// O_NOFOLLOW on the open itself can close.
			onRequest = func() {
				defer GinkgoRecover()
				Expect(os.Symlink(target, keyPath)).To(Succeed())
			}

			err := run("generate", certname)

			Expect(err).To(MatchError(ContainSubstring("failed to save private key")))
			Expect(err).To(MatchError(ContainSubstring("run clean --certname")),
				"a failure after issuance must say how to recover from it")
			Expect(hits).To(Equal(1))
			notThroughLink()
		})

		// runBounded runs generate against a FIFO at the key path. A write
		// that reaches a FIFO with no reader blocks in open for ever, so a
		// regression must fail here within its own bound rather than hang the
		// suite. Should the open block, the cleanup's reader releases it, so
		// the specs that follow are not wedged either.
		runBounded := func() error {
			GinkgoHelper()
			DeferCleanup(func() {
				if r, err := os.OpenFile(keyPath, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
					_ = r.Close()
				}
			})
			done := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				done <- run("generate", certname)
			}()
			var err error
			Eventually(done, "5s").Should(Receive(&err), "generate hung opening a FIFO")
			return err
		}

		It("refuses a FIFO at the key path before asking the server for a key", func() {
			Expect(syscall.Mkfifo(keyPath, 0o600)).To(Succeed())

			err := runBounded()

			Expect(err).To(MatchError(ContainSubstring("not a regular file")))
			Expect(hits).To(BeZero())
		})

		It("refuses a FIFO planted at the key path while the request is in flight", func() {
			// The gap O_NONBLOCK closes.
			onRequest = func() {
				defer GinkgoRecover()
				Expect(syscall.Mkfifo(keyPath, 0o600)).To(Succeed())
			}

			err := runBounded()

			Expect(err).To(MatchError(ContainSubstring("failed to save private key")))
			Expect(hits).To(Equal(1))
		})

		It("does not write the key into a FIFO that someone is reading", func() {
			// With a reader attached the open succeeds even with O_NONBLOCK.
			// What stops the key reaching whoever holds the other end is then
			// platform-dependent below this layer: Linux refuses to truncate a
			// FIFO, darwin does not. The regular-file check on the opened
			// descriptor refuses on both, and the error asserted here is its
			// own, so it is that check this spec pins.
			var reader *os.File
			onRequest = func() {
				defer GinkgoRecover()
				Expect(syscall.Mkfifo(keyPath, 0o600)).To(Succeed())
				var err error
				reader, err = os.OpenFile(keyPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
				Expect(err).NotTo(HaveOccurred())
			}

			err := run("generate", certname)
			Expect(reader).NotTo(BeNil())
			DeferCleanup(reader.Close)

			Expect(err).To(MatchError(ContainSubstring("not a regular file")))
			buf := make([]byte, 16)
			n, _ := reader.Read(buf)
			Expect(buf[:n]).To(BeEmpty(), "the key reached the FIFO's reader")
		})

		It("refuses a missing --out-dir before asking the server for a key", func() {
			outDir = filepath.Join(outDir, "missing")

			err := run("generate", certname)

			Expect(err).To(MatchError(ContainSubstring("--out-dir")))
			Expect(err).To(MatchError(ContainSubstring("nothing was sent to the server")))
			Expect(hits).To(BeZero(),
				"a path the key cannot be written to must not cost an issued certificate")
		})

		It("follows a symlinked --out-dir to the directory it names", func() {
			// The directory is the operator's own choice, so only a link at
			// the key path itself is refused.
			link := filepath.Join(GinkgoT().TempDir(), "out-link")
			Expect(os.Symlink(outDir, link)).To(Succeed())
			outDir = link

			Expect(run("generate", certname)).To(Succeed())

			Expect(os.ReadFile(keyPath)).To(Equal([]byte("KEY")),
				"the key lands in the directory the link names")
		})

		It("refuses an --out-dir that is not a directory before asking the server for a key", func() {
			outDir = filepath.Join(outDir, "file")
			Expect(os.WriteFile(outDir, nil, 0o600)).To(Succeed())

			err := run("generate", certname)

			Expect(err).To(MatchError(ContainSubstring("is not a directory")))
			Expect(hits).To(BeZero())
		})

		It("refuses a key path it cannot inspect before asking the server for a key", func() {
			// An --out-dir without search permission: the Lstat fails with
			// EACCES rather than ENOENT, and the write would fail the same way
			// once the certificate had been issued.
			if os.Geteuid() == 0 {
				Skip("root bypasses directory permissions")
			}
			Expect(os.Chmod(outDir, 0o600)).To(Succeed())
			DeferCleanup(os.Chmod, outDir, os.FileMode(0o700))

			err := run("generate", certname)

			Expect(err).To(MatchError(ContainSubstring("checking private key path")))
			Expect(hits).To(BeZero())
		})
	})
})
