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

package fileexport_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/voxpupuli/openvox-ca/internal/fileexport"
)

// Two-block chains, so a narrowing scope is distinguishable from chain. The
// bodies are arbitrary base64; nothing here parses a certificate or a CRL.
const (
	issuingCert = "-----BEGIN CERTIFICATE-----\nSVNTVUlORw==\n-----END CERTIFICATE-----\n"
	rootCert    = "-----BEGIN CERTIFICATE-----\nUk9PVA==\n-----END CERTIFICATE-----\n"
	certChain   = issuingCert + rootCert

	ownCRL      = "-----BEGIN X509 CRL-----\nT1dO\n-----END X509 CRL-----\n"
	upstreamCRL = "-----BEGIN X509 CRL-----\nVVBTVFJFQU0=\n-----END X509 CRL-----\n"
	crlChain    = ownCRL + upstreamCRL
)

// stubSource is a MaterialSource returning fixed PEM bytes.
type stubSource struct {
	cert, crl []byte
	certErr   error
	crlErr    error
}

func (s *stubSource) GetCACert(context.Context) ([]byte, error) { return s.cert, s.certErr }
func (s *stubSource) GetCRL(context.Context) ([]byte, error)    { return s.crl, s.crlErr }

// metricValue gathers reg and returns the value of the counter or gauge series
// matching name and labels, or false when no such series exists.
func metricValue(reg *prometheus.Registry, name string, labels map[string]string) (float64, bool) {
	GinkgoHelper()
	mfs, err := reg.Gather()
	Expect(err).NotTo(HaveOccurred())
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			have := make(map[string]string, len(m.GetLabel()))
			for _, lp := range m.GetLabel() {
				have[lp.GetName()] = lp.GetValue()
			}
			matched := len(have) == len(labels)
			for k, v := range labels {
				if have[k] != v {
					matched = false
				}
			}
			if !matched {
				continue
			}
			if c := m.GetCounter(); c != nil {
				return c.GetValue(), true
			}
			return m.GetGauge().GetValue(), true
		}
	}
	return 0, false
}

func readFile(path string) string {
	GinkgoHelper()
	b, err := os.ReadFile(path)
	Expect(err).NotTo(HaveOccurred())
	return string(b)
}

var _ = Describe("Exporter", func() {
	var (
		ctx      context.Context
		dir      string
		crlPath  string
		certPath string
		src      *stubSource
		reg      *prometheus.Registry
		metrics  *fileexport.Metrics
	)

	BeforeEach(func() {
		ctx = context.Background()
		dir = GinkgoT().TempDir()
		crlPath = filepath.Join(dir, "crl.pem")
		certPath = filepath.Join(dir, "ca.pem")
		src = &stubSource{cert: []byte(certChain), crl: []byte(crlChain)}
		reg = prometheus.NewRegistry()
		metrics = fileexport.NewMetrics(reg)
	})

	newExporter := func(targets ...fileexport.Target) *fileexport.Exporter {
		GinkgoHelper()
		cfg := fileexport.Config{Targets: targets}
		Expect(cfg.Validate()).To(Succeed())
		return fileexport.New(cfg, src, metrics)
	}

	syncs := func(path, result string) float64 {
		GinkgoHelper()
		v, found := metricValue(reg, "openvoxca_file_export_syncs_total",
			map[string]string{"path": path, "result": result})
		Expect(found).To(BeTrue(), "syncs_total{path=%q,result=%q} must exist", path, result)
		return v
	}

	gauge := func(name, path string) (float64, bool) {
		GinkgoHelper()
		return metricValue(reg, "openvoxca_file_export_"+name, map[string]string{"path": path})
	}

	// captureLogs sends slog to a buffer until the spec ends. Call it after the
	// fixture is built, so that what it holds is what the sync under test
	// logged and nothing else. SyncAll runs on the spec's own goroutine, so the
	// buffer needs no lock.
	captureLogs := func() *bytes.Buffer {
		GinkgoHelper()
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
		DeferCleanup(func() { slog.SetDefault(orig) })
		return &buf
	}

	Describe("writing", func() {
		It("writes a missing file with the whole chain, world-readable and no wider", func() {
			exp := newExporter(
				fileexport.Target{Path: crlPath, Material: "crl"},
				fileexport.Target{Path: certPath, Material: "cert"},
			)
			Expect(exp.SyncAll(ctx)).To(Succeed())

			Expect(readFile(crlPath)).To(Equal(crlChain))
			Expect(readFile(certPath)).To(Equal(certChain))
			for _, p := range []string{crlPath, certPath} {
				info, err := os.Stat(p)
				Expect(err).NotTo(HaveOccurred())
				// World-readable, because the material is public. That the umask
				// cannot narrow it is AtomicWriteFile's property, pinned under a
				// planted umask in internal/storage/atomicwrite_test.go; under
				// the usual 022 this assertion could not tell the two apart.
				Expect(info.Mode().Perm()).To(Equal(fs.FileMode(0o644)),
					"an exported CA certificate or CRL is public and written world-readable")
			}
		})

		DescribeTable("narrows to what the scope asks for",
			func(material, scope, want string) {
				path := filepath.Join(dir, material+"-"+scope)
				exp := newExporter(fileexport.Target{Path: path, Material: material, Scope: scope})
				Expect(exp.SyncAll(ctx)).To(Succeed())
				Expect(readFile(path)).To(Equal(want))
			},
			Entry("cert, self: the issuing CA alone", "cert", "self", issuingCert),
			Entry("cert, root: the trust anchor alone", "cert", "root", rootCert),
			Entry("crl, self: this CA's block alone", "crl", "self", ownCRL),
			Entry("crl, chain: the stored blob verbatim", "crl", "chain", crlChain),
		)

		It("rewrites the file when the material changes", func() {
			exp := newExporter(fileexport.Target{Path: crlPath, Material: "crl"})
			Expect(exp.SyncAll(ctx)).To(Succeed())

			src.crl = []byte(upstreamCRL + ownCRL)
			Expect(exp.SyncAll(ctx)).To(Succeed())
			Expect(readFile(crlPath)).To(Equal(upstreamCRL + ownCRL))
		})

		It("rewrites a file of the right length whose bytes differ", func() {
			// The size check short-circuits only a mismatch, so equal length
			// must still be compared byte for byte.
			Expect(os.WriteFile(crlPath, []byte(upstreamCRL+ownCRL), 0o644)).To(Succeed())
			Expect(len(upstreamCRL + ownCRL)).To(Equal(len(crlChain)))

			exp := newExporter(fileexport.Target{Path: crlPath, Material: "crl"})
			Expect(exp.SyncAll(ctx)).To(Succeed())
			Expect(readFile(crlPath)).To(Equal(crlChain))
		})
	})

	Describe("leaving a current file alone", func() {
		It("neither rewrites nor re-modes a file that already holds the material", func() {
			// 0640, an old mtime, and the inode: a rewrite would replace all
			// three, since AtomicWriteFile renames a fresh 0644 file into place.
			Expect(os.WriteFile(crlPath, []byte(crlChain), 0o600)).To(Succeed())
			Expect(os.Chmod(crlPath, 0o640)).To(Succeed())
			old := time.Now().Add(-time.Hour).Truncate(time.Second)
			Expect(os.Chtimes(crlPath, old, old)).To(Succeed())
			before, err := os.Stat(crlPath)
			Expect(err).NotTo(HaveOccurred())

			exp := newExporter(fileexport.Target{Path: crlPath, Material: "crl"})
			Expect(exp.SyncAll(ctx)).To(Succeed())

			after, err := os.Stat(crlPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(after.Mode().Perm()).To(Equal(fs.FileMode(0o640)))
			Expect(after.ModTime()).To(Equal(before.ModTime()))
			Expect(os.SameFile(before, after)).To(BeTrue(), "the file must not have been replaced")
		})

		It("still counts the check as a success, which is what keeps it from looking stale", func() {
			Expect(os.WriteFile(crlPath, []byte(crlChain), 0o644)).To(Succeed())
			exp := newExporter(fileexport.Target{Path: crlPath, Material: "crl"})
			Expect(exp.SyncAll(ctx)).To(Succeed())

			Expect(syncs(crlPath, "success")).To(Equal(1.0))
			v, found := gauge("last_success_timestamp_seconds", crlPath)
			Expect(found).To(BeTrue())
			Expect(v).To(BeNumerically(">", 0))
		})
	})

	Describe("failing", func() {
		It("keeps the previous file when the CRL cannot be read, and says so", func() {
			Expect(os.WriteFile(crlPath, []byte(ownCRL), 0o644)).To(Succeed())
			src.crlErr = errors.New("storage down")

			exp := newExporter(fileexport.Target{Path: crlPath, Material: "crl"})
			logs := captureLogs()
			Expect(exp.SyncAll(ctx)).To(MatchError(And(
				ContainSubstring(crlPath), ContainSubstring("storage down"))))

			Expect(readFile(crlPath)).To(Equal(ownCRL), "a stale copy must be kept, not removed")
			// The alert's annotation and docs/file-export.md tell an operator to
			// grep for this message, so it is part of the runbook.
			Expect(logs.String()).To(And(
				ContainSubstring(`level=WARN msg="File export failed for target"`),
				ContainSubstring("path="+crlPath),
				ContainSubstring("storage down")))
			Expect(syncs(crlPath, "error")).To(Equal(1.0))
			Expect(syncs(crlPath, "success")).To(Equal(0.0))
			_, found := gauge("last_success_timestamp_seconds", crlPath)
			Expect(found).To(BeFalse())
			v, found := gauge("last_error_timestamp_seconds", crlPath)
			Expect(found).To(BeTrue())
			Expect(v).To(BeNumerically(">", 0))
		})

		DescribeTable("fails only the targets that asked for the material that could not be read",
			func(failCert bool) {
				failed, written, want := crlPath, certPath, certChain
				if failCert {
					src.certErr = errors.New("storage down")
					failed, written, want = certPath, crlPath, crlChain
				} else {
					src.crlErr = errors.New("storage down")
				}
				exp := newExporter(
					fileexport.Target{Path: crlPath, Material: "crl"},
					fileexport.Target{Path: certPath, Material: "cert"},
				)
				// The storage error, not "refusing to export an empty ...": the
				// empty-material guard would also keep the old file, but would
				// name the symptom instead of the read that caused it.
				Expect(exp.SyncAll(ctx)).To(MatchError(And(
					ContainSubstring(failed), ContainSubstring("storage down"),
					Not(ContainSubstring("refusing to export an empty")))))

				Expect(readFile(written)).To(Equal(want))
				Expect(syncs(written, "success")).To(Equal(1.0))
				Expect(syncs(failed, "error")).To(Equal(1.0))
				Expect(failed).NotTo(BeAnExistingFile())
			},
			Entry("the CRL", false),
			Entry("the CA certificate", true),
		)

		It("refuses to replace a file with an empty material", func() {
			Expect(os.WriteFile(crlPath, []byte(ownCRL), 0o644)).To(Succeed())
			src.crl = nil

			exp := newExporter(fileexport.Target{Path: crlPath, Material: "crl"})
			Expect(exp.SyncAll(ctx)).To(MatchError(ContainSubstring("refusing to export an empty crl")))
			Expect(readFile(crlPath)).To(Equal(ownCRL))
		})

		It("keeps the previous file when the directory cannot be written", func() {
			if os.Geteuid() == 0 {
				Skip("root writes through a read-only directory mode")
			}
			exp := newExporter(fileexport.Target{Path: crlPath, Material: "crl"})
			Expect(exp.SyncAll(ctx)).To(Succeed())

			Expect(os.Chmod(dir, 0o555)).To(Succeed())
			DeferCleanup(os.Chmod, dir, fs.FileMode(0o755))
			src.crl = []byte(upstreamCRL + ownCRL)

			Expect(exp.SyncAll(ctx)).To(HaveOccurred())
			Expect(readFile(crlPath)).To(Equal(crlChain))
			Expect(syncs(crlPath, "error")).To(Equal(1.0))
		})

		// The two ways a target can fail to be inspected. Each decides what
		// happens to a file the CA cannot see into, and the answer has to be
		// "leave it": treating either as "differs" would rename a fresh file
		// over one an operator locked down, and count it a success.
		It("keeps a file it cannot read to compare, and counts the failure", func() {
			if os.Geteuid() == 0 {
				Skip("root reads through a 0000 mode")
			}
			// Same length as the material, so the size check cannot settle it
			// and the read has to happen.
			other := upstreamCRL + ownCRL
			Expect(len(other)).To(Equal(len(crlChain)))
			Expect(os.WriteFile(crlPath, []byte(other), 0o600)).To(Succeed())
			Expect(os.Chmod(crlPath, 0o000)).To(Succeed())
			DeferCleanup(os.Chmod, crlPath, fs.FileMode(0o600))
			before, err := os.Stat(crlPath)
			Expect(err).NotTo(HaveOccurred())

			exp := newExporter(fileexport.Target{Path: crlPath, Material: "crl"})
			Expect(exp.SyncAll(ctx)).To(MatchError(ContainSubstring("to compare it")))

			after, err := os.Stat(crlPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(os.SameFile(before, after)).To(BeTrue(), "the unreadable file must not have been replaced")
			Expect(after.Mode().Perm()).To(Equal(fs.FileMode(0o000)))
			Expect(syncs(crlPath, "error")).To(Equal(1.0))
			Expect(syncs(crlPath, "success")).To(Equal(0.0))
		})

		It("fails a target whose path cannot be inspected at all, and writes nothing", func() {
			if os.Geteuid() == 0 {
				Skip("root searches a directory without its search bit")
			}
			locked := filepath.Join(dir, "locked")
			Expect(os.Mkdir(locked, 0o755)).To(Succeed())
			target := filepath.Join(locked, "crl.pem")
			Expect(os.WriteFile(target, []byte(ownCRL), 0o644)).To(Succeed())
			// Readable but not searchable: Lstat on anything inside fails with
			// EACCES, which is neither "absent" nor an answer.
			Expect(os.Chmod(locked, 0o600)).To(Succeed())
			DeferCleanup(os.Chmod, locked, fs.FileMode(0o755))

			exp := newExporter(fileexport.Target{Path: target, Material: "crl"})
			Expect(exp.SyncAll(ctx)).To(MatchError(ContainSubstring("checking " + target)))
			Expect(syncs(target, "error")).To(Equal(1.0))

			Expect(os.Chmod(locked, 0o755)).To(Succeed())
			Expect(readFile(target)).To(Equal(ownCRL))
		})

		It("reports a missing directory rather than creating it, and still writes the rest", func() {
			missing := filepath.Join(dir, "absent", "crl.pem")
			exp := newExporter(
				fileexport.Target{Path: missing, Material: "crl"},
				fileexport.Target{Path: certPath, Material: "cert"},
			)
			Expect(exp.SyncAll(ctx)).To(MatchError(ContainSubstring(missing)))
			Expect(filepath.Join(dir, "absent")).NotTo(BeAnExistingFile())
			Expect(readFile(certPath)).To(Equal(certChain))
		})

		It("refuses a directory at the path", func() {
			Expect(os.Mkdir(crlPath, 0o755)).To(Succeed())
			exp := newExporter(fileexport.Target{Path: crlPath, Material: "crl"})
			Expect(exp.SyncAll(ctx)).To(MatchError(ContainSubstring("is not a regular file")))
			info, err := os.Stat(crlPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.IsDir()).To(BeTrue())
		})

		It("refuses a FIFO at the path without opening it", func() {
			// Reading a FIFO with no writer blocks, so a sync that opened one
			// would never return. Replacing it would succeed -- rename(2) is
			// happy to -- which is why the refusal has to be explicit.
			Expect(syscall.Mkfifo(crlPath, 0o644)).To(Succeed())
			exp := newExporter(fileexport.Target{Path: crlPath, Material: "crl"})

			done := make(chan error, 1)
			go func() { done <- exp.SyncAll(ctx) }()
			var err error
			Eventually(done).WithTimeout(5 * time.Second).Should(Receive(&err))
			Expect(err).To(MatchError(ContainSubstring("is not a regular file")))

			info, statErr := os.Lstat(crlPath)
			Expect(statErr).NotTo(HaveOccurred())
			Expect(info.Mode()&fs.ModeNamedPipe).NotTo(BeZero(), "the FIFO must still be there")
		})
	})

	Describe("symbolic links", func() {
		It("replaces a link with a regular file and never writes through it", func() {
			elsewhere := filepath.Join(dir, "elsewhere.pem")
			Expect(os.WriteFile(elsewhere, []byte("NOT OURS"), 0o644)).To(Succeed())
			Expect(os.Symlink(elsewhere, crlPath)).To(Succeed())

			exp := newExporter(fileexport.Target{Path: crlPath, Material: "crl"})
			logs := captureLogs()
			Expect(exp.SyncAll(ctx)).To(Succeed())

			info, err := os.Lstat(crlPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().IsRegular()).To(BeTrue(), "the link itself must have been replaced")
			Expect(readFile(crlPath)).To(Equal(crlChain))
			Expect(readFile(elsewhere)).To(Equal("NOT OURS"), "the link's target must be untouched")
			// A link someone placed is being undone, so the operator is told,
			// and told where it pointed.
			Expect(logs.String()).To(And(
				ContainSubstring(`level=WARN msg="File export is replacing a symbolic link`),
				ContainSubstring("path="+crlPath),
				ContainSubstring("link_target="+elsewhere)))
		})

		It("replaces a link even when its target already holds the material", func() {
			// The export owns the path. A link that happens to be current today
			// stops being current the moment what it points at is not.
			elsewhere := filepath.Join(dir, "elsewhere.pem")
			Expect(os.WriteFile(elsewhere, []byte(crlChain), 0o644)).To(Succeed())
			Expect(os.Symlink(elsewhere, crlPath)).To(Succeed())

			exp := newExporter(fileexport.Target{Path: crlPath, Material: "crl"})
			Expect(exp.SyncAll(ctx)).To(Succeed())

			info, err := os.Lstat(crlPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().IsRegular()).To(BeTrue())
		})

		It("replaces a dangling link without creating its target", func() {
			// The shape a migration off the filesystem backend leaves behind: a
			// Puppet-compatible path still linked into a CA directory that is
			// gone.
			gone := filepath.Join(dir, "old-cadir", "ca_crl.pem")
			Expect(os.Symlink(gone, crlPath)).To(Succeed())

			exp := newExporter(fileexport.Target{Path: crlPath, Material: "crl"})
			Expect(exp.SyncAll(ctx)).To(Succeed())

			info, err := os.Lstat(crlPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().IsRegular()).To(BeTrue())
			Expect(readFile(crlPath)).To(Equal(crlChain))
			Expect(filepath.Join(dir, "old-cadir")).NotTo(BeAnExistingFile())
		})
	})

	Describe("metrics", func() {
		It("publishes the sync counters at zero before the first sync", func() {
			newExporter(fileexport.Target{Path: crlPath, Material: "crl"})

			Expect(syncs(crlPath, "success")).To(Equal(0.0))
			Expect(syncs(crlPath, "error")).To(Equal(0.0))
			_, found := gauge("last_success_timestamp_seconds", crlPath)
			Expect(found).To(BeFalse(), "a zero timestamp would claim a success in 1970")
			_, found = gauge("last_error_timestamp_seconds", crlPath)
			Expect(found).To(BeFalse())
		})

		It("counts every sync, not only the ones that wrote", func() {
			exp := newExporter(fileexport.Target{Path: crlPath, Material: "crl"})
			Expect(exp.SyncAll(ctx)).To(Succeed())
			Expect(exp.SyncAll(ctx)).To(Succeed())
			Expect(syncs(crlPath, "success")).To(Equal(2.0))
		})

		It("tolerates nil metrics", func() {
			cfg := fileexport.Config{Targets: []fileexport.Target{{Path: crlPath, Material: "crl"}}}
			Expect(cfg.Validate()).To(Succeed())
			exp := fileexport.New(cfg, src, nil)
			Expect(exp.SyncAll(ctx)).To(Succeed())
			src.crlErr = errors.New("boom")
			Expect(exp.SyncAll(ctx)).To(HaveOccurred())
		})
	})
})
