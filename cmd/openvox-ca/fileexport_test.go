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
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/certstore/certconfig"
	"github.com/voxpupuli/openvox-ca/internal/fileexport"
	"github.com/voxpupuli/openvox-ca/internal/fileexport/fileexportconfig"
)

var _ = Describe("checkFileExport", func() {
	var (
		cadir string
		out   string
		cfg   *serverConfig
	)

	BeforeEach(func() {
		cadir = GinkgoT().TempDir()
		out = GinkgoT().TempDir()
		cfg = &serverConfig{CADir: cadir}
	})

	withTarget := func(path string) {
		cfg.FileExport.Targets = append(cfg.FileExport.Targets,
			fileexport.Target{Path: path, Material: fileexport.MaterialCRL})
	}

	It("accepts no block at all", func() {
		Expect(checkFileExport(cfg, cadir, "")).To(Succeed())
	})

	It("accepts a target of its own and normalises it", func() {
		withTarget(filepath.Join(out, ".", "crl.pem"))
		Expect(checkFileExport(cfg, cadir, "")).To(Succeed())
		Expect(cfg.FileExport.Targets[0].Path).To(Equal(filepath.Join(out, "crl.pem")))
		Expect(cfg.FileExport.Targets[0].Scope).To(Equal(fileexport.ScopeChain))
	})

	It("refuses an invalid block under its own name", func() {
		cfg.FileExport.Targets = []fileexport.Target{{Path: "relative.pem", Material: "crl"}}
		Expect(checkFileExport(cfg, cadir, "")).To(MatchError(And(
			HavePrefix("invalid file_export config:"), ContainSubstring("must be absolute"))))
	})

	It("refuses a target inside cadir", func() {
		withTarget(filepath.Join(cadir, "ca_crl.pem"))
		Expect(checkFileExport(cfg, cadir, "")).To(MatchError(And(
			ContainSubstring("target 0 writes"), ContainSubstring("is inside cadir"))))
	})

	It("refuses a target over the CA's own certificate file", func() {
		// The one that would do quiet damage: scope self over ca_cert_file
		// drops the intermediates from the CA's own bundle.
		cfg.CACertFile = filepath.Join(out, "ca_crt.pem")
		withTarget(cfg.CACertFile)
		Expect(checkFileExport(cfg, cadir, "")).To(MatchError(ContainSubstring("is ca_cert_file")))
	})

	It("refuses a target over the config file the server was started with", func() {
		configPath := filepath.Join(out, "config.yaml")
		withTarget(configPath)
		Expect(checkFileExport(cfg, cadir, configPath)).To(MatchError(ContainSubstring("--config")))
	})

	DescribeTable("refuses a target over a file another writer owns",
		func(field string) {
			files := &certconfig.FilesConfig{
				Cert: filepath.Join(out, "tls.crt"),
				Key:  filepath.Join(out, "tls.key"),
				CA:   filepath.Join(out, "chain.pem"),
			}
			cfg.ManagedCerts = certconfig.Config{{
				Certname: "puppetserver.example.com",
				Store:    certconfig.StoreConfig{Files: files},
			}}
			target := map[string]string{"cert": files.Cert, "key": files.Key, "ca": files.CA}[field]
			withTarget(target)
			Expect(checkFileExport(cfg, cadir, "")).To(MatchError(
				ContainSubstring("managed_certs[0] (puppetserver.example.com).store.files." + field)))
		},
		Entry("a managed certificate", "cert"),
		Entry("a managed private key, which would make the reconcile loop reissue on every pass", "key"),
		Entry("a managed chain file", "ca"),
	)

	// No producer of the reserved set hands back a relative path today, so this
	// branch is reached only through the helper. It refuses rather than
	// skipping: a relative path can never equal an absolute target, and
	// skipping would be a gap that reads as a pass.
	It("refuses to compare against a reserved path that is not absolute", func() {
		targets := []fileexport.Target{{Path: filepath.Join(out, "crl.pem"), Material: "crl"}}
		err := checkTargetsAgainst(targets, []certconfig.ReservedPath{
			{Setting: "some_setting", Path: "relative/ca_crt.pem"},
		})
		Expect(err).To(MatchError(And(
			ContainSubstring("some_setting"), ContainSubstring("not an absolute path"))))
	})

	DescribeTable("refuses a target over the CA's serving certificate store",
		func(field, setting string) {
			files := &certconfig.FilesConfig{
				Cert: filepath.Join(out, "serving.crt"),
				Key:  filepath.Join(out, "serving.key"),
				CA:   filepath.Join(out, "serving-chain.pem"),
			}
			cfg.ServingCert = &certconfig.Entry{
				Certname: "ca.example.com",
				Store:    certconfig.StoreConfig{Files: files},
			}
			target := map[string]string{"cert": files.Cert, "key": files.Key, "ca": files.CA}[field]
			withTarget(target)
			Expect(checkFileExport(cfg, cadir, "")).To(MatchError(ContainSubstring(setting)))
		},
		Entry("its certificate", "cert", servingCertPathSetting+"cert"),
		Entry("its key", "key", servingCertPathSetting+"key"),
		Entry("its chain, which caOwnedPaths deliberately leaves out", "ca", "serving_cert.store.files.ca"),
	)
})

// stubMaterial is a fileexport.MaterialSource whose CRL can be changed while
// the exporter loop is running.
type stubMaterial struct {
	mu  sync.Mutex
	crl []byte
}

func (s *stubMaterial) GetCACert(context.Context) ([]byte, error) { return []byte("CERT"), nil }
func (s *stubMaterial) GetCRL(context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.crl, nil
}

func (s *stubMaterial) set(crl string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.crl = []byte(crl)
}

// docs/file-export.md, fileexportconfig.DefaultInterval and runFileExporter
// all say a revocation reaches an exported file on the same schedule that
// crl_sync_interval_sec gives it to another replica's checks. That holds only
// while the two defaults agree, and they are constants in different packages.
var _ = Describe("the file export's default interval", func() {
	It("is crl_sync_interval_sec's default", func() {
		Expect(fileexportconfig.DefaultInterval).To(Equal(defaultCRLSyncInterval))
	})
})

var _ = Describe("runFileExporter", func() {
	It("syncs at startup, picks up a change on the next tick, and stops on cancel", func() {
		path := filepath.Join(GinkgoT().TempDir(), "crl.pem")
		cfg := fileexport.Config{Targets: []fileexport.Target{{Path: path, Material: "crl"}}}
		Expect(cfg.Validate()).To(Succeed())
		src := &stubMaterial{crl: []byte("FIRST")}
		exp := fileexport.New(cfg, src, nil)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			runFileExporter(ctx, exp, 50*time.Millisecond, 1)
		}()
		// Waits as well as cancels, so that a failed Eventually below cannot
		// leave the loop writing into a TempDir that cleanup is removing.
		DeferCleanup(func() {
			cancel()
			Eventually(done).WithTimeout(5 * time.Second).Should(BeClosed())
		})

		Eventually(func() (string, error) {
			b, err := os.ReadFile(path)
			return string(b), err
		}).WithTimeout(5 * time.Second).Should(Equal("FIRST"))

		// The change arrives with no notification at all, as a revocation on
		// another replica does. Only the timer can carry it to the file.
		src.set("SECOND")
		Eventually(func() (string, error) {
			b, err := os.ReadFile(path)
			return string(b), err
		}).WithTimeout(5 * time.Second).Should(Equal("SECOND"))

		cancel()
		Eventually(done).WithTimeout(5 * time.Second).Should(BeClosed())
	})

	It("logs a failed cycle by count, leaving each error to the line that names its target", func() {
		dir := GinkgoT().TempDir()
		cfg := fileexport.Config{Targets: []fileexport.Target{
			{Path: filepath.Join(dir, "absent", "crl.pem"), Material: "crl"},
			{Path: filepath.Join(dir, "gone", "crl.pem"), Material: "crl"},
		}}
		Expect(cfg.Validate()).To(Succeed())
		exp := fileexport.New(cfg, &stubMaterial{crl: []byte("CRL")}, nil)

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		DeferCleanup(func() { slog.SetDefault(orig) })

		syncFilesOnce(context.Background(), exp)

		var cycle []string
		for _, line := range strings.Split(buf.String(), "\n") {
			if strings.Contains(line, "File export cycle completed with errors") {
				cycle = append(cycle, line)
			}
		}
		Expect(cycle).To(HaveLen(1))
		Expect(cycle[0]).To(ContainSubstring("failed_targets=2"))
		Expect(cycle[0]).NotTo(ContainSubstring("absent"),
			"the cycle line must not repeat the per-target errors logged above it")
		Expect(strings.Count(buf.String(), `msg="File export failed for target"`)).To(Equal(2))
	})

	// startFileExport is the one place the configured interval reaches the
	// timer; the specs around this one hand runFileExporter an interval
	// directly. A one-second interval_sec has to carry a change to the file well
	// inside five seconds, which the sixty-second default cannot.
	It("runs the loop at the configured interval_sec, not the default", func() {
		path := filepath.Join(GinkgoT().TempDir(), "crl.pem")
		cfg := fileexport.Config{IntervalSec: 1, Targets: []fileexport.Target{{Path: path, Material: "crl"}}}
		Expect(cfg.Validate()).To(Succeed())
		src := &stubMaterial{crl: []byte("FIRST")}

		g := newGoroutineGroup(context.Background())
		DeferCleanup(g.Stop)
		startFileExport(g, cfg, src, nil)

		Eventually(func() (string, error) {
			b, err := os.ReadFile(path)
			return string(b), err
		}).WithTimeout(5 * time.Second).Should(Equal("FIRST"))

		src.set("SECOND")
		Eventually(func() (string, error) {
			b, err := os.ReadFile(path)
			return string(b), err
		}).WithTimeout(5*time.Second).Should(Equal("SECOND"),
			"a change must reach the file within the configured one-second interval")
	})

	// An hour's interval, so the write the spec waits for cannot be a tick's:
	// it has to be the startup sync.
	It("writes before the first tick", func() {
		path := filepath.Join(GinkgoT().TempDir(), "crl.pem")
		cfg := fileexport.Config{Targets: []fileexport.Target{{Path: path, Material: "crl"}}}
		Expect(cfg.Validate()).To(Succeed())
		exp := fileexport.New(cfg, &stubMaterial{crl: []byte("NOW")}, nil)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			runFileExporter(ctx, exp, time.Hour, 1)
		}()
		DeferCleanup(func() {
			cancel()
			Eventually(done).WithTimeout(5 * time.Second).Should(BeClosed())
		})

		Eventually(func() (string, error) {
			b, err := os.ReadFile(path)
			return string(b), err
		}).WithTimeout(5 * time.Second).Should(Equal("NOW"))
	})
})

// The refusal has to come before the --daemon fork: past it, the child's
// stderr is /dev/null and the operator has already been told the CA started.
// Driven through the whole command with a stubbed fork, as
// backendsettings_test.go does, so that a refusal moved into the serve path
// fails here rather than passing a unit spec of checkFileExport.
var _ = Describe("a server whose file_export writes into its own cadir", func() {
	var (
		forked bool
		cfg    string
		cadir  string
	)

	BeforeEach(func() {
		clearServerEnv()
		cadir = GinkgoT().TempDir()
		cfg = filepath.Join(GinkgoT().TempDir(), "config.yaml")
		GinkgoT().Setenv(configEnvVar, cfg)

		forked = false
		orig := startDaemonChild
		startDaemonChild = func(*exec.Cmd) error { forked = true; return errStubbedFork }
		DeferCleanup(func() { startDaemonChild = orig })
	})

	run := func() (string, error) {
		cmd := newRootCmd()
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs([]string{"--cadir", cadir, "--host", "127.0.0.1", "--port", "0", "--daemon"})
		err := cmd.Execute()
		return out.String(), err
	}

	It("is refused before forking", func() {
		Expect(os.WriteFile(cfg, []byte("file_export:\n  targets:\n    - path: "+
			filepath.Join(cadir, "ca_crl.pem")+"\n      material: crl\n"), 0o600)).To(Succeed())

		out, err := run()
		Expect(err).To(MatchError(ContainSubstring("is inside cadir")))
		Expect(forked).To(BeFalse(), "the refusal has to come before the fork")
		Expect(out).NotTo(ContainSubstring("started in background"))
	})

	// The twin: a target of its own reaches the fork, so the spec above fails
	// on the refusal rather than on anything else this command line gets wrong.
	It("forks when the target is outside the CA's own files", func() {
		Expect(os.WriteFile(cfg, []byte("file_export:\n  targets:\n    - path: "+
			filepath.Join(GinkgoT().TempDir(), "crl.pem")+"\n      material: crl\n"), 0o600)).To(Succeed())

		_, err := run()
		Expect(err).To(MatchError(errStubbedFork))
		Expect(forked).To(BeTrue())
	})
})

// The wiring itself. Every spec above drives a function; this drives the serve
// command, so deleting the block in main.go that starts the job -- or putting
// it on a path the single-process server does not reach -- fails here.
//
// With the metrics exporter on, because the metrics are wired on a branch of
// their own (fileexport.NewMetrics only when the exporter exists) and they are
// the only input OpenVoxCAFileExportStale has. A serve run without
// metrics_listen skips that branch, so dropping it, passing nil, or a
// registration that collides and panics would all pass a spec that only
// checked the files.
var _ = Describe("the serve command with file_export configured", func() {
	It("writes the stored CRL and CA certificate, and reports each sync on /metrics", func() {
		clearServerEnv()
		caDir := GinkgoT().TempDir()
		bootstrapCAInDir(caDir, "ca.example.com")
		outDir := GinkgoT().TempDir()
		crlPath := filepath.Join(outDir, "crl.pem")
		certPath := filepath.Join(outDir, "ca.pem")

		configPath := serveConfig(caDir, "", "127.0.0.1", freeLoopbackPort(), false)
		metricsAddr := fmt.Sprintf("127.0.0.1:%d", freeLoopbackPort())
		appendConfig(configPath, "metrics_listen: "+metricsAddr+"\n"+
			"file_export:\n  targets:\n"+
			"    - {path: "+crlPath+", material: crl}\n"+
			"    - {path: "+certPath+", material: cert}\n")

		// The stored material, read before the server takes the instance lock.
		wantCRL, err := os.ReadFile(filepath.Join(caDir, "ca_crl.pem"))
		Expect(err).NotTo(HaveOccurred())
		wantCert, err := os.ReadFile(filepath.Join(caDir, "ca_crt.pem"))
		Expect(err).NotTo(HaveOccurred())

		startServe(configPath)

		Eventually(func() ([]byte, error) { return os.ReadFile(crlPath) }).
			WithTimeout(10 * time.Second).Should(Equal(wantCRL))
		Eventually(func() ([]byte, error) { return os.ReadFile(certPath) }).
			WithTimeout(10 * time.Second).Should(Equal(wantCert))

		scrape := func() (string, error) {
			resp, err := http.Get("http://" + metricsAddr + "/metrics")
			if err != nil {
				return "", err
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			return string(body), err
		}
		for _, p := range []string{crlPath, certPath} {
			Eventually(scrape).WithTimeout(10*time.Second).Should(MatchRegexp(
				`(?m)^openvoxca_file_export_syncs_total\{path="%s",result="success"\} [1-9]`,
				regexp.QuoteMeta(p)), "the sync of %s must be counted on the CA's own registry", p)
			Eventually(scrape).WithTimeout(10 * time.Second).Should(MatchRegexp(
				`(?m)^openvoxca_file_export_last_success_timestamp_seconds\{path="%s"\} `,
				regexp.QuoteMeta(p)))
		}
	})
})
