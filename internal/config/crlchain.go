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

package config

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxCRLChainURLs bounds crl_chain.urls. Each entry is one ancestor's CRL, and
// a chain is one CRL per ancestor, so this matches the 64-CRL bound on
// crl_chain.file and is refused at startup rather than at the first fetch.
const MaxCRLChainURLs = 64

// MaxCRLChainRefreshIntervalSec bounds crl_chain.refresh_interval_sec at 30
// days. Nothing upstream publishes that rarely, and the bound keeps the
// seconds-to-Duration multiplication clear of overflow: a wrapped interval goes
// negative, which fires the fetch job's timer at once, so every replica would
// fetch every upstream back to back without pause.
const MaxCRLChainRefreshIntervalSec = 30 * 24 * 3600

// MaxCRLChainFetchTimeoutSec bounds crl_chain.fetch_timeout_sec. A fetch that
// takes longer than this is not going to succeed, and the bound keeps the
// seconds-to-Duration multiplication well clear of overflow.
const MaxCRLChainFetchTimeoutSec = 600

// CRLChainConfig is the crl_chain block: the upstream CRLs this CA publishes
// alongside its own, for agents doing full-chain revocation checking (Puppet's
// default certificate_revocation = chain).
type CRLChainConfig struct {
	// File is a PEM bundle of upstream CRLs. Re-read by the crl-chain-refresh
	// job, so refreshing the file is how an operator keeps ancestor CRLs
	// current — every CRL in it is signature-verified against the stored CA
	// bundle before it is served. Empty disables it. Mutually exclusive with
	// URLs.
	File string `yaml:"file"`

	// RefreshIntervalSec is how often the file is re-read, or the URLs
	// fetched, and the published CRL rewritten if its upstream blocks changed.
	// 0 = built-in default (1h); at most MaxCRLChainRefreshIntervalSec.
	// Gated on the chain feature alone: an operator publishing an upstream
	// chain is not necessarily running any other periodic job.
	RefreshIntervalSec int `yaml:"refresh_interval_sec"`

	// URLs are fetched for upstream CRLs on the refresh interval, one CRL per
	// entry: http://, https:// or file:///<absolute path>. Mutually exclusive
	// with File. Each round's results are merged into the stored chain, so a
	// revocation never waits on an upstream.
	URLs []string `yaml:"urls"`

	// FetchTimeoutSec bounds each entry's fetch. 0 = built-in default (30s).
	FetchTimeoutSec int `yaml:"fetch_timeout_sec"`

	// HTTPConfig configures the client used for http:// and https:// entries.
	HTTPConfig HTTPClientConfig `yaml:"http_config"`
}

// Validate refuses a crl_chain block the server cannot run. It is called while
// the configuration is loaded, which is before the --daemon fork, so a refusal
// reaches the operator's terminal.
func (c CRLChainConfig) Validate() error {
	var errs []error
	if c.File != "" && len(c.URLs) > 0 {
		errs = append(errs, errors.New("crl_chain.file and crl_chain.urls are mutually exclusive: "+
			"the file is authoritative on every CRL amendment and would drop every fetched "+
			"ancestor it does not list"))
	}
	if len(c.URLs) > MaxCRLChainURLs {
		errs = append(errs, fmt.Errorf("crl_chain.urls lists %d entries; at most %d are allowed, "+
			"one per ancestor", len(c.URLs), MaxCRLChainURLs))
	}
	seen := make(map[string]bool, len(c.URLs))
	plainHTTP := -1
	for i, raw := range c.URLs {
		if seen[raw] {
			errs = append(errs, fmt.Errorf("crl_chain.urls[%d] %s is listed twice", i, redactedURL(raw)))
			continue
		}
		seen[raw] = true
		if err := validateCRLChainURL(raw); err != nil {
			errs = append(errs, fmt.Errorf("crl_chain.urls[%d]: %w", i, err))
		} else if u, _ := url.Parse(raw); u.Scheme == "http" && plainHTTP < 0 {
			plainHTTP = i
		}
	}
	// One http_config serves every entry, so its credentials go to every
	// listed upstream: allowed only when none of them would carry it in clear.
	if plainHTTP >= 0 && (c.HTTPConfig.BasicAuth != nil || c.HTTPConfig.Authorization != nil) {
		errs = append(errs, fmt.Errorf("crl_chain.http_config sets credentials, which are sent to every "+
			"crl_chain.urls entry, and crl_chain.urls[%d] is plain http://, which would carry them in "+
			"clear text; fetch every entry over https:// or file:///, or drop the credentials", plainHTTP))
	}
	if c.RefreshIntervalSec < 0 || c.RefreshIntervalSec > MaxCRLChainRefreshIntervalSec {
		errs = append(errs, fmt.Errorf("crl_chain.refresh_interval_sec must be between 0 (the default) "+
			"and %d (got %d)", MaxCRLChainRefreshIntervalSec, c.RefreshIntervalSec))
	}
	if c.FetchTimeoutSec < 0 || c.FetchTimeoutSec > MaxCRLChainFetchTimeoutSec {
		errs = append(errs, fmt.Errorf("crl_chain.fetch_timeout_sec must be between 0 (the default) "+
			"and %d (got %d)", MaxCRLChainFetchTimeoutSec, c.FetchTimeoutSec))
	}
	if err := c.HTTPConfig.Validate("crl_chain.http_config"); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// validateCRLChainURL refuses an entry that is not one this feature fetches.
//
// No credentials in the URL: a CRL is public by definition, and anything inline
// would land in the configuration -- often a ConfigMap -- and in the URL label
// of the fetch metrics. http_config carries file-based credentials for an
// upstream that insists.
//
// No message quotes the entry as written: one carrying credentials is exactly
// the entry refused, and the refusal reaches the terminal, the journal or the
// pod log. They quote it without its user information, or, where it carries
// some, cannot be parsed, or holds an '@' anywhere, not at all; the caller
// names its index.
func validateCRLChainURL(raw string) error {
	// Checked first, because the entry becomes a metric label value, and the
	// Prometheus client panics on one that is not UTF-8 -- dropping every series
	// collected after it, on every scrape. YAML cannot carry one; the
	// environment can.
	if !utf8.ValidString(raw) {
		return errors.New("is not valid UTF-8")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("is not a URL: %w", unwrapURLError(raw, err))
	}
	// Any user information, for every scheme, and before anything quotes the
	// entry: a token in the username position is as secret as a password,
	// and url.Redacted masks only the password.
	if u.User != nil {
		return errors.New("carries credentials; CRLs are public, and an upstream that " +
			"needs authentication takes it from crl_chain.http_config")
	}
	shown := quotedURL(u)
	switch u.Scheme {
	case "http", "https":
		if u.Host == "" {
			return fmt.Errorf("%s has no host", shown)
		}
	case "file":
		// file:///abs/path only. A host would be meaningless here and is most
		// often the sign of a missing slash (file://etc/crl.pem names host "etc").
		if u.Host != "" {
			return fmt.Errorf("%s names a host; a file entry is file:///<absolute path>", shown)
		}
		if u.Path == "" || !path.IsAbs(u.Path) || u.Opaque != "" {
			return fmt.Errorf("%s is not an absolute path; a file entry is file:///<absolute path>", shown)
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("%s carries a query or fragment, which a file entry cannot use", shown)
		}
	default:
		return fmt.Errorf("%s must be an http://, https:// or file:/// URL", shown)
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return fmt.Errorf("%s contains whitespace", shown)
	}
	return nil
}

// redactedURL quotes raw with its user information removed, or says it cannot
// be parsed, for a message that must not echo a credential.
func redactedURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(not a URL)"
	}
	return quotedURL(u)
}

// quotedURL quotes u without its user information -- all of it, username
// included, unlike url.Redacted -- or withholds it altogether when what is
// left still holds an '@'.
//
// url.Parse finds user information only after "//". Without it --
// https:user:pw@host, https:/user:pw@host, file:user:pw@/etc/crl.pem -- the
// credential lands in Opaque or Path, User stays nil, and clearing User removes
// nothing. An '@' is rare in a CRL URL's path, and an entry that has one is
// still named by its index.
func quotedURL(u *url.URL) string {
	c := *u
	c.User = nil
	s := c.String()
	if strings.Contains(s, "@") {
		return "(withheld, as it may carry credentials)"
	}
	return strconv.Quote(s)
}

// unwrapURLError drops the *url.Error wrapper, whose message repeats the input
// -- credentials included -- and keeps only what was wrong with it.
//
// Unless raw holds an '@': the parser's own reason can quote the input too. A
// password holding '/', '?' or '#' ends the authority before its '@', so
// https://user:pw/x@host reads as host "user" with port ":pw", and the error
// names that port. Such a URL gets a reason that quotes nothing.
func unwrapURLError(raw string, err error) error {
	if strings.Contains(raw, "@") {
		return errors.New("it cannot be parsed, and holds an '@', so the parser's reason is withheld " +
			"as it may quote a credential")
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
