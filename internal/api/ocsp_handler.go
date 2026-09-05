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

package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"

	xocsp "golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// handleOCSP serves RFC 6960 OCSP requests on both the POST and GET endpoints:
//
//	POST /ocsp                 DER-encoded OCSPRequest in the body
//	GET  /ocsp/{request}       base64-encoded (standard or URL-safe) DER in path
//
// Both paths are also registered under the /puppet-ca/v1 prefix via Routes().
func (s *Server) handleOCSP(w http.ResponseWriter, r *http.Request) {
	var (
		reqDER []byte
		err    error
	)

	switch r.Method {
	case http.MethodGet:
		encoded := r.PathValue("request")
		reqDER, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			// RFC 6960 §A.1: GET path uses URL-safe base64 without padding.
			// Try RawURLEncoding (no padding, URL-safe alphabet) as the conformant fallback.
			reqDER, err = base64.RawURLEncoding.DecodeString(encoded)
			if err != nil {
				http.Error(w, "invalid base64 in OCSP GET request path", http.StatusBadRequest)
				return
			}
		}

	case http.MethodPost:
		reqDER, err = io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			slog.Warn("read OCSP request body failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	answer, err := s.CA.AnswerOCSP(r.Context(), reqDER)
	if err != nil {
		status, body := ocspErrorResponse(err)
		switch status {
		case http.StatusInternalServerError:
			slog.Error("OCSP internal error", "error", err)
		case http.StatusServiceUnavailable:
			// Debug, not Warn, and the level is the point. A shed is the bound
			// working, and this fires once per refused request on an
			// unauthenticated endpoint — so at Warn an anonymous caller chooses
			// how much this CA writes to disk, turning a request flood into a
			// log flood and amplifying exactly the load the bound exists to
			// shed.
			//
			// Nothing is lost by dropping it: puppetca_ca_signing_shed_total
			// counts every one of these, and the metric is already what the
			// docs tell operators to alert on. This line only adds which caller
			// provoked it, which is a debugging question rather than a
			// monitoring one — so it belongs at the level you turn on when you
			// are asking it.
			slog.Debug("OCSP response shed: CA signing concurrency limit reached",
				"client_ip", clientIP(r))
		default:
			slog.Warn("OCSP request error", "error", err)
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(status)
		w.Write(body)
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	if r.Method == http.MethodGet {
		// The window comes from the answer rather than from ca.OCSPValidity,
		// because they are not always the same and the difference matters more
		// here than anywhere else. An `unknown` means "this replica has not read
		// that serial yet", which its index sync corrects within minutes;
		// telling a shared proxy to store that for four hours would have it
		// replayed to every client behind the proxy long after this CA would
		// answer differently. The CA decides how long its answer is good for and
		// this only transcribes it.
		if answer.MaxAge > 0 {
			// Clamp the validity window to a non-negative value bounded by
			// int32: HTTP cache directives are practically restricted to
			// ~68 years (RFC 7234 §1.2.1), and bare int(float) is both
			// platform-dependent on 32-bit targets and silently wraps for
			// negative inputs.
			secs := answer.MaxAge.Seconds()
			secs = math.Max(0, math.Min(math.MaxInt32, secs))
			w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, public", int64(secs)))
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
	}
	w.Write(answer.DER)
}

// ocspErrorResponse maps an AnswerOCSP failure to the HTTP status and the
// pre-serialised RFC 6960 response body to answer it with.
//
// Split out from the handler so the classification can be stated directly. It
// is the part worth pinning — it decides what a verifier does next — and
// exercising it through the handler would mean holding a signature open just
// to observe which constant comes back. (That the bound really engages under
// concurrent signing is a separate claim, and belongs where it can be shown:
// internal/ca/signboundrace_test.go.)
//
// The three cases say genuinely different things to a verifier:
//
//   - tryLater: the responder is at the concurrency its operator configured for
//     the deployment's signer. Nothing is broken and the request was well
//     formed; come back (RFC 6960 §2.3).
//   - internalError: a server fault. A verifier may retry, and an operator has
//     something to fix.
//   - malformedRequest: the request itself was bad, and retrying it unchanged
//     will not help. Never reach for this on a server-side failure — it tells a
//     verifier not to retry, and records an outage as a client error.
func ocspErrorResponse(err error) (int, []byte) {
	switch {
	case errors.Is(err, ca.ErrSigningBusy):
		return http.StatusServiceUnavailable, xocsp.TryLaterErrorResponse
	case errors.Is(err, ca.ErrInternal):
		return http.StatusInternalServerError, xocsp.InternalErrorErrorResponse
	default:
		return http.StatusBadRequest, xocsp.MalformedRequestErrorResponse
	}
}
