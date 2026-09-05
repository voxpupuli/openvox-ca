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

package api

import (
	"errors"
	"fmt"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

var _ = Describe("OCSP error classification", func() {
	// What a verifier does next is decided here, so each case is pinned by the
	// response status a verifier actually reads, not by the Go error alone.
	DescribeTable("maps an AnswerOCSP failure to an RFC 6960 response",
		func(err error, wantStatus int, wantBody []byte) {
			status, body := ocspErrorResponse(err)
			Expect(status).To(Equal(wantStatus))
			Expect(body).To(Equal(wantBody))
		},
		// A full signing bound is capacity, not breakage. tryLater invites the
		// retry that malformedRequest would forbid, and internalError would
		// report the operator's own configured limit as a fault.
		Entry("a shed signature becomes tryLater",
			ca.ErrSigningBusy, http.StatusServiceUnavailable, xocsp.TryLaterErrorResponse),
		Entry("a wrapped shed is still tryLater",
			fmt.Errorf("answering: %w", ca.ErrSigningBusy),
			http.StatusServiceUnavailable, xocsp.TryLaterErrorResponse),
		Entry("a server fault becomes internalError",
			ca.ErrInternal, http.StatusInternalServerError, xocsp.InternalErrorErrorResponse),
		Entry("a wrapped server fault is still internalError",
			fmt.Errorf("reading the CRL: %w", ca.ErrInternal),
			http.StatusInternalServerError, xocsp.InternalErrorErrorResponse),
		Entry("anything else is the caller's fault",
			errors.New("parsing OCSP request: truncated"),
			http.StatusBadRequest, xocsp.MalformedRequestErrorResponse),
	)

	// The two sentinels must not collapse into one another: a shed that also
	// matched ErrInternal would be reported as a server fault, and the ordering
	// in ocspErrorResponse would stop being load-bearing.
	It("keeps a shed distinct from an internal error", func() {
		Expect(errors.Is(ca.ErrSigningBusy, ca.ErrInternal)).To(BeFalse())
		Expect(errors.Is(ca.ErrInternal, ca.ErrSigningBusy)).To(BeFalse())
	})
})
