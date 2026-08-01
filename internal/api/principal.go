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
	"context"
	"log/slog"
	"net/http"
	"strconv"
)

// clientPrincipal is who made a request: a common name, together with the trust
// domain that vouched for it.
//
// SECURITY: a common name is an identity only inside the namespace of the issuer
// that signed it, so once client_ca is configured the bare string is not one.
// ops-admin from our own CA and ops-admin from a partner's CA are different
// principals, and anything keyed on the name alone conflates them. The
// destructive-operation tracker did: two principals shared one rate-limit
// bucket, so a partner's bulk clean raised the alarm against ours, and either
// could spend the other's allowance. An audit record naming only the CN has the
// matching defect -- it cannot tell an investigator which of them acted.
// NIST 800-53: AU-3 (Content of Audit Records), AC-3 (Access Enforcement)
type clientPrincipal struct {
	// cn is the presented common name, verbatim: untrusted, possibly hostile,
	// and reaching a log record only through LogValue.
	cn string
	// domain is the trust domain that verified the certificate. Nil when
	// attribution has not run or did not succeed.
	domain *TrustDomain
}

// principalKey is the context key under which the middleware records its
// attribution. Its own unexported type, so no other package can collide with it.
type principalKey struct{}

// withPrincipal records an attributed principal on a request context.
func withPrincipal(ctx context.Context, p clientPrincipal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// clientOf returns the principal behind a request.
//
// The domain comes from the authorisation middleware, which is the only place
// that can know it: attribution *is* verifying against one domain's anchors
// alone, and its outcome is not recoverable from the request afterwards. A
// request that never passed through it -- no AuthConfig, so no mTLS at all --
// still has a name on the wire, and the principal reports that name as
// unattributed rather than implying anything vouched for it.
func clientOf(r *http.Request) clientPrincipal {
	if p, ok := r.Context().Value(principalKey{}).(clientPrincipal); ok {
		return p
	}
	return clientPrincipal{cn: clientCN(r)}
}

// where names the vouching domain, for a log record or a key.
func (p clientPrincipal) where() string {
	if p.domain == nil {
		return "unattributed"
	}
	return p.domain.Describe()
}

// Key identifies the principal for rate limiting and audit.
//
// SECURITY: the encoding must be injective, because one half of it is hostile --
// the CN arrives from an issuer the operator does not control and may contain
// whatever separator is chosen. What makes it so is that the domain token comes
// first and is self-delimiting: "this CA" and "unattributed" are fixed, and a
// client_ca name is rendered through %q, which escapes any quote it contains. No
// CN can reach past it into another domain's namespace.
//
// Quoting the name too is not load-bearing today -- given a self-delimiting
// prefix the remainder is unambiguous whatever it holds. It is here so the
// property survives a change to the token set, since the alternative is a rule
// that has to be re-derived by whoever next adds one.
func (p clientPrincipal) Key() string {
	return p.where() + "/" + strconv.Quote(p.cn)
}

// LogValue renders the principal for slog, neutralising the name on the way out.
//
// Sanitising here rather than at each call site is the point. The CN cannot
// reach a log record except through this method, so there is no per-site rule
// left to forget -- and forgetting it is the defect this branch has now shipped
// twice, once in the code written to fix the first instance.
func (p clientPrincipal) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("cn", sanitiseForLog(p.cn)),
		slog.String("domain", p.where()),
	)
}
