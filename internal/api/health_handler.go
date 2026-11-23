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
	"encoding/json"
	"net/http"
)

type healthResponse struct {
	Status string `json:"status"`
	// Reason says why a not_ready answer is not ready, when the cause is one
	// an operator acts on rather than initialisation still running.
	Reason string `json:"reason,omitempty"`
}

// reasonUpstreamCRLChain is the not_ready reason while readiness waits for a
// crl_chain.urls round, so a probe failure names the upstream fetch rather
// than reading like a CA that never initialised. The healthcheck subcommand
// (the image's HEALTHCHECK) prints it; a kubelet probe event carries only the
// status code, so there it is for whoever reads the endpoint by hand.
const reasonUpstreamCRLChain = "waiting_for_upstream_crl_chain"

// handleLive is the liveness probe: returns 200 as long as the server is running.
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(healthResponse{Status: "ok"})
}

// handleReady is the readiness probe: returns 200 when the CA is initialised
// and ready to serve requests, 503 otherwise.
//
// Ready is startup plus one condition: with crl_chain.urls set and no
// upstream CRL stored, readiness waits for a fetch round to store one -- see
// CA.HoldReadinessForUpstreamChain. Serving before then would hand agents
// on certificate_revocation = chain a chain they reject.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	switch {
	case !s.CA.IsReady():
		writeNotReady(w, "")
	case s.CA.UpstreamChainHeld():
		writeNotReady(w, reasonUpstreamCRLChain)
	default:
		writeOK(w)
	}
}

// handleStartup is the startup probe: returns 200 once the CA has finished
// initialising, 503 while initialisation is still in progress.
//
// Deliberately not the readiness check. A pod held unready for its upstream
// CRLs must stay running and keep fetching: a startup probe that failed with
// it would have the kubelet restart the container in a loop, and every
// restart would start the wait again.
func (s *Server) handleStartup(w http.ResponseWriter, r *http.Request) {
	if !s.CA.IsReady() {
		writeNotReady(w, "")
		return
	}
	writeOK(w)
}

func writeOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(healthResponse{Status: "ok"})
}

func writeNotReady(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	json.NewEncoder(w).Encode(healthResponse{Status: "not_ready", Reason: reason})
}
