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

// Package boundedfile reads an operator-supplied file -- often a mount the
// process does not control -- bounded in size, in time, and in how many reads a
// wedged mount may strand: crl_chain.file, the file:/// entries in
// crl_chain.urls, and the credential, CA and client-key files an http_config
// block names.
//
// One reader for all of them, so the bounds and the lessons behind them cannot
// drift apart between copies.
package boundedfile

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
)

// MaxCRLBytes bounds a read of upstream CRLs, by whichever way they arrive:
// crl_chain.file, a file:/// entry, or an http(s) response. Every CRL that
// survives verification is appended to
// what agents fetch and to what the Kubernetes exporter writes into a Secret,
// and crl_chain.file is read while the CRL lock and the CA's own mutex are held
// -- so an oversized file is not merely a large allocation, it is a large
// allocation blocking every issuance and revocation in the fleet. A real chain
// is a handful of CRLs; 4 MiB is generous for that and still small enough that
// a truncated or wrongly-mounted file fails loudly instead of stalling.
//
// It is also the cap on the whole upstream chain a crl_chain.urls merge may
// publish (internal/ca/crlchainfetch.go), which is what lets decodeCRLChain
// read the stored chain unbounded: changing it moves that cap too.
const MaxCRLBytes = 4 << 20

// Slots is the admission ceiling for reads of one path: once Slots reads of it
// are stranded -- their caller's deadline passed while they were still
// blocked -- a new read is refused rather than started.
//
// It is a ceiling on admission, not on the stranded count itself. Reads that
// were already in flight when a mount wedged are each stranded as their own
// deadline passes, so the count can go past Slots by that many; it cannot grow
// after that, which is what bounds the leak.
//
// A read cannot be interrupted -- os.Open and io.ReadAll are ordinary blocking
// syscalls -- so on a wedged mount (a CSI driver that has hung, an NFS server
// that has gone, a FIFO nobody writes) the goroutine doing it outlives the
// caller's deadline and keeps its descriptor. Without a ceiling, every attempt
// against such a path strands one more, until the process runs out of
// descriptors for unrelated work, storage I/O included.
//
// Only reads that have outlived their deadline count. Healthy reads of one
// path can be in flight together -- the HTTP client re-reads a credentials
// file on every request, and crl_chain.urls fetches several entries at once --
// and must never be refused for it, however many callers share a file.
//
// Per path, not process-wide. crl_chain.urls may list several file:/// entries,
// read in parallel, and one wedged mount must refuse only its own entry: with a
// shared pool it would hold every slot within a few rounds and fail every other
// entry, on healthy mounts too, under an error naming none of them. Four,
// because a read that has outlived one deadline is already a mount that has
// stopped answering; the ceiling bounds a leak, it is not a concurrency budget.
const Slots = 4

var (
	mu sync.Mutex
	// stranded counts reads of each path whose caller gave up on them and
	// which have not yet returned. A slot is held until the read returns,
	// which under a wedged mount may be forever.
	stranded = map[string]int{}
	// inflight counts every read of each path that has not returned, stranded
	// or not. Nothing is refused on it; it is what a spec watches to know a
	// read has started.
	inflight = map[string]int{}
)

// adjust adds delta to path's count in m, dropping the entry at zero. mu must
// be held.
func adjust(m map[string]int, path string, delta int) {
	if m[path] += delta; m[path] <= 0 {
		delete(m, path)
	}
}

// Read reads path, giving up when ctx is done. It refuses, rather than
// truncates, a file larger than limit bytes: a half-read PEM bundle would drop
// CRLs, or certificates, with no error. It refuses, rather than queues, a read
// of a path that already has Slots reads stranded: waiting would spend the
// caller's deadline to reach the same refusal.
//
// The caller sets the deadline; nothing here imposes one.
func Read(ctx context.Context, path string, limit int64) ([]byte, error) {
	mu.Lock()
	if stranded[path] >= Slots {
		mu.Unlock()
		return nil, fmt.Errorf("%d reads of %s have outlived their deadline and not returned; "+
			"refusing to strand another", Slots, path)
	}
	adjust(inflight, path, 1)
	mu.Unlock()

	type read struct {
		data []byte
		err  error
	}
	// Under mu: whether this read has finished, and whether its caller gave
	// up on it first, which is what decides who counts it as stranded.
	var finished, abandoned bool
	// Buffered, so the goroutine can always send and exit even when nobody is
	// left to receive: on the deadline path this function has already returned.
	done := make(chan read, 1)
	go func() {
		data, err := readBlocking(path, limit)
		// Accounted before the send, so a read that has finished never holds
		// a slot while its result waits to be collected.
		mu.Lock()
		finished = true
		adjust(inflight, path, -1)
		if abandoned {
			adjust(stranded, path, -1)
		}
		mu.Unlock()
		done <- read{data, err}
	}()
	select {
	case <-ctx.Done():
		mu.Lock()
		if !finished {
			abandoned = true
			adjust(stranded, path, 1)
		}
		mu.Unlock()
		return nil, ctx.Err()
	case r := <-done:
		return r.data, r.err
	}
}

func readBlocking(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}
