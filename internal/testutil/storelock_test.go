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

package testutil

import (
	"testing"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// TestRecordingBackendIsNotLockEnforcementFaithful pins the deliberate
// non-forwarding of storage's unexported enforcesInstance predicate.
//
// The property was documented on recordingUnlocker and enforced by nothing.
// It became load-bearing when LockIsEnforced started keying on which lock was
// taken rather than on the unlocker's type: a maintainer "fixing" the wrapper
// to forward would make this backend read as enforced, and a spec written
// against it would then meet the unenforceable-lock refusal and be repaired by
// passing --replicas-stopped -- quietly retiring the gate it was meant to pin.
//
// A plain test rather than a Ginkgo spec: this package is a fixture library
// with no suite bootstrap, and adding one to carry a single assertion would be
// a larger change than the assertion.
func TestRecordingBackendIsNotLockEnforcementFaithful(t *testing.T) {
	b := NewRecordingBackend(t.TempDir())

	ul, err := b.AcquireInstanceLock()
	if err != nil {
		t.Fatalf("AcquireInstanceLock: %v", err)
	}
	t.Cleanup(func() { _ = ul.Unlock() })

	if storage.LockIsEnforced(ul) {
		t.Fatal("RecordingBackend's unlocker reports as enforcement-faithful. " +
			"Its godoc says it is not, and specs asserting on holdInstanceLock's " +
			"`enforced` return must not be written against it. If the forwarding " +
			"was added deliberately, update the godoc and this test together.")
	}
}
