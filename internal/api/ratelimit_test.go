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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("destructiveOpTracker", func() {
	It("returns false when under threshold", func() {
		t := newDestructiveOpTracker(3, time.Minute)
		Expect(t.Record("admin")).To(BeFalse())
		Expect(t.Record("admin")).To(BeFalse())
		Expect(t.Record("admin")).To(BeFalse())
	})

	It("returns true when threshold is exceeded", func() {
		t := newDestructiveOpTracker(2, time.Minute)
		Expect(t.Record("admin")).To(BeFalse()) // count=1
		Expect(t.Record("admin")).To(BeFalse()) // count=2
		Expect(t.Record("admin")).To(BeTrue())  // count=3 > threshold
	})

	It("tracks identities independently", func() {
		t := newDestructiveOpTracker(1, time.Minute)
		Expect(t.Record("alice")).To(BeFalse()) // alice count=1
		Expect(t.Record("bob")).To(BeFalse())   // bob count=1
		Expect(t.Record("alice")).To(BeTrue())  // alice count=2 > threshold
		Expect(t.Record("bob")).To(BeTrue())    // bob count=2 > threshold
	})

	It("resets after the window expires", func() {
		// Drive the window with an injected clock so the reset is
		// deterministic, avoiding a scheduler-sensitive real sleep.
		clock := time.Now()
		t := newDestructiveOpTracker(1, 10*time.Millisecond)
		t.now = func() time.Time { return clock }

		Expect(t.Record("admin")).To(BeFalse())
		Expect(t.Record("admin")).To(BeTrue())

		clock = clock.Add(15 * time.Millisecond) // advance past the window
		Expect(t.Record("admin")).To(BeFalse())  // window reset
	})
})
