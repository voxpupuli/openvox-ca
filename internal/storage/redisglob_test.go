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

package storage

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// scanSpy is a go-redis hook recording what every SCAN sent as its MATCH
// pattern and which keys the server returned for it. What List finally
// returns cannot show an over-broad pattern: its loop discards a foreign key
// after the fact. The keys SCAN handed back are where the cost shows.
type scanSpy struct {
	mu       sync.Mutex
	matches  []string
	returned []string
}

func (s *scanSpy) DialHook(next redis.DialHook) redis.DialHook { return next }

func (s *scanSpy) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (s *scanSpy) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		err := next(ctx, cmd)
		sc, ok := cmd.(*redis.ScanCmd)
		if !ok {
			return err
		}
		args := cmd.Args()
		s.mu.Lock()
		defer s.mu.Unlock()
		for i := 0; i+1 < len(args); i++ {
			if a, ok := args[i].(string); ok && strings.EqualFold(a, "match") {
				s.matches = append(s.matches, args[i+1].(string))
			}
		}
		keys, _ := sc.Val()
		s.returned = append(s.returned, keys...)
		return err
	}
}

func (s *scanSpy) snapshot() (matches, returned []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.matches...), append([]string(nil), s.returned...)
}

// globPrefix carries every character Redis's glob matcher treats specially,
// and globDecoy is a different prefix that the unescaped form of globPrefix
// matches: "*" takes "XX", "?" takes "Y", "[de]" takes "d" and "\g" takes "g".
// A List under globPrefix that SCANs with the raw prefix therefore walks the
// decoy's keys too.
const (
	globPrefix = `a*b?c[de]f\g`
	globDecoy  = "aXXbYcdfg"
)

// expectListScansOnlyItsOwnPrefix seeds a CSR under globPrefix and another
// under globDecoy on cli, lists CSRs through a backend on globPrefix, and
// asserts both the result and that SCAN never returned the decoy's key.
// base namespaces both prefixes, so a shared server can run it, and must hold
// no glob character itself.
func expectListScansOnlyItsOwnPrefix(cli *redis.Client, base string) {
	ctx := context.Background()
	spy := &scanSpy{}
	cli.AddHook(spy)

	own := NewRedisBackendFromClient(cli, base+globPrefix, 5*time.Second, 5*time.Second)
	decoy := NewRedisBackendFromClient(cli, base+globDecoy, 5*time.Second, 5*time.Second)
	Expect(own.Put(ctx, CSRKey("mine"), []byte("csr"), BlobPublic)).To(Succeed())
	Expect(decoy.Put(ctx, CSRKey("theirs"), []byte("csr"), BlobPublic)).To(Succeed())
	DeferCleanup(func() {
		_ = own.Delete(context.Background(), CSRKey("mine"))
		_ = decoy.Delete(context.Background(), CSRKey("theirs"))
	})

	Expect(own.List(ctx, csrPrefix)).To(ConsistOf(CSRKey("mine")))

	matches, returned := spy.snapshot()
	Expect(matches).NotTo(BeEmpty(), "List must have issued a SCAN with a MATCH pattern")
	for _, m := range matches {
		Expect(m).To(Equal(base + `a\*b\?c\[de\]f\\g:requests:*`))
	}
	Expect(returned).To(ContainElement(base+globPrefix+":requests:mine"),
		"non-vacuity: SCAN must have returned this backend's own key")
	Expect(returned).NotTo(ContainElement(base+globDecoy+":requests:theirs"),
		"SCAN walked another prefix's key: the MATCH pattern was not escaped")
}

var _ = Describe("redisGlobEscape", func() {
	DescribeTable("escapes each glob metacharacter and nothing else",
		func(in, want string) {
			Expect(redisGlobEscape(in)).To(Equal(want))
		},
		Entry("a plain prefix", "puppet-ca:requests:", "puppet-ca:requests:"),
		Entry("a star", "a*b", `a\*b`),
		Entry("a question mark", "a?b", `a\?b`),
		Entry("a character class", "a[bc]d", `a\[bc\]d`),
		Entry("a backslash", `a\b`, `a\\b`),
		Entry("a caret and a dash, special only inside a class", "a^b-c", "a^b-c"),
	)
})

var _ = Describe("RedisBackend.List with glob characters in the key prefix", func() {
	It("scans only its own prefix's keys", func() {
		_, cli, stop := newMiniredis()
		DeferCleanup(stop)
		expectListScansOnlyItsOwnPrefix(cli, "")
	})
})
