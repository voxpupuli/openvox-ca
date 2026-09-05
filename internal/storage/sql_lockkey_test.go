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
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"hash/fnv"
	"os"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// lockNameSamples returns lock names that are not reserved singletons, chosen
// to probe the partition rather than to be representative: ordinary subject
// locks, names that shade into the reserved ones, names that imitate the
// derived encodings, and the degenerate empty and oversized cases.
func lockNameSamples() []string {
	names := []string{
		"subject:node1.example.com",
		"subject:crl",
		"subject:bootstrap",
		"subject:",
		"",
		"crl ",
		" crl",
		"crl\x00",
		"Crl",
		"CRL",
		"bootstrap2",
		"crlx",
		"openvox-ca:0:crl",
		"openvox-ca:1:crl",
		"subject:" + strings.Repeat("a", 512),
		lockKeyDomain + "crl",
	}
	// A broad sweep of ordinary subject locks, so the partition is asserted
	// over a population and not just over hand-picked edge cases.
	for i := range lockNameSampleSweep {
		names = append(names, fmt.Sprintf("subject:node%06d.example.com", i))
	}
	return names
}

// lockNameSampleSweep is the size of that sweep. Named so the contract spec
// below can assert it: two specs do all their work inside a range over
// lockNameSamples, and would pass with every assertion unexecuted if this
// helper were ever trimmed or short-circuited.
const lockNameSampleSweep = 100000

var _ = Describe("SQLLockNameSamplesContract", func() {
	It("keeps the shared sample set non-empty and free of reserved names", func() {
		samples := lockNameSamples()
		// The bound is a literal on purpose. Asserting against
		// lockNameSampleSweep would compare the helper against the very
		// constant a regression would have changed, so the guard could never
		// fail — which is precisely the failure mode it exists to catch.
		Expect(len(samples)).To(BeNumerically(">=", 100000),
			"the shared sample set shrank; specs that range over it may now assert nothing")
		for _, name := range samples {
			Expect(reservedLockOrdinals).NotTo(HaveKey(name),
				"%q is a reserved name and must not be in the derived-half sample set", name)
		}
	})
})

// A Pollard's rho witness pair against the pre-#203 advisory-lock derivation
// (FNV-1a/64 over the whole lock name), found in about three minutes on a
// laptop — which is what made "distinct names can alias" a fact rather than a
// worry. Both pass ValidateSubject's ^[a-z0-9_.][a-z0-9._-]*$, so both were
// reachable as a CSR subject, and both hashed to key 7567271680115793544.
//
// Used twice: SQLAdvisoryLockKeyDigestStrength below pins the property at the
// derivation, and the AcquireLockAliasingSubjects specs in the postgres and
// mysql integration files pin it against a real server, where before the fix
// one of the pair genuinely excluded the other.
const (
	aliasingSubjectA = "subject:node500f599943c82351.example.com"
	aliasingSubjectB = "subject:node9dd6db26bbd40960.example.com"
)

var _ = Describe("SQLReservedLockKeys", func() {
	It("reserves every singleton lock name that reaches a SQL backend, on stable ordinals", func() {
		// These ordinals are protocol: every replica must derive the same key
		// or two replicas will not exclude one another. Renumbering one, or
		// reusing a retired one, silently breaks mutual exclusion across a
		// mixed-version cluster. Append only.
		//
		// Adding a CA-layer singleton lock name (internal/ca/init.go) means
		// adding it here too — rule 7 of docs/development/locking.md. The set
		// is "singletons that can reach a SQL backend", which is why
		// sql-schema-migrate (this package's own) is present and
		// etcdDecomposeLockName (which only EtcdBackend takes) is not.
		Expect(reservedLockOrdinals).To(Equal(map[string]int64{
			"bootstrap":          1,
			"crl":                2,
			"sql-schema-migrate": 3,
			"hmac-key":           4,
		}), "reserved advisory-lock ordinals are protocol; see docs/development/locking.md rule 11")

		// migrateLockName is in the table only by string coincidence: the map
		// holds the literal "bootstrap" and nothing ties the two together.
		// Renaming the constant would silently drop MigrateService's lock into
		// the derived half *and* stop it excluding the CA bootstrap lock, which
		// migrate.go documents as its whole purpose. The existing specs in
		// migrate_test.go compare the acquired name against the constant
		// itself, so they survive any rename.
		//
		// That every such constant is registered *at all* is
		// SQLLockNameConstantsAreRegistered below, which enumerates them from
		// the package source rather than naming them here. This assertion is
		// about which *value* this particular one must hold.
		//
		// HaveKey alone would be satisfied by migrateLockName being any of the
		// reserved names, and all but one of those would be wrong: the
		// property that matters is that it equals the CA bootstrap lock, not
		// that it is reserved at all. Converging it onto lockNameSQLMigrate —
		// same package, similar name — would keep HaveKey green while silently
		// removing the migration/CA-bootstrap exclusion. The literal is the
		// only way to pin it, since internal/storage cannot import internal/ca
		// to compare against lockNameBootstrap.
		Expect(migrateLockName).To(Equal("bootstrap"),
			"MigrateService must take the same lock name as the CA bootstrap lock (internal/ca's lockNameBootstrap)")

		for name, ordinal := range reservedLockOrdinals {
			// advisoryLockKey composes the key as reservedLockKeyBase|ordinal,
			// which is only a disjoint composition while the ordinal stays
			// inside the low 32 bits the base leaves free. An ordinal at or
			// above 1<<32 would overlap the namespace itself and could collide
			// with another reserved key rather than extending the table.
			Expect(ordinal).To(BeNumerically(">", 0),
				"ordinal for %q must be positive; 0 is the absent-from-table sentinel", name)
			Expect(ordinal).To(BeNumerically("<", int64(1)<<32),
				"ordinal for %q overflows the low 32 bits reservedLockKeyBase leaves free", name)

			key := advisoryLockKey(name)
			// The partition depends on the reserved half never setting bit 63,
			// which is what advisoryLockKey uses to tag the derived half.
			Expect(key).To(BeNumerically(">=", 0),
				"reserved key for %q must leave bit 63 clear", name)
			Expect(key).To(Equal(reservedLockKeyBase|ordinal),
				"reserved key for %q must be the namespaced base plus its ordinal", name)
			// Namespaced, not a bare ordinal. pg_advisory_lock keys are shared
			// with every other client of the database, and 1/2/3 are exactly
			// what a co-tenant would pick; a bare ordinal would trade #203's
			// aliasing for a collision with someone else's singleton job.
			Expect(key).To(BeNumerically(">", int64(1)<<32),
				"reserved key for %q is a bare ordinal, unnamespaced against co-tenants of the database", name)
		}
	})
})

// Golden vectors for the lock-key derivation, computed from the code they pin.
// They exist so that a change to the encoding — the digest slice, the byte
// order, lockKeyDomain, the reserved namespace — cannot pass unnoticed, because
// every other assertion in this file is structural and survives all four.
//
// What they guard is drift, not initial correctness: they were captured by
// running the implementation, so a bug present at capture time would have been
// frozen in rather than caught. The properties that actually matter are proved
// independently — SQLReservedLockKeys and SQLAdvisoryLockKeyPartition establish
// the disjoint halves without reference to any pinned value, and
// SQLAdvisoryLockKeyDigestStrength re-derives the old FNV-1a key with a second
// implementation rather than hard-coding it.
const (
	goldenDerivedKey       = int64(-565704137139314636)
	goldenDerivedMySQLName = "openvox-ca:1:78263715a1d7a034be49ef6e1cfdc5d8"
	goldenCRLKey           = int64(8031716253724835842)
)

var _ = Describe("SQLLockKeyGoldenVectors", func() {
	It("pins the derived encoding that every replica must reproduce identically", func() {
		// The derived encoding is protocol just as the reserved ordinals are:
		// replicas exclude one another only by deriving the same key, so a
		// change here is a cluster-wide breaking change needing a full restart,
		// not a rolling one (rule 11 of docs/development/locking.md).
		//
		// The structural assertions elsewhere in this file — bit 63 set, the
		// openvox-ca:1: tag, the 32-hex width — all survive a change of
		// lockKeyDomain, a swap to little-endian, or taking a different slice
		// of the digest, each of which silently changes every subject-lock key.
		// These vectors are what actually pin it. Recompute them deliberately
		// if you are changing the derivation on purpose; do not paste over them
		// to make a red suite green.
		Expect(advisoryLockKey("subject:node1.example.com")).To(Equal(goldenDerivedKey),
			"derived advisory-lock key encoding changed; this breaks mutual exclusion mid-rollout")
		Expect(mysqlLockName("subject:node1.example.com")).To(Equal(goldenDerivedMySQLName),
			"derived GET_LOCK name encoding changed; this breaks mutual exclusion mid-rollout")
		Expect(advisoryLockKey("crl")).To(Equal(goldenCRLKey),
			"reserved advisory-lock key for crl changed")
		Expect(mysqlLockName("crl")).To(Equal("openvox-ca:0:crl"),
			"reserved GET_LOCK name for crl changed")
	})
})

var _ = Describe("SQLAdvisoryLockKeyPartition", func() {
	It("puts every non-reserved lock key in a half no reserved key can occupy", func() {
		// The property under test, stated exactly: a name that is not a
		// registered singleton is hashed, and every hashed key has bit 63 set,
		// while every reserved key has it clear. The two halves are therefore
		// disjoint by construction, so no subject name — crafted or otherwise
		// — can reach the "crl" or "bootstrap" key. This is what makes #203
		// impossible rather than improbable: ValidateSubject is not
		// load-bearing for it.
		crlKey := advisoryLockKey("crl")
		bootstrapKey := advisoryLockKey("bootstrap")

		for _, name := range lockNameSamples() {
			key := advisoryLockKey(name)
			Expect(key).To(BeNumerically("<", 0),
				"derived key for %q must set bit 63, marking it outside the reserved half", name)
			Expect(key).NotTo(Equal(crlKey), "derived key for %q aliased the crl lock", name)
			Expect(key).NotTo(Equal(bootstrapKey), "derived key for %q aliased the bootstrap lock", name)
		}
	})
})

var _ = Describe("SQLAdvisoryLockKeyDigestStrength", func() {
	It("separates the two subject names that shared one FNV-1a advisory-lock key", func() {
		// Re-derive the old key here rather than hard-coding it, so the spec
		// proves the pair really is a collision witness instead of asserting
		// it. If this stops holding, the witness is wrong and every assertion
		// after it is vacuous.
		Expect(aliasingSubjectA).NotTo(Equal(aliasingSubjectB))
		Expect(fnv64a(aliasingSubjectA)).To(Equal(fnv64a(aliasingSubjectB)),
			"witness pair no longer collides under FNV-1a; the regression it guards is unproven")

		Expect(advisoryLockKey(aliasingSubjectA)).NotTo(Equal(advisoryLockKey(aliasingSubjectB)),
			"advisory-lock key still aliases the known FNV-1a collision pair")
		Expect(mysqlLockName(aliasingSubjectA)).NotTo(Equal(mysqlLockName(aliasingSubjectB)),
			"GET_LOCK name still aliases the known FNV-1a collision pair")
	})
})

// fnv64a reproduces the pre-#203 advisory-lock digest, used only to prove the
// witness pair above is genuine.
func fnv64a(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return int64(h.Sum64())
}

var _ = Describe("SQLMySQLLockName", func() {
	It("tags reserved and derived GET_LOCK names apart and keeps both inside the limit", func() {
		for name := range reservedLockOrdinals {
			lockName := mysqlLockName(name)
			Expect(lockName).To(Equal(mysqlLockPrefix+"0:"+name),
				"reserved GET_LOCK name for %q", name)
			Expect(len(lockName)).To(BeNumerically("<=", mysqlLockNameLimit),
				"reserved GET_LOCK name %q exceeds MySQL's limit", lockName)
		}

		reservedNames := map[string]bool{}
		for name := range reservedLockOrdinals {
			reservedNames[mysqlLockName(name)] = true
		}

		derivedPrefix := mysqlLockPrefix + "1:"
		seen := map[string]string{}
		for _, name := range lockNameSamples() {
			lockName := mysqlLockName(name)
			Expect(lockName).To(HavePrefix(derivedPrefix),
				"derived GET_LOCK name for %q must carry the derived class tag", name)
			// Fixed width: the 128-bit digest as hex, so length is a property
			// of the form and not of the name.
			Expect(len(lockName)).To(Equal(len(derivedPrefix)+32),
				"derived GET_LOCK name %q is not the fixed derived width", lockName)
			Expect(len(lockName)).To(BeNumerically("<=", mysqlLockNameLimit),
				"derived GET_LOCK name %q exceeds MySQL's limit", lockName)
			Expect(reservedNames).NotTo(HaveKey(lockName),
				"derived GET_LOCK name for %q collided with a reserved one", name)

			// A cheap sanity net, not the entropy check: a 100k sweep cannot
			// detect a halving of the digest's entropy (the birthday bound is
			// ~2^32 even at 64 effective bits), and any mutation crude enough
			// to collide here changes the width and dies on the assertion
			// above. SQLLockKeyGoldenVectors is what pins the encoding.
			if other, ok := seen[lockName]; ok {
				Expect(other).To(Equal(name),
					"GET_LOCK names for %q and %q collided", other, name)
			}
			seen[lockName] = name
		}
	})
})

// lockNameConstantExemptions lists package-storage lock-name constants that are
// deliberately NOT in reservedLockOrdinals, each with the reason. An entry here
// is a claim that the name cannot reach a SQL backend; if that stops being
// true, move it into reservedLockOrdinals rather than leaving it here.
var lockNameConstantExemptions = map[string]string{
	"etcdDecomposeLockName": "is taken only by a method on the concrete *EtcdBackend, never routed through StorageService, so it cannot reach a SQL backend",
	"instanceLockName":      "is taken only through fileLocks.acquireInstance, never through WithLock or any Locker; SQLBackend routes it to the flock sidecar beside the database file, and the backends that do have SQL advisory locks are exactly the ones AcquireInstanceLock exempts",
}

var _ = Describe("SQLLockNameConstantsAreRegistered", func() {
	It("finds every lock-name constant in the package source and requires each to be reserved or exempt", func() {
		// Why this parses the source rather than listing constants: the first
		// version of this check asserted HaveKey for the two constants that
		// existed when it was written, under a comment claiming *every*
		// singleton was registered. That claim was then falsified on a merged
		// tree rather than on this one: #202's branch adds a third such
		// constant to this package (`lockNameHMACKey`), the integration build
		// merged the two branches, and the check stayed green having never
		// looked at it — an enumeration reading as a universal. Nothing in this
		// branch alone would have shown it. Deriving the list from the source
		// makes the claim in the comment the claim in the code, so the fifth
		// singleton is caught rather than remembered.
		//
		// Scope, stated rather than implied. This covers constants declared in
		// package storage only: the CA-layer names (internal/ca's
		// lockNameBootstrap and lockNameCRL) are invisible here because
		// internal/storage must not import internal/ca, and they remain covered
		// by rule 7 of docs/development/locking.md alone. It also keys on the
		// identifier containing "lockname", so a lock-name constant named
		// something else entirely would still be missed.
		// Every .go file in the directory, parsed individually rather than
		// through a build-tag-aware loader. That is deliberate: a lock name
		// declared in a platform-guarded file (filelock_unix.go,
		// filelock_other.go) must be seen on every platform, and a loader that
		// honoured build tags would hide it on the others — a safety check that
		// only looks at the current GOOS is not a safety check.
		entries, err := os.ReadDir(".")
		Expect(err).NotTo(HaveOccurred(), "reading package directory")

		fset := token.NewFileSet()
		var files []*ast.File
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, perr := parser.ParseFile(fset, name, nil, 0)
			Expect(perr).NotTo(HaveOccurred(), "parsing %s", name)
			files = append(files, file)
		}
		Expect(len(files)).To(BeNumerically(">", 0), "found no non-test Go files to scan")

		found := map[string]string{} // constant identifier -> its string value
		for _, file := range files {
			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.CONST {
					continue
				}
				for _, spec := range gen.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, ident := range vs.Names {
						if i >= len(vs.Values) || !strings.Contains(strings.ToLower(ident.Name), "lockname") {
							continue
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						value, uerr := strconv.Unquote(lit.Value)
						Expect(uerr).NotTo(HaveOccurred(), "unquoting %s", ident.Name)
						found[ident.Name] = value
					}
				}
			}
		}

		// Positive control. If the walk finds nothing — a wrong directory, a
		// broken identifier filter, a parse that silently skipped files — every
		// assertion below is vacuous and the spec would pass having checked no
		// constant at all. These two exist today and must always be found.
		Expect(found).To(HaveKey("lockNameSQLMigrate"),
			"source walk found no lockNameSQLMigrate; the parse or the identifier filter is wrong, not the code")
		Expect(found).To(HaveKey("migrateLockName"),
			"source walk found no migrateLockName; the parse or the identifier filter is wrong, not the code")
		// The exemption branch needs its own control, or a walk that stopped
		// seeing etcd_inventory.go would exercise zero exemption checks and
		// still report success — the same vacuity the two lines above guard
		// for the reserved branch.
		Expect(found).To(HaveKey("etcdDecomposeLockName"),
			"source walk found no etcdDecomposeLockName; the exemption branch below would then never execute")

		for ident, value := range found {
			if reason, exempt := lockNameConstantExemptions[ident]; exempt {
				Expect(reservedLockOrdinals).NotTo(HaveKey(value),
					"%s (%q) is exempt because it %s, but it is also reserved — pick one", ident, value, reason)
				continue
			}
			Expect(reservedLockOrdinals).To(HaveKey(value),
				"%s = %q is a lock name in package storage that is neither reserved in reservedLockOrdinals "+
					"nor listed in lockNameConstantExemptions. If it can reach a SQL backend it needs the next "+
					"free ordinal (see docs/development/locking.md rule 11); if it cannot, add it to the "+
					"exemptions with the reason.", ident, value)
		}
	})
})
