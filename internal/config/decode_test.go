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

package config_test

import (
	"bytes"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.yaml.in/yaml/v3"

	"github.com/voxpupuli/openvox-ca/internal/certstore/certconfig"
	"github.com/voxpupuli/openvox-ca/internal/config"
)

var _ = Describe("DecodeStrict", func() {
	// What strictness accepts is exactly what the struct declares, so a key
	// added to ServerConfig is accepted with no list to update. Marshalling a
	// zero ServerConfig writes every key it declares, nested blocks included
	// when they are structs; decoding that back must succeed. If a future key
	// needed a second registration to be accepted, this would fail on it.
	It("accepts every key config.ServerConfig declares", func() {
		doc, err := yaml.Marshal(config.ServerConfig{})
		Expect(err).NotTo(HaveOccurred())
		// The floor: a document with no keys in it would pass vacuously.
		Expect(bytes.Count(doc, []byte("\n"))).To(BeNumerically(">", 100),
			"marshalled only:\n%s", doc)

		var out config.ServerConfig
		Expect(config.DecodeStrict(doc, &out, "openvox-ca")).To(Succeed())
	})

	It("names the program in the remedy", func() {
		var out struct {
			A bool `yaml:"a"`
		}
		err := config.DecodeStrict([]byte("b: 1\n"), &out, "openvox-ca-ctl")
		Expect(err).To(MatchError(And(
			ContainSubstring(`line 1: unknown key "b"`),
			ContainSubstring("openvox-ca-ctl refuses keys it does not recognise"))))
	})

	// The key is the operator's but is read from a file and echoed into a
	// log, so it is quoted: a control character in it is escaped rather than
	// written raw.
	DescribeTable("quotes the key it echoes",
		func(doc, quoted, raw string) {
			var out struct {
				A bool `yaml:"a"`
			}
			err := config.DecodeStrict([]byte(doc), &out, "openvox-ca")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(`unknown key ` + quoted))
			Expect(err.Error()).NotTo(ContainSubstring(raw))
		},
		Entry("an escape sequence", "\"b\\x1b[31m\": 1\n", `"b\x1b[31m"`, "\x1b"),
		// The two that would start a forged line in a log.
		Entry("a newline", "\"b\\nforged\": 1\n", `"b\nforged"`, "\n"),
		Entry("a carriage return", "\"b\\rforged\": 1\n", `"b\rforged"`, "\r"),
	)

	// certconfig.Duration wraps yaml.v3's own TypeError to say what a
	// duration has to look like. Rewriting from the inner error would keep
	// yaml.v3's words and lose the explanation.
	It("keeps a custom unmarshaller's message that wraps a decode error", func() {
		var out struct {
			D certconfig.Duration `yaml:"d"`
		}
		err := config.DecodeStrict([]byte("d: [720h]\n"), &out, "openvox-ca")
		Expect(err).To(MatchError(ContainSubstring("a duration must be a scalar")))
	})

	// The third outcome of the trailing-document loop: a later document that
	// does not parse. Accepting it would drop everything after the marker,
	// which is the silent loss this refuses.
	It("refuses a second document that does not parse", func() {
		var out struct {
			A bool `yaml:"a"`
		}
		err := config.DecodeStrict([]byte("a: true\n---\nb: [unclosed\n"), &out, "openvox-ca")
		// yaml.v3's own syntax error, returned as it is rather than replaced.
		Expect(err).To(MatchError(ContainSubstring("did not find expected")))
	})

	// yaml.v3 gathers both kinds into one error. Neither may displace the
	// other, and the remedy, which is about unknown keys, appears once.
	It("reports a type error and an unknown key from the same document together", func() {
		var out struct {
			A bool `yaml:"a"`
		}
		err := config.DecodeStrict([]byte("a: enabled\nb: 1\n"), &out, "openvox-ca")
		Expect(err).To(MatchError(And(
			ContainSubstring("cannot unmarshal !!str `enabled` into bool"),
			ContainSubstring(`line 2: unknown key "b"`))))
		Expect(strings.Count(err.Error(), "refuses keys it does not recognise")).To(Equal(1))
	})

	It("passes other decode errors through unchanged", func() {
		var out struct {
			A bool `yaml:"a"`
		}
		err := config.DecodeStrict([]byte("a: enabled\n"), &out, "openvox-ca")
		Expect(err).To(MatchError(ContainSubstring("cannot unmarshal !!str `enabled` into bool")))
		Expect(err.Error()).NotTo(ContainSubstring("refuses keys"),
			"the unknown-key remedy belongs only to unknown keys")
	})

	It("gives each of two like-named unknown keys on one flow-style line its own path", func() {
		var out struct {
			Items []struct {
				Name string `yaml:"name"`
			} `yaml:"items"`
		}
		err := config.DecodeStrict([]byte("items: [{name: a, naem: x}, {name: b, naem: y}]\n"), &out, "openvox-ca")
		Expect(err).To(MatchError(And(
			ContainSubstring(`unknown key "items[0].naem"`),
			ContainSubstring(`unknown key "items[1].naem"`))))
	})

	// The unknown key sits beside the merge key, not inside the anchor, so
	// this pins only that a merge key does not throw the path walk off.
	It("is not thrown off by a merge key", func() {
		var out struct {
			Base  map[string]string `yaml:"base"`
			Inner struct {
				A string `yaml:"a"`
			} `yaml:"inner"`
		}
		doc := "base: &b\n  a: x\ninner:\n  <<: *b\n  z: 1\n"
		err := config.DecodeStrict([]byte(doc), &out, "openvox-ca")
		Expect(err).To(MatchError(ContainSubstring(`line 5: unknown key "inner.z"`)))
	})
})
