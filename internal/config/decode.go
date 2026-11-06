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

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DecodeStrict decodes one YAML configuration document into out, refusing any
// key out does not declare.
//
// A plain yaml.Unmarshal drops an unknown key without a word, so a misspelt
// setting leaves the real one at its default: `encrypt_ca_kye: true` bootstraps
// a CA with a plaintext key, and nothing in the log says the line was skipped.
// What a key is allowed to be is whatever out's yaml tags say, so a setting
// added as a struct field is accepted with no second list to update. Maps
// (labels, annotations) still take any key, because their keys are data.
//
// program names what the keys belong to ("openvox-ca", "openvox-ca-ctl") in
// the refusal. The error does not name the file; callers wrap it with the path.
//
// An empty or comment-only document is valid and leaves out untouched. A
// second document with any content is refused rather than ignored, for the same
// reason as an unknown key: yaml.Unmarshal reads only the first, so settings
// after a stray `---` are dropped just as silently.
func DecodeStrict(data []byte, out any, program string) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return describeDecodeError(data, err, program)
	}
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if !emptyDocument(&doc) {
			return fmt.Errorf("line %d: a second YAML document starts here, and %s reads "+
				"only the first: merge it into the first document or remove the `---` "+
				"before it", doc.Line, program)
		}
	}
}

// emptyDocument reports whether a document holds nothing, as the one a
// trailing `---` produces does.
func emptyDocument(doc *yaml.Node) bool {
	switch len(doc.Content) {
	case 0:
		return true
	case 1:
		n := doc.Content[0]
		return n.Kind == yaml.ScalarNode && n.Tag == "!!null"
	default:
		return false
	}
}

// unknownFieldRe matches yaml.v3's message for a key KnownFields refused. Its
// wording is not an API, so describeDecodeError keeps any message this does not
// match exactly as yaml.v3 wrote it: a change upstream costs the rewording, never
// the refusal.
//
// (?s), because yaml.v3 embeds the key raw: without it a key holding a newline
// would miss the pattern and reach the log unquoted, which is the one case the
// quoting below exists for.
var unknownFieldRe = regexp.MustCompile(`(?s)^line (\d+): field (.+?) not found in type .+$`)

// describeDecodeError rewrites yaml.v3's unknown-field messages, which name a
// Go type ("not found in type main.serverConfig") that means nothing to an
// operator, into ones that name the key by its full path and say what to do.
// Every other message passes through unchanged.
func describeDecodeError(data []byte, err error, program string) error {
	// The decoder's own error only. A custom unmarshaller (certconfig.Duration)
	// can wrap a TypeError with a message of its own; reaching through that
	// wrapper would rebuild the message from the inner error and discard the
	// explanation, so a wrapped one is passed through as it is.
	var te *yaml.TypeError
	if !errors.As(err, &te) || error(te) != err {
		return err
	}
	var root yaml.Node
	// Only to find paths; if the document cannot be parsed again, the keys
	// are reported bare.
	_ = yaml.Unmarshal(data, &root)

	msgs := make([]string, 0, len(te.Errors))
	reported := map[*yaml.Node]bool{}
	unknown := false
	for _, msg := range te.Errors {
		m := unknownFieldRe.FindStringSubmatch(msg)
		if m == nil {
			msgs = append(msgs, msg)
			continue
		}
		unknown = true
		line, _ := strconv.Atoi(m[1])
		key := m[2]
		if path := keyPath(&root, line, key, reported); path != "" {
			key = path
		}
		// Quoted: the key is the operator's, but it is read from a file and
		// echoed into a log, so a control character in it is escaped.
		msgs = append(msgs, fmt.Sprintf("line %d: unknown key %q", line, key))
	}
	out := strings.Join(msgs, "; ")
	if unknown {
		out += fmt.Sprintf(" (%s refuses keys it does not recognise rather than ignore "+
			"them: correct the spelling, or remove the key)", program)
	}
	return errors.New(out)
}

// keyPath finds the mapping key spelt key on the given line and returns its
// dotted path from the document root, with list indices in brackets
// ("managed_certs[0].store.secret.nmae"). It returns "" when there is no such
// key, which leaves the caller with the bare name.
//
// yaml.v3 reports a key by line and spelling only, so two unknown keys spelt
// alike on one line -- in flow style, `[{fiel: a}, {fiel: b}]` -- match the
// same way. It reports them in document order, so each call takes the first
// match not already in reported, and records it there.
func keyPath(n *yaml.Node, line int, key string, reported map[*yaml.Node]bool) string {
	var walk func(n *yaml.Node, prefix string) string
	walk = func(n *yaml.Node, prefix string) string {
		switch n.Kind {
		case yaml.DocumentNode:
			for _, c := range n.Content {
				if p := walk(c, prefix); p != "" {
					return p
				}
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				path := k.Value
				if prefix != "" {
					path = prefix + "." + k.Value
				}
				if k.Line == line && k.Value == key && !reported[k] {
					reported[k] = true
					return path
				}
				if p := walk(v, path); p != "" {
					return p
				}
			}
		case yaml.SequenceNode:
			for i, c := range n.Content {
				if p := walk(c, fmt.Sprintf("%s[%d]", prefix, i)); p != "" {
					return p
				}
			}
		}
		return ""
	}
	return walk(n, "")
}
