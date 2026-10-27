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

// Command chartconfig strict-decodes the config.yaml in rendered Helm
// manifests against the server's schema, with the decoder the server itself
// uses. mage chart:validate runs it over every fixture it renders:
//
//	go run ./test/chartconfig .test-output/chart/*.yaml
//
// The chart writes `config` verbatim into that file, so a value a fixture --
// or an operator copying one -- passes there reaches the server unexamined by
// anything else: helm lint and kubeconform judge the manifest, not the
// application config inside a ConfigMap. This catches a key the server does
// not declare and a value it cannot decode into the field's type. It does not
// catch what the server refuses after decoding, such as a negative
// leaf_backdate_sec or a managed_certs entry that fails validation; chart:test
// holds reject cases for those that the chart can render.
//
// It is a program of its own rather than code in the magefile so that the
// magefile does not import internal/config, and with it every storage backend:
// only this target pays to compile them.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/voxpupuli/openvox-ca/internal/config"
)

func main() {
	n, err := checkManifests(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Printf("Strict-decoded %d rendered config.yaml file(s) against the server's schema\n", n)
}

// checkManifests checks every manifest file named and returns how many
// config.yaml documents it decoded. It fails when none of the manifests
// carried one: one fixture may render no ConfigMap of its own
// (existingConfigMap), but if none did, the extraction is what is wrong.
func checkManifests(paths []string) (int, error) {
	total := 0
	for _, path := range paths {
		data, err := os.ReadFile(path) //nolint:gosec // G703: the paths are the manifests chart:validate just rendered, passed as this program's arguments
		if err != nil {
			return total, err
		}
		n, err := checkManifest(string(data))
		if err != nil {
			return total, fmt.Errorf("%s renders a config.yaml openvox-ca would refuse to start "+
				"with: %w", path, err)
		}
		total += n
	}
	if total == 0 {
		return 0, fmt.Errorf("no ConfigMap carrying config.yaml in %s, so no rendered config "+
			"was checked against the server's schema", strings.Join(paths, ", "))
	}
	return total, nil
}

// checkManifest strict-decodes the config.yaml of every ConfigMap in one
// rendered manifest stream and returns how many it checked. A ConfigMap is
// matched by carrying the key rather than by name, so a fixture that renames
// the release cannot slip past.
func checkManifest(manifest string) (int, error) {
	dec := yaml.NewDecoder(strings.NewReader(manifest))
	checked := 0
	for {
		var doc struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
			Data map[string]string `yaml:"data"`
		}
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return checked, nil
		}
		if err != nil {
			return checked, fmt.Errorf("reading the rendered manifest: %w", err)
		}
		cfg, ok := doc.Data["config.yaml"]
		if doc.Kind != "ConfigMap" || !ok {
			continue
		}
		var out config.ServerConfig
		if err := config.DecodeStrict([]byte(cfg), &out, "openvox-ca"); err != nil {
			return checked, fmt.Errorf("ConfigMap %q: %w", doc.Metadata.Name, err)
		}
		checked++
	}
}
