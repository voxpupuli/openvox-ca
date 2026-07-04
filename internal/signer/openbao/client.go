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

package openbao

import (
	"fmt"

	"github.com/openbao/openbao/api/v2"
)

// newClient builds an OpenBao API client from cfg. TLS is configured via the
// SDK's own ConfigureTLS (same file-path shape as internal/storage/spec.go's
// loadBackendTLS); all three of TLSCAFile/TLSCertFile/TLSKeyFile may be empty
// to use the platform default trust store with no client certificate.
func newClient(cfg Config) (*api.Client, error) {
	openBaoCfg := api.DefaultConfig()
	if openBaoCfg.Error != nil {
		return nil, fmt.Errorf("building default OpenBao client config: %w", openBaoCfg.Error)
	}
	openBaoCfg.Address = cfg.Addr
	openBaoCfg.Timeout = cfg.loginTimeout()

	if cfg.TLSCAFile != "" || cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		tlsCfg := &api.TLSConfig{
			CACert:     cfg.TLSCAFile,
			ClientCert: cfg.TLSCertFile,
			ClientKey:  cfg.TLSKeyFile,
		}
		if err := openBaoCfg.ConfigureTLS(tlsCfg); err != nil {
			return nil, fmt.Errorf("configuring OpenBao client TLS: %w", err)
		}
	}

	client, err := api.NewClient(openBaoCfg)
	if err != nil {
		return nil, fmt.Errorf("creating OpenBao client: %w", err)
	}
	return client, nil
}
