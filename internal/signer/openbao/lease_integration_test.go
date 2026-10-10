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

//go:build openbao_integration

package openbao_test

import (
	"context"
	"errors"
	"net/http"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/openbao/openbao/api/v2"

	"github.com/voxpupuli/openvox-ca/internal/signer/openbao"
)

var _ = Describe("OpenBao token lifecycle against a live server", func() {
	It("revokes the AppRole token it logged in for when closed", func() {
		addr := os.Getenv("PUPPET_CA_TEST_OPENBAO_ADDR")
		if addr == "" {
			Skip("set PUPPET_CA_TEST_OPENBAO_ADDR (see mage test:backendsOpenBao) to run OpenBao integration tests")
		}
		tm, err := openbao.NewTokenManager(context.Background(), openbao.Config{
			Addr:                addr,
			KeyName:             envOrDefault("PUPPET_CA_TEST_OPENBAO_KEY_NAME", "test-key"),
			AuthMethod:          openbao.AuthAppRole,
			AppRoleRoleID:       os.Getenv("PUPPET_CA_TEST_OPENBAO_ROLE_ID"),
			AppRoleSecretIDFile: os.Getenv("PUPPET_CA_TEST_OPENBAO_SECRET_ID_FILE"),
		})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(tm.Close)

		// A second client holding the same token, to ask OpenBao about it
		// after the manager has let go of its own.
		cfg := api.DefaultConfig()
		cfg.Address = addr
		probe, err := api.NewClient(cfg)
		Expect(err).NotTo(HaveOccurred())
		probe.SetToken(tm.Client().Token())

		_, err = probe.Auth().Token().LookupSelf()
		Expect(err).NotTo(HaveOccurred(), "the freshly minted token should be live before Close")

		Expect(tm.Close()).To(Succeed())

		_, err = probe.Auth().Token().LookupSelf()
		var respErr *api.ResponseError
		Expect(errors.As(err, &respErr)).To(BeTrue(), "looking up a revoked token should fail with an API error")
		Expect(respErr.StatusCode).To(Equal(http.StatusForbidden))
	})
})
