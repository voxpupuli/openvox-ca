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

package ca

import (
	"encoding/pem"
	"fmt"
)

// MigrateCAKey says how openvox-ca-ctl migrate writes the CA key into its
// destination (#516): what each end's configuration says about encryption and
// where each finds its passphrase.
type MigrateCAKey struct {
	// Source is the source configuration's passphrase source, used only to
	// decrypt an encrypted source key. SourceCADir is its cadir, which the
	// refusal for a missing passphrase inspects.
	Source      KeyPassphraseConfig
	SourceCADir string

	// Dest is the destination configuration's passphrase source, DestCADir
	// its cadir, and DestEncrypt its encrypt_ca_key.
	Dest        KeyPassphraseConfig
	DestCADir   string
	DestEncrypt bool
}

// Encode returns the CA key the destination stores, given the key the source
// stores, and whether it was encrypted on the way.
//
// An encrypted key is decrypted under the source's passphrase and encrypted
// again under the destination's, through the encoder bootstrap uses, whether
// or not the destination sets encrypt_ca_key: migrate never writes a decrypted
// copy of a key that was encrypted, and a key encrypted under the
// destination's own passphrase source is one the destination is known to be
// able to open. A plaintext key is encrypted when the destination sets
// encrypt_ca_key, and is otherwise copied as it is.
//
// Every refusal names the end it is about: a source key that does not decrypt,
// a destination with no passphrase source to encrypt under, or a key that
// encrypt_ca_key asks to encrypt and that does not parse.
func (m MigrateCAKey) Encode(stored []byte) (out []byte, encrypted bool, err error) {
	block, _ := pem.Decode(stored)
	if block == nil {
		if m.DestEncrypt {
			return nil, false, fmt.Errorf("the source's CA key is not a PEM block, so it cannot be encrypted for the destination")
		}
		return stored, false, nil
	}
	if isEncryptedPEM(block) {
		key, err := decryptCAKey(block, m.Source, m.SourceCADir, needSourceKeyEncrypted)
		if err != nil {
			return nil, false, fmt.Errorf("the source's CA key: %w", err)
		}
		need := needDestKeepsEncrypted
		if m.DestEncrypt {
			need = needDestEncryptConfigured
		}
		out, err := encodeCAKey(key, true, m.Dest, m.DestCADir, need)
		if err != nil {
			return nil, false, fmt.Errorf("the destination's CA key: %w", err)
		}
		return out, true, nil
	}
	if !m.DestEncrypt {
		return stored, false, nil
	}
	key, err := parsePrivateKeyDER(block.Type, block.Bytes)
	if err != nil {
		return nil, false, fmt.Errorf("parsing the source's CA key to encrypt it: %w", err)
	}
	out, err = encodeCAKey(key, true, m.Dest, m.DestCADir, needDestEncryptConfigured)
	if err != nil {
		return nil, false, fmt.Errorf("the destination's CA key: %w", err)
	}
	return out, true, nil
}
