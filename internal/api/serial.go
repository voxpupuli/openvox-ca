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

package api

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// SerialNumberFormat selects how certificate status responses encode
// serial_number. The zero value encodes it as SerialNumberAsNumber does.
type SerialNumberFormat string

const (
	// SerialNumberAsNumber encodes the serial as a bare JSON number at full
	// precision. This is what OpenVox Server sends, and the default.
	SerialNumberAsNumber SerialNumberFormat = "number"
	// SerialNumberAsHex encodes the serial as a JSON string of uppercase,
	// colon-separated hex bytes, e.g. "9F:3C:2A:…:F8": the bytes openssl
	// prints on its Serial Number line, without the sign byte DER adds when
	// the top bit is set. It changes the field's JSON type from number to
	// string, so a server using it no longer matches OpenVox Server's API.
	SerialNumberAsHex SerialNumberFormat = "hex"
)

// ParseSerialNumberFormat validates a serial_number_format setting, ignoring
// case and surrounding space as storage.ParseBackendKind does. An empty value
// selects the default.
func ParseSerialNumberFormat(s string) (SerialNumberFormat, error) {
	switch f := SerialNumberFormat(strings.ToLower(strings.TrimSpace(s))); f {
	case "":
		return SerialNumberAsNumber, nil
	case SerialNumberAsNumber, SerialNumberAsHex:
		return f, nil
	default:
		return "", fmt.Errorf("unknown serial number format %q: must be %q or %q",
			s, SerialNumberAsNumber, SerialNumberAsHex)
	}
}

// CertSerial is the serial_number of a certificate status response. It
// encodes in the format it was built with; decoding accepts the default
// number form only, since nothing in this tree reads the hex form back.
type CertSerial struct {
	big.Int
	format SerialNumberFormat
}

// newCertSerial copies n into a CertSerial that encodes as format selects.
func newCertSerial(n *big.Int, format SerialNumberFormat) *CertSerial {
	s := &CertSerial{format: format}
	s.Set(n)
	return s
}

// MarshalJSON implements json.Marshaler.
func (s *CertSerial) MarshalJSON() ([]byte, error) {
	if s.format == SerialNumberAsHex {
		return json.Marshal(colonHex(&s.Int))
	}
	return s.Int.MarshalJSON()
}

// colonHex renders n's magnitude as uppercase hex bytes joined by colons,
// padded to whole bytes and never beyond them: 0xA is "0A", 0x1234 is
// "12:34". A negative n, which no certificate this CA accepts can carry,
// keeps its sign as a leading "-" rather than losing it.
func colonHex(n *big.Int) string {
	b := n.Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02X", c)
	}
	hex := strings.Join(parts, ":")
	if n.Sign() < 0 {
		return "-" + hex
	}
	return hex
}
