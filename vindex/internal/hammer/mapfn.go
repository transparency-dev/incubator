// Copyright 2026 The Transparency Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hammer

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// MapFn extracts deduplicated canonical keys from a raw Input Log entry in pure Go.
type MapFn func(leaf []byte) ([]string, error)

// MapFnForFormat returns the pure-Go reference MapFn for the given synthetic LeafFormat.
func MapFnForFormat(format LeafFormat) MapFn {
	switch format {
	case FormatSumDB:
		return MapSumDBLeaf
	case FormatCT:
		return MapCTLeaf
	default:
		return MapRawLeaf
	}
}

func appendValidatedCanonicalKey(dst []string, key string) ([]string, error) {
	if err := wire.ValidateCanonicalKey([]byte(key)); err != nil {
		return nil, fmt.Errorf("invalid canonical key %q: %w", key, err)
	}
	return append(dst, key), nil
}

func finalizeCanonicalKeys(keys []string) []string {
	slices.Sort(keys)
	return slices.Compact(keys)
}

// MapRawLeaf extracts the first ASCII whitespace-delimited token from each non-empty line in leaf.
func MapRawLeaf(leaf []byte) ([]string, error) {
	var keys []string
	for line := range bytes.SplitSeq(leaf, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var err error
		keys, err = appendValidatedCanonicalKey(keys, string(fields[0]))
		if err != nil {
			return nil, err
		}
	}
	return finalizeCanonicalKeys(keys), nil
}

// MapSumDBLeaf parses a Go SumDB entry in pure Go, filtering pseudo-versions, escaping module paths,
// and deduplicating keys per entry (e.g. matching <ver> and <ver>/go.mod lines).
func MapSumDBLeaf(leaf []byte) ([]string, error) {
	var keys []string
	for line := range strings.SplitSeq(string(leaf), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rawMod, rest, ok := strings.Cut(line, " ")
		if !ok || rawMod == "" {
			continue
		}
		rawVer, hashField, ok := strings.Cut(rest, " ")
		if !ok || rawVer == "" || strings.TrimSpace(hashField) == "" {
			continue
		}
		ver := strings.TrimSuffix(rawVer, "/go.mod")
		if !semver.IsValid(ver) || module.IsPseudoVersion(ver) {
			continue
		}
		escaped, err := module.EscapePath(rawMod)
		if err != nil || escaped == "" || len(escaped) > 1024 {
			continue
		}
		keys, err = appendValidatedCanonicalKey(keys, escaped)
		if err != nil {
			return nil, err
		}
	}
	return finalizeCanonicalKeys(keys), nil
}

// MapCTLeaf parses an X.509 CT entry (RFC 6962 MerkleTreeLeaf, Static-CT TileLeaf, or raw DER)
// using the Go standard library crypto/x509 parser and converts Subject CN and SAN dNSNames
// into reversed-DNS canonical keys.
func MapCTLeaf(leaf []byte) ([]string, error) {
	certDER, err := extractX509CertDER(leaf)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseCertificate failed: %w", err)
	}

	var keys []string
	addCandidate := func(domain string) error {
		canon, cErr := client.DomainToCanonicalKey(domain)
		if cErr != nil {
			return nil
		}
		var kErr error
		keys, kErr = appendValidatedCanonicalKey(keys, canon)
		return kErr
	}

	if cert.Subject.CommonName != "" {
		if err := addCandidate(cert.Subject.CommonName); err != nil {
			return nil, err
		}
	}
	for _, dns := range cert.DNSNames {
		if err := addCandidate(dns); err != nil {
			return nil, err
		}
	}
	return finalizeCanonicalKeys(keys), nil
}

func extractX509CertDER(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty CT leaf")
	}
	// 1. RFC 6962 MerkleTreeLeaf: version(0) || leaf_type(0) || timestamp(8) || entry_type(0=x509) || cert_len(3) || certDER || ext_len(2)
	if len(data) >= 17 && data[0] == 0 && data[1] == 0 && binary.BigEndian.Uint16(data[10:12]) == 0 {
		certLen := int(data[12])<<16 | int(data[13])<<8 | int(data[14])
		if certLen > 0 && len(data) >= 17+certLen {
			extLen := int(binary.BigEndian.Uint16(data[15+certLen : 17+certLen]))
			if 17+certLen+extLen == len(data) {
				return data[15 : 15+certLen], nil
			}
		}
	}
	// 2. Static-CT TileLeaf: timestamp(8) || entry_type(0=x509) || cert_len(3) || certDER ...
	if len(data) >= 13 && binary.BigEndian.Uint16(data[8:10]) == 0 {
		certLen := int(data[10])<<16 | int(data[11])<<8 | int(data[12])
		if certLen > 0 && len(data) >= 13+certLen {
			return data[13 : 13+certLen], nil
		}
	}
	// 3. Raw DER X.509 certificate
	return data, nil
}
