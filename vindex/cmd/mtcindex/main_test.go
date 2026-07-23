// Copyright 2026 Google LLC. All Rights Reserved.
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

package main

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/transparency-dev/incubator/vindex/internal/mtc"
)

// helper to marshal TBSCertificateLogEntry
func marshalMTCEntry(dnsNames []string) ([]byte, error) {
	rawNames := []asn1.RawValue{}
	for _, name := range dnsNames {
		rawNames = append(rawNames, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(name)})
	}
	sanValue, err := asn1.Marshal(rawNames)
	if err != nil {
		return nil, err
	}

	ext := struct {
		Id       asn1.ObjectIdentifier
		Critical bool `asn1:"optional,default:false"`
		Value    []byte
	}{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
		Value: sanValue,
	}
	extBytes, err := asn1.Marshal(ext)
	if err != nil {
		return nil, err
	}

	entry := mtc.TBSCertificateLogEntry{
		Extensions: []asn1.RawValue{{FullBytes: extBytes}},
	}

	entryBytes, err := asn1.Marshal(entry)
	if err != nil {
		return nil, err
	}

	return append([]byte{0, 1}, entryBytes...), nil
}

func TestMapFn(t *testing.T) {
	// Fixed DER payload from vindex/internal/mtc/mtc_test.go
	derHex := "30820146a003020102301c311a3018060a2b0601040182da4b2f010c0a34343336332e34382e38301e170d3235313131313230313732365a170d3235313131383230313732365a30818e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311430120603550407130b4c6f7320416e67656c6573313c303a060355040a1333496e7465726e657420436f72706f726174696f6e20666f722041737369676e6564204e616d657320616e64204e756d626572733116301406035504030c0d2a2e6578616d706c652e636f6d042088c3292097527f95650a51dac5945eca168bc4bb2664c30d022036a4c47cfccea34e304c30250603551d11041e301c820d2a2e6578616d706c652e636f6d820b6578616d706c652e636f6d300e0603551d0f0101ff04040302078030130603551d25040c300a06082b0601050507030100"
	derBytes, err := hex.DecodeString(derHex)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	// Type 1: tbs_cert_entry
	// Prefix with \x00\x01 (big-endian uint16 of 1 is [0, 1])
	validType1 := append([]byte{0x00, 0x01}, derBytes...)

	// Type 0: something else
	validType0 := append([]byte{0x00, 0x00}, derBytes...)

	// Invalid entry data for Type 1
	invalidType1 := append([]byte{0x00, 0x01}, []byte("invalid der")...)

	// Generated test cases
	subdomainCert, err := marshalMTCEntry([]string{"deep.maps.google.co.uk"})
	if err != nil {
		t.Fatalf("failed to create subdomain cert: %v", err)
	}
	mixedCaseCert, err := marshalMTCEntry([]string{"MAPS.GOOGLE.COM"})
	if err != nil {
		t.Fatalf("failed to create mixed case cert: %v", err)
	}

	tests := []struct {
		name string
		data []byte
		want [][32]byte
	}{
		{
			name: "Valid Type 1 (wildcard stripped)",
			data: validType1,
			want: [][32]byte{
				sha256.Sum256([]byte("example.com")),
			},
		},
		{
			name: "Type 0 (ignored)",
			data: validType0,
			want: nil,
		},
		{
			name: "Invalid Type 1 (ignored/warning)",
			data: invalidType1,
			want: nil,
		},
		{
			name: "Too short data",
			data: []byte{0x00},
			want: nil,
		},
		{
			name: "Subdomain indexing",
			data: subdomainCert,
			want: [][32]byte{
				sha256.Sum256([]byte("deep.maps.google.co.uk")),
				sha256.Sum256([]byte("maps.google.co.uk")),
				sha256.Sum256([]byte("google.co.uk")),
			},
		},
		{
			name: "Mixed case normalization",
			data: mixedCaseCert,
			want: [][32]byte{
				sha256.Sum256([]byte("maps.google.com")),
				sha256.Sum256([]byte("google.com")),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapFn(tt.data)

			// Sort helper for [32]byte
			less := func(a, b [32]byte) bool {
				for i := 0; i < 32; i++ {
					if a[i] < b[i] {
						return true
					}
					if a[i] > b[i] {
						return false
					}
				}
				return false
			}

			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(less)); diff != "" {
				t.Errorf("mapFn() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
