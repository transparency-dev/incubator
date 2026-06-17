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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/transparency-dev/incubator/vindex/api"
	"github.com/transparency-dev/incubator/vindex/internal/web"
	"golang.org/x/crypto/cryptobyte"
)

func createTestCertBytes(dnsNames []string, isPrecert bool) ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	var tbsDER []byte
	if isPrecert {
		parsed, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, err
		}
		tbsDER = parsed.RawTBSCertificate
	}

	// Now marshal using cryptobyte into the form expected by mapFn
	// version = 0, leafType = 0, timestamp = 12345678
	var b cryptobyte.Builder
	b.AddUint8(0)         // version
	b.AddUint8(0)         // leafType
	b.AddUint64(12345678) // timestamp
	if isPrecert {
		b.AddUint16(1) // certType (precert)
		dummyIKH := make([]byte, 32)
		b.AddBytes(dummyIKH)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(tbsDER)
		})
	} else {
		b.AddUint16(0) // certType (x509)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(certDER)
		})
	}
	return b.Bytes()
}

func TestMapFn(t *testing.T) {
	testCases := []struct {
		desc      string
		dnsNames  []string
		wantKeys  []string
		isPrecert bool
		rawBytes  []byte
	}{
		{
			desc:      "standard domains and wildcards",
			dnsNames:  []string{"*.google.com", "google.com", "maps.google.com"},
			wantKeys:  []string{"google.com", "maps.google.com"},
			isPrecert: false,
		},
		{
			desc:      "deeper subdomain",
			dnsNames:  []string{"deep.maps.google.co.uk"},
			wantKeys:  []string{"deep.maps.google.co.uk", "maps.google.co.uk", "google.co.uk"},
			isPrecert: false,
		},
		{
			desc:      "mixed case",
			dnsNames:  []string{"MAPS.GOOGLE.COM"},
			wantKeys:  []string{"maps.google.com", "google.com"},
			isPrecert: false,
		},
		{
			desc:      "invalid or TLD",
			dnsNames:  []string{"localhost", "*.co.uk"},
			wantKeys:  []string{"localhost", "co.uk"},
			isPrecert: false,
		},
		{
			desc:      "precert: standard domains and wildcards",
			dnsNames:  []string{"*.google.com", "google.com", "maps.google.com"},
			wantKeys:  []string{"google.com", "maps.google.com"},
			isPrecert: true,
		},
		{
			desc:      "precert: deeper subdomain",
			dnsNames:  []string{"deep.maps.google.co.uk"},
			wantKeys:  []string{"deep.maps.google.co.uk", "maps.google.co.uk", "google.co.uk"},
			isPrecert: true,
		},
		{
			desc:     "truncated header",
			rawBytes: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // 11 bytes, header is 12 bytes
			wantKeys: []string{},
		},
		{
			desc: "unknown cert type",
			rawBytes: []byte{
				0,                      // version
				0,                      // leafType
				0, 0, 0, 0, 0, 0, 0, 0, // timestamp
				0, 99, // certType = 99
			},
			wantKeys: []string{},
		},
		{
			desc: "precert truncated TBS",
			rawBytes: func() []byte {
				var b cryptobyte.Builder
				b.AddUint8(0)         // version
				b.AddUint8(0)         // leafType
				b.AddUint64(12345678) // timestamp
				b.AddUint16(1)        // certType (precert)
				dummyIKH := make([]byte, 32)
				b.AddBytes(dummyIKH)
				b.AddUint24(100)                  // length prefix 100
				b.AddBytes([]byte{1, 2, 3, 4, 5}) // only 5 bytes of data
				bytes, _ := b.Bytes()
				return bytes
			}(),
			wantKeys: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			var data []byte
			var err error
			if tc.rawBytes != nil {
				data = tc.rawBytes
			} else {
				data, err = createTestCertBytes(tc.dnsNames, tc.isPrecert)
				if err != nil {
					t.Fatalf("failed to create test cert: %v", err)
				}
			}
			hashes := mapFn(data)

			gotKeys := make(map[string]bool)
			for _, h := range hashes {
				found := false
				for _, wk := range tc.wantKeys {
					if sha256.Sum256([]byte(wk)) == h {
						gotKeys[wk] = true
						found = true
						break
					}
				}
				if !found {
					t.Errorf("got unexpected hash for a key not in wantKeys")
				}
			}

			for _, wk := range tc.wantKeys {
				if !gotKeys[wk] {
					t.Errorf("missing expected key: %s", wk)
				}
			}
			if len(gotKeys) != len(tc.wantKeys) {
				t.Errorf("got %d unique keys, want %d", len(gotKeys), len(tc.wantKeys))
			}
		})
	}
}

func TestMetricsEndpoint(t *testing.T) {
	s := web.NewServer(func(ctx context.Context, h [sha256.Size]byte) (api.LookupResponse, error) {
		return api.LookupResponse{}, nil
	})
	r := mux.NewRouter()
	s.RegisterHandlers(r)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /metrics: got status %d, want %d", w.Code, http.StatusOK)
	}
}
