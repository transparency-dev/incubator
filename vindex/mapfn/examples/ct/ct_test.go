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

package main

import (
	_ "embed"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"
)

func generateTestCert(t *testing.T, cn string, sans []string) []byte {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: cn,
		},
		DNSNames:              sans,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	return der
}

func buildRFC6962Leaf(entryType uint16, payload []byte) []byte {
	var buf []byte
	buf = append(buf, 0x00) // version 0
	buf = append(buf, 0x00) // leaf_type = timestamped_entry
	var ts [8]byte
	buf = append(buf, ts[:]...)
	var et [2]byte
	binary.BigEndian.PutUint16(et[:], entryType)
	buf = append(buf, et[:]...)

	switch entryType {
	case 0: // x509_entry
		certLen := len(payload)
		buf = append(buf, byte(certLen>>16), byte(certLen>>8), byte(certLen))
		buf = append(buf, payload...)
		buf = append(buf, 0x00, 0x00) // extensions length
	case 1: // precert_entry
		var keyHash [32]byte
		buf = append(buf, keyHash[:]...)
		tbsLen := len(payload)
		buf = append(buf, byte(tbsLen>>16), byte(tbsLen>>8), byte(tbsLen))
		buf = append(buf, payload...)
		buf = append(buf, 0x00, 0x00) // extensions length
	}
	return buf
}

func TestMapCTLeaf_X509Certificate(t *testing.T) {
	certDer := generateTestCert(t, "example.com", []string{"foo.bar.example.com", "*.sub.example.org"})
	leaf := buildRFC6962Leaf(0, certDer)

	var domains []string
	MapCTLeaf(leaf, func(key []byte) {
		domains = append(domains, string(key))
	})
	domainMap := make(map[string]bool)
	for _, d := range domains {
		domainMap[d] = true
	}

	expectedDomains := []string{
		"com.example.",
		"com.example.bar.foo.",
		"org.example.sub.*.",
	}

	if len(domains) != len(expectedDomains) {
		t.Errorf("got %d domains %v, want %d %v", len(domains), domains, len(expectedDomains), expectedDomains)
	}
	for _, d := range expectedDomains {
		if !domainMap[d] {
			t.Errorf("expected domain %q in mapped entries, got %v", d, domains)
		}
	}
}

func TestMapCTLeaf_StaticCTTileLeaf_HeaderDisambiguation(t *testing.T) {
	certDer := generateTestCert(t, "static-ct.example.com", []string{"api.static-ct.example.com"})
	parsedCert, err := x509.ParseCertificate(certDer)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	// Build a Static-CT precert TileLeaf whose 8-byte timestamp begins with 0x00, 0x00
	// and whose issuer_key_hash begins with 0x00, 0x01 (colliding with RFC 6962 entry_type at offset 10..12).
	var leaf []byte
	ts := [8]byte{0x00, 0x00, 0x01, 0x98, 0xcf, 0x15, 0xff, 0xf7}
	leaf = append(leaf, ts[:]...)
	leaf = append(leaf, 0x00, 0x01) // entry_type = precert_entry (at offset 8..10)
	var keyHash [32]byte
	keyHash[0] = 0x00
	keyHash[1] = 0x01 // at offset 10..12 in leaf!
	leaf = append(leaf, keyHash[:]...)
	tbs := parsedCert.RawTBSCertificate
	tbsLen := len(tbs)
	leaf = append(leaf, byte(tbsLen>>16), byte(tbsLen>>8), byte(tbsLen))
	leaf = append(leaf, tbs...)
	leaf = append(leaf, 0x00, 0x00) // extensions
	leaf = append(leaf, 0x00, 0x00, 0x00)
	leaf = append(leaf, 0x00, 0x00) // chain

	var got []string
	MapCTLeaf(leaf, func(key []byte) {
		got = append(got, string(key))
	})
	want := []string{
		"com.example.static-ct.",
		"com.example.static-ct.api.",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("MapCTLeaf(Static-CT precert with 0x0001 issuer_key_hash prefix) = %v, want %v", got, want)
	}
}

func TestMapCTLeaf_MultiLabelTLD_And_IDNA(t *testing.T) {
	// Subject.CommonName is marshaled as UTF8String by x509.CreateCertificate, allowing IDN test input.
	certDer := generateTestCert(t, "*.münchen.de.", []string{"deep.sub.service.co.uk.", "MAPS.GOOGLE.COM"})
	var domains []string
	MapCTLeaf(certDer, func(key []byte) {
		domains = append(domains, string(key))
	})
	domainMap := make(map[string]bool)
	for _, d := range domains {
		domainMap[d] = true
	}

	expectedDomains := []string{
		"de.xn--mnchen-3ya.*.",
		"uk.co.service.sub.deep.",
		"com.google.maps.",
	}

	if len(domains) != len(expectedDomains) {
		t.Errorf("got %d domains %v, want %d %v", len(domains), domains, len(expectedDomains), expectedDomains)
	}
	for _, d := range expectedDomains {
		if !domainMap[d] {
			t.Errorf("expected domain %q in mapped entries, got %v", d, domains)
		}
	}
}

func TestMapCTLeaf_NoPlaintextFallback(t *testing.T) {
	plain := []byte("alpha.example.com\n*.beta.example.com\n")
	var domains []string
	MapCTLeaf(plain, func(key []byte) {
		domains = append(domains, string(key))
	})
	if len(domains) != 0 {
		t.Errorf("expected 0 keys for non-ASN.1 plaintext input, got %v", domains)
	}
}

func TestMapCTLeaf_LargeSANOverflow(t *testing.T) {
	var sans []string
	for i := 0; i < 100; i++ {
		sans = append(sans, fmt.Sprintf("host-%03d.long-subdomain-segment.example.com", i))
	}
	certDer := generateTestCert(t, "", sans)
	leaf := buildRFC6962Leaf(0, certDer)

	var domains []string
	MapCTLeaf(leaf, func(key []byte) {
		domains = append(domains, string(key))
	})
	if len(domains) != 100 {
		t.Fatalf("expected 100 domains, got %d", len(domains))
	}
}

func TestMapCTLeaf_Empty(t *testing.T) {
	var count int
	emitCount := func(key []byte) { count++ }

	count = 0
	MapCTLeaf(nil, emitCount)
	if count != 0 {
		t.Fatalf("expected 0 results for nil input, got %d", count)
	}

	count = 0
	MapCTLeaf([]byte("   \n\t  "), emitCount)
	if count != 0 {
		t.Fatalf("expected 0 results for whitespace input, got %d", count)
	}
}

func TestCanonicalizeDomainBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{name: "IPv4 literal 192.0.2.1", in: "192.0.2.1", want: "", wantOK: false},
		{name: "IPv4 literal 127.0.0.1", in: "127.0.0.1", want: "", wantOK: false},
		{name: "IPv4 literal trailing dot", in: "192.0.2.1.", want: "", wantOK: false},
		{name: "IPv6 literal", in: "2001:db8::1", want: "", wantOK: false},
		{name: "IPv6 bracketed literal", in: "[2001:db8::1]", want: "", wantOK: false},
		{name: "leading hyphen label", in: "-bad.example.com", want: "", wantOK: false},
		{name: "trailing hyphen label", in: "bad-.example.com", want: "", wantOK: false},
		{name: "leading hyphen TLD", in: "example.-com", want: "", wantOK: false},
		{name: "trailing hyphen TLD", in: "example.com-", want: "", wantOK: false},
		{name: "numeric subdomains", in: "1.2.example.com", want: "com.example.2.1.", wantOK: true},
		{name: "wildcard subdomain", in: "*.mail.example.com", want: "com.example.mail.*.", wantOK: true},
		{name: "IDN domain", in: "bücher.example.com", want: "com.example.xn--bcher-kva.", wantOK: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf [256]byte
			got, ok := canonicalizeDomainBytes([]byte(tc.in), &buf)
			if ok != tc.wantOK || string(got) != tc.want {
				t.Errorf("canonicalizeDomainBytes(%q) = (%q, %v), want (%q, %v)", tc.in, string(got), ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestMapCTLeaf_SkipIPAndInvalidLabels(t *testing.T) {
	invalidCert := generateTestCert(t, "192.0.2.1", []string{
		"127.0.0.1",
		"2001:db8::1",
		"[2001:db8::1]",
		"-bad.example.com",
		"bad-.example.com",
		"example.-com",
	})
	invalidLeaf := buildRFC6962Leaf(0, invalidCert)

	var gotInvalid []string
	MapCTLeaf(invalidLeaf, func(key []byte) {
		gotInvalid = append(gotInvalid, string(key))
	})
	if len(gotInvalid) != 0 {
		t.Errorf("MapCTLeaf(invalid IP/hyphen labels) emitted %v, want 0 keys", gotInvalid)
	}

	// Subject.CommonName is marshaled as UTF8String by x509.CreateCertificate, allowing IDN test input.
	mixedCert := generateTestCert(t, "bücher.example.com", []string{
		"192.0.2.1",
		"127.0.0.1",
		"2001:db8::1",
		"[2001:db8::1]",
		"-bad.example.com",
		"bad-.example.com",
		"example.-com",
		"1.2.example.com",
		"*.mail.example.com",
	})
	mixedLeaf := buildRFC6962Leaf(0, mixedCert)

	var gotMixed []string
	MapCTLeaf(mixedLeaf, func(key []byte) {
		gotMixed = append(gotMixed, string(key))
	})
	slices.Sort(gotMixed)
	wantMixed := []string{
		"com.example.2.1.",
		"com.example.mail.*.",
		"com.example.xn--bcher-kva.",
	}
	if !slices.Equal(gotMixed, wantMixed) {
		t.Errorf("MapCTLeaf(mixed valid/invalid) = %v, want %v", gotMixed, wantMixed)
	}
}

//go:embed testdata/golden_leaves.json
var goldenLeavesJSON []byte

type goldenCase struct {
	Index      int    `json:"index"`
	EntryType  string `json:"entry_type"`
	Category   string `json:"category"`
	LeafHex    string `json:"leaf_hex"`
	ByteLength int    `json:"byte_length"`
}

func TestMapCTLeaf_GoldenDataset(t *testing.T) {
	var cases []goldenCase
	if err := json.Unmarshal(goldenLeavesJSON, &cases); err != nil {
		t.Fatalf("failed to unmarshal golden_leaves.json: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("empty golden dataset")
	}

	for _, tc := range cases {
		leafBytes, err := hex.DecodeString(tc.LeafHex)
		if err != nil {
			t.Fatalf("case %d: failed to decode hex: %v", tc.Index, err)
		}
		if len(leafBytes) != tc.ByteLength {
			t.Fatalf("case %d: byte length mismatch: got %d, want %d", tc.Index, len(leafBytes), tc.ByteLength)
		}

		var domains []string
		MapCTLeaf(leafBytes, func(key []byte) {
			domains = append(domains, string(key))
		})

		want := []string{
			"com.flowers-to-the-world.",
			fmt.Sprintf("com.flowers-to-the-world.letsencrypt_sycamore2026h2.2025.08.22.%02d.", tc.Index&^1),
		}
		if !slices.Equal(domains, want) {
			t.Errorf("case %d [%s/%s]: got %v, want %v", tc.Index, tc.EntryType, tc.Category, domains, want)
		}
	}
}

func BenchmarkMapCTLeaf(b *testing.B) {
	var cases []goldenCase
	if err := json.Unmarshal(goldenLeavesJSON, &cases); err != nil {
		b.Fatalf("failed to unmarshal golden_leaves.json: %v", err)
	}
	if len(cases) == 0 {
		b.Fatal("empty golden dataset")
	}
	leaf, err := hex.DecodeString(cases[0].LeafHex)
	if err != nil {
		b.Fatalf("failed to decode hex: %v", err)
	}

	b.ReportAllocs()
	emitSink := func(key []byte) {}
	for b.Loop() {
		MapCTLeaf(leaf, emitSink)
	}
}

func TestMapCTLeaf_ConcurrentSafety(t *testing.T) {
	certDer := generateTestCert(t, "example.com", []string{"foo.bar.example.com", "*.sub.example.org"})
	leaf := buildRFC6962Leaf(0, certDer)

	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				var count int
				MapCTLeaf(leaf, func(key []byte) {
					count++
				})
				if count != 3 {
					t.Errorf("got %d domains, want 3", count)
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

func TestReadASN1Header_OverflowGuard(t *testing.T) {
	// 4-byte length 0x80000000 (negative on 32-bit int) or 0x7fffffff
	malformed := []byte{0x30, 0x84, 0x80, 0x00, 0x00, 0x00, 0x01, 0x02}
	if _, _, _, ok := readASN1Header(malformed, 0); ok {
		t.Fatal("expected readASN1Header to reject negative/overflowing 4-byte length")
	}
	malformedMax := []byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x01, 0x02}
	if _, _, _, ok := readASN1Header(malformedMax, 0); ok {
		t.Fatal("expected readASN1Header to reject 0x7fffffff length")
	}
}
