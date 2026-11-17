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
	"context"
	"crypto/sha256"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
)

//go:embed testdata/golden_leaves.json
var goldenLeavesJSON []byte

type goldenLeafCase struct {
	Category        string   `json:"category"`
	LeafHex         string   `json:"leaf_hex"`
	ExpectedDomains []string `json:"expected_domains"`
}

func (c goldenLeafCase) mustLeafBytes() []byte {
	b, err := hex.DecodeString(c.LeafHex)
	if err != nil {
		panic(fmt.Sprintf("failed to decode leaf hex for %q: %v", c.Category, err))
	}
	return b
}

func loadGoldenLeaves(tb testing.TB) []goldenLeafCase {
	tb.Helper()
	var cases []goldenLeafCase
	if err := json.Unmarshal(goldenLeavesJSON, &cases); err != nil {
		tb.Fatalf("failed to unmarshal golden_leaves.json: %v", err)
	}
	if len(cases) == 0 {
		tb.Fatal("no golden test cases loaded")
	}
	return cases
}

func newMTCWASMHost(tb testing.TB, workers int) *wasmhost.WASMHost {
	tb.Helper()
	ctx := context.Background()
	wasmPath := filepath.Join(tb.TempDir(), "mtc.wasm")

	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-buildid=", "-buildmode=c-shared", "-o", wasmPath, ".")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		tb.Fatalf("failed to build mtc.wasm: %v\n%s", err, string(out))
	}

	wasmBytes, err := os.ReadFile(wasmPath)
	if err != nil {
		tb.Fatalf("failed to read compiled wasm: %v", err)
	}

	host, err := wasmhost.NewWASMHost(ctx, wasmBytes, workers)
	if err != nil {
		tb.Fatalf("failed to create WASM host: %v", err)
	}
	tb.Cleanup(func() { _ = host.Close(ctx) })
	return host
}

type tbsCertificateLogEntry struct {
	Version                  int `asn1:"optional,explicit,default:0,tag:0"`
	Issuer                   pkix.RDNSequence
	Validity                 struct{ NotBefore, NotAfter time.Time }
	Subject                  pkix.RDNSequence
	SubjectPublicKeyInfoHash []byte
	IssuerUniqueID           asn1.BitString  `asn1:"optional,tag:1"`
	SubjectUniqueID          asn1.BitString  `asn1:"optional,tag:2"`
	Extensions               []asn1.RawValue `asn1:"optional,explicit,tag:3"`
}

func TestMapMTCLeaf_Golden(t *testing.T) {
	t.Parallel()
	cases := loadGoldenLeaves(t)

	for _, tc := range cases {
		t.Run(tc.Category, func(t *testing.T) {
			t.Parallel()
			raw := tc.mustLeafBytes()
			var got []string
			MapMTCLeaf(raw, func(key []byte) {
				got = append(got, string(key))
			})
			want := slices.Clone(tc.ExpectedDomains)
			slices.Sort(got)
			slices.Sort(want)

			if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("MapMTCLeaf() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMapMTCLeaf_ConcurrentSafety(t *testing.T) {
	t.Parallel()
	cases := loadGoldenLeaves(t)

	var wg sync.WaitGroup
	for g := range 16 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for iter := range 50 {
				tc := cases[(worker+iter)%len(cases)]
				raw := tc.mustLeafBytes()
				var got []string
				MapMTCLeaf(raw, func(key []byte) {
					got = append(got, string(key))
				})
				want := slices.Clone(tc.ExpectedDomains)
				slices.Sort(got)
				slices.Sort(want)
				if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("concurrent MapMTCLeaf(%s) mismatch:\n%s", tc.Category, diff)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestMapMTCLeaf_WASMHost_GoldenAndMalformedOverflow(t *testing.T) {
	ctx := context.Background()
	host := newMTCWASMHost(t, 2)

	less := func(a, b wasmhost.MappedEntry) bool {
		return a.Key < b.Key
	}

	for _, tc := range loadGoldenLeaves(t) {
		t.Run(tc.Category, func(t *testing.T) {
			raw := tc.mustLeafBytes()
			bundleEntries, err := host.MapBundle(ctx, [][]byte{raw})
			if err != nil {
				t.Fatalf("host.MapBundle failed: %v", err)
			}
			var entries []wasmhost.MappedEntry
			if len(bundleEntries) > 0 {
				entries = bundleEntries[0]
			}

			var want []wasmhost.MappedEntry
			for _, d := range tc.ExpectedDomains {
				want = append(want, wasmhost.MappedEntry{
					Key:     d,
					KeyHash: sha256.Sum256([]byte(d)),
				})
			}

			if diff := cmp.Diff(want, entries, cmpopts.SortSlices(less), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("host.MapBundle() mismatch (-want +got):\n%s", diff)
			}
		})
	}

	// Regression test for 32-bit wasip1 int32 addition overflow in readTagLen on crafted ASN.1 lengths.
	malformedLeaves := [][]byte{
		{0x00, 0x01, 0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}, // l = MaxInt32
		{0x00, 0x01, 0x30, 0x84, 0x7f, 0xff, 0xff, 0xfa}, // l = MaxInt32 - 5
		{0x00, 0x01, 0x30, 0x84, 0x80, 0x00, 0x00, 0x00}, // l = MinInt32 on 32-bit
		{0x00, 0x01, 0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, // l = -1 on 32-bit
	}
	for _, ml := range malformedLeaves {
		MapMTCLeaf(ml, func(key []byte) {
			t.Fatalf("expected 0 emitted keys on malformed ASN.1 leaf %x, got %q", ml, key)
		})
	}
	bundleEntries, err := host.MapBundle(ctx, malformedLeaves)
	if err != nil {
		t.Fatalf("host.MapBundle trapped on crafted 4-byte ASN.1 lengths: %v", err)
	}
	for i, entries := range bundleEntries {
		if len(entries) != 0 {
			t.Fatalf("malformed leaf %d emitted %v, want empty", i, entries)
		}
	}
}

func BenchmarkMapMTCLeaf(b *testing.B) {
	cases := loadGoldenLeaves(b)
	leaf := cases[0].mustLeafBytes()

	b.ReportAllocs()
	emitSink := func([]byte) {}
	for b.Loop() {
		MapMTCLeaf(leaf, emitSink)
	}
}

func BenchmarkMapMTCLeaf_WASM(b *testing.B) {
	ctx := context.Background()
	host := newMTCWASMHost(b, 4)
	cases := loadGoldenLeaves(b)
	bundle := [][]byte{cases[0].mustLeafBytes()}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := host.MapBundle(ctx, bundle); err != nil {
			b.Fatalf("host.MapBundle failed: %v", err)
		}
	}
}

func buildCustomMTCLeaf(t *testing.T, cn string, sans []string) []byte {
	t.Helper()
	var subj pkix.RDNSequence
	if cn != "" {
		subj = pkix.RDNSequence{
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{
					Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
					Value: cn,
				},
			},
		}
	}

	var exts []asn1.RawValue
	if len(sans) > 0 {
		var rawNames []asn1.RawValue
		for _, s := range sans {
			rawNames = append(rawNames, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(s)})
		}
		sanVal, err := asn1.Marshal(rawNames)
		if err != nil {
			t.Fatalf("failed to marshal SANs: %v", err)
		}
		ext := struct {
			Id       asn1.ObjectIdentifier
			Critical bool `asn1:"optional,default:false"`
			Value    []byte
		}{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: sanVal,
		}
		extBytes, err := asn1.Marshal(ext)
		if err != nil {
			t.Fatalf("failed to marshal extension: %v", err)
		}
		exts = append(exts, asn1.RawValue{FullBytes: extBytes})
	}

	der, err := asn1.Marshal(tbsCertificateLogEntry{
		Subject:    subj,
		Extensions: exts,
	})
	if err != nil {
		t.Fatalf("failed to marshal TBSCertificateLogEntry: %v", err)
	}
	return append([]byte{0, 1}, der...)
}

func TestMapMTCLeaf_SubjectCN_IDNA_TrailingDot_And_Overflow(t *testing.T) {
	t.Parallel()
	leaf1 := buildCustomMTCLeaf(t, "cn-only.example.com.", []string{"münchen.de.", "*.münchen.de"})
	var got1 []string
	MapMTCLeaf(leaf1, func(key []byte) {
		got1 = append(got1, string(key))
	})
	want1 := []string{
		"com.example.cn-only.",
		"de.xn--mnchen-3ya.",
		"de.xn--mnchen-3ya.*.",
	}
	if diff := cmp.Diff(want1, got1); diff != "" {
		t.Errorf("MapMTCLeaf(CN/IDNA/TrailingDot) mismatch (-want +got):\n%s", diff)
	}

	var sans []string
	var want2 []string
	for i := range 100 {
		sans = append(sans, fmt.Sprintf("host-%03d.long-subdomain-segment.example.com", i))
		want2 = append(want2, fmt.Sprintf("com.example.long-subdomain-segment.host-%03d.", i))
	}
	leaf2 := buildCustomMTCLeaf(t, "", sans)
	var got2 []string
	MapMTCLeaf(leaf2, func(key []byte) {
		got2 = append(got2, string(key))
	})
	if diff := cmp.Diff(want2, got2); diff != "" {
		t.Errorf("MapMTCLeaf(100 SANs overflow) mismatch (-want +got):\n%s", diff)
	}
}

func TestCanonicalizeDomainBytes(t *testing.T) {
	t.Parallel()

	// Construct a valid multi-label Japanese IDN >253 raw UTF-8 bytes that compresses to <=253 Punycode bytes.
	jpLabel := strings.Repeat("日本語", 6) // 18 runes = 54 UTF-8 bytes; Punycode "xn--..." is 28 ASCII bytes
	longUTF8IDN := strings.Join([]string{jpLabel, jpLabel, jpLabel, jpLabel, jpLabel, "jp"}, ".")
	if len(longUTF8IDN) <= 253 {
		t.Fatalf("expected longUTF8IDN > 253 UTF-8 bytes, got %d", len(longUTF8IDN))
	}
	wantLongIDN, err := client.DomainToCanonicalKey(longUTF8IDN)
	if err != nil {
		t.Fatalf("client.DomainToCanonicalKey(longUTF8IDN) failed: %v", err)
	}

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
		{name: "multi-label UTF-8 IDN >253 raw bytes", in: longUTF8IDN, want: wantLongIDN, wantOK: true},
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

func TestMapMTCLeaf_SkipIPAndInvalidLabels(t *testing.T) {
	t.Parallel()
	invalidLeaf := buildCustomMTCLeaf(t, "192.0.2.1", []string{
		"127.0.0.1",
		"2001:db8::1",
		"[2001:db8::1]",
		"-bad.example.com",
		"bad-.example.com",
		"example.-com",
	})
	var gotInvalid []string
	MapMTCLeaf(invalidLeaf, func(key []byte) {
		gotInvalid = append(gotInvalid, string(key))
	})
	if len(gotInvalid) != 0 {
		t.Errorf("MapMTCLeaf(invalid IP/hyphen labels) emitted %v, want 0 keys", gotInvalid)
	}

	mixedLeaf := buildCustomMTCLeaf(t, "192.0.2.1", []string{
		"127.0.0.1",
		"2001:db8::1",
		"[2001:db8::1]",
		"-bad.example.com",
		"bad-.example.com",
		"example.-com",
		"1.2.example.com",
		"*.mail.example.com",
		"bücher.example.com",
	})
	var gotMixed []string
	MapMTCLeaf(mixedLeaf, func(key []byte) {
		gotMixed = append(gotMixed, string(key))
	})
	wantMixed := []string{
		"com.example.2.1.",
		"com.example.mail.*.",
		"com.example.xn--bcher-kva.",
	}
	if diff := cmp.Diff(wantMixed, gotMixed); diff != "" {
		t.Errorf("MapMTCLeaf(mixed valid/invalid) mismatch (-want +got):\n%s", diff)
	}
}
