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

package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

func TestOutputLogLeafRoundTrip(t *testing.T) {
	mptRoot := sha256.Sum256([]byte("mpt-root"))
	inRoot := sha256.Sum256([]byte("in-root"))
	inCP := &log.Checkpoint{
		Origin: "go.sum database tree",
		Size:   42,
		Hash:   inRoot[:],
	}

	leaf := FormatOutputLogLeafFull(mptRoot, 10, inCP)
	parsed, err := ParseOutputLogLeafFull(leaf)
	if err != nil {
		t.Fatalf("ParseOutputLogLeafFull failed: %v", err)
	}
	if parsed.MPTRoot != mptRoot {
		t.Errorf("mptRoot = %x, want %x", parsed.MPTRoot, mptRoot)
	}
	if parsed.InputOrigin != "go.sum database tree" {
		t.Errorf("inputOrigin = %q, want %q", parsed.InputOrigin, "go.sum database tree")
	}
	if parsed.From != 10 {
		t.Errorf("from = %d, want 10", parsed.From)
	}
	if parsed.InputSize != 42 {
		t.Errorf("inputSize = %d, want 42", parsed.InputSize)
	}
	if parsed.InputRoot != inRoot {
		t.Errorf("inputRoot = %x, want %x", parsed.InputRoot, inRoot)
	}
	if parsed.InCP.Origin != "go.sum database tree" || parsed.InCP.Size != 42 || !bytes.Equal(parsed.InCP.Hash, inRoot[:]) {
		t.Errorf("gotCP = %+v", parsed.InCP)
	}

	// Simple leaf round-trip (from=0)
	simpleLeaf := FormatOutputLogLeaf(mptRoot, inCP)
	gotRoot, gotCP, err := ParseOutputLogLeaf(simpleLeaf)
	if err != nil {
		t.Fatalf("ParseOutputLogLeaf failed: %v", err)
	}
	if gotRoot != mptRoot || gotCP.Size != 42 || gotCP.Origin != "go.sum database tree" || !bytes.Equal(gotCP.Hash, inRoot[:]) {
		t.Errorf("simple leaf round-trip mismatch")
	}

	// Reject fewer or more than 6 lines, or trailing data after 6th newline
	if _, err := ParseOutputLogLeafFull(append(bytes.Clone(leaf), '\n')); err == nil {
		t.Errorf("expected error for trailing newline after 6th line")
	}
	if _, err := ParseOutputLogLeafFull(append(bytes.Clone(leaf), []byte("extra line\n")...)); err == nil {
		t.Errorf("expected error for 7th line")
	}
	if _, err := ParseOutputLogLeafFull(FormatStateEntry(" leading-space", 0, 10, inRoot, mptRoot)); err == nil {
		t.Errorf("expected error for leading space in input-origin")
	}
	if _, err := ParseOutputLogLeafFull(FormatStateEntry("example.com/log", 11, 10, inRoot, mptRoot)); err == nil {
		t.Errorf("expected error when from > input-size")
	}

	// Reject hex-encoded checkpoint root hash (must be strict 44-char base64)
	hexCP := []byte("example.com/inputlog\n42\n0101010101010101010101010101010101010101010101010101010101010101\n")
	if _, err := ParseCheckpointHeader(hexCP); err == nil {
		t.Errorf("expected ParseCheckpointHeader to reject 64-char hex hash, got nil")
	}

	if got := PercentEncodeCanonicalKey("a+b/c?d=e&f#g~h_i-j.k"); got != "a%2Bb%2Fc%3Fd%3De%26f%23g~h_i-j.k" {
		t.Errorf("PercentEncodeCanonicalKey = %q", got)
	}
}

func TestFormatAndParseSections(t *testing.T) {
	mptRoot := sha256.Sum256([]byte("mpt-root"))
	valueRoot := sha256.Sum256([]byte("value-root"))
	inRoot := sha256.Sum256([]byte("in-root"))
	rawOutCP := []byte("example.com/vindex\n1\n" + base64.StdEncoding.EncodeToString(mptRoot[:]) + "\n\n— example.com/vindex sig==\n")
	inCP := &log.Checkpoint{
		Origin: "example.com/inputlog",
		Size:   10,
		Hash:   inRoot[:],
	}

	keysBody := FormatKeysResponseFull(
		rawOutCP,
		0,
		mptRoot,
		2,
		inCP,
		[][32]byte{valueRoot},
		"inclusion",
		[]byte("proof-bytes"),
		[]KeyValueRoot{{Key: "com.google.mail.", ValueRoot: valueRoot}},
	)

	stanzas := bytes.SplitN(keysBody, []byte("\n\n"), 2)
	if len(stanzas) != 2 {
		t.Fatalf("expected 2 top-level sections, got %d", len(stanzas))
	}
	keysSec, err := ParseKeysSection(stanzas[0])
	if err != nil {
		t.Fatalf("ParseKeysSection failed: %v", err)
	}
	if !bytes.Equal(keysSec.MPTProof, []byte("proof-bytes")) {
		t.Errorf("keysSec.MPTProof = %q, want proof-bytes", keysSec.MPTProof)
	}
	if len(keysSec.Matches) != 1 || keysSec.Matches[0].Key != "com.google.mail." || keysSec.Matches[0].ValueRoot != valueRoot {
		t.Errorf("keysSec.Matches = %+v", keysSec.Matches)
	}

	bindSec, err := ParseBindingSection(stanzas[1])
	if err != nil {
		t.Fatalf("ParseBindingSection failed: %v", err)
	}
	if bindSec.MPTRoot != mptRoot || bindSec.InputOrigin != "example.com/inputlog" || bindSec.InputSize != 10 || bindSec.InputRoot != inRoot || bindSec.From != 2 || bindSec.OutLeafIdx != 0 {
		t.Errorf("bindSec = %+v", bindSec)
	}
	if len(bindSec.InclusionProof) != 1 || !bytes.Equal(bindSec.InclusionProof[0], valueRoot[:]) {
		t.Errorf("bindSec.InclusionProof = %+v", bindSec.InclusionProof)
	}
	if !bytes.Equal(bindSec.RawProofAndCP, stanzas[1]) {
		t.Errorf("bindSec.RawProofAndCP = %q, want %q", bindSec.RawProofAndCP, stanzas[1])
	}

	// Test bare 'proof' line when mptProof is empty
	emptyProofSec := FormatKeysSection(nil, "inclusion", []KeyValueRoot{{Key: "com.google.mail.", ValueRoot: valueRoot}})
	if bytes.Contains(emptyProofSec, []byte("proof ")) || !bytes.Contains(emptyProofSec, []byte("proof\n")) {
		t.Errorf("expected bare 'proof' line without trailing space when mptProof is empty, got:\n%s", string(emptyProofSec))
	}
	if _, err := ParseKeysSection(emptyProofSec); err != nil {
		t.Fatalf("ParseKeysSection(emptyProofSec) failed: %v", err)
	}
	if _, err := ParseKeysSection([]byte("c2sp.org/tlog-vindex-keys@v1\nproof \n")); err == nil {
		t.Errorf("expected error for 'proof ' with trailing space and empty base64")
	}

	valuesBody := FormatValuesResponse(1, [][32]byte{valueRoot}, []uint64{5, 8})
	valSec, err := ParseValuesResponse(valuesBody)
	if err != nil {
		t.Fatalf("ParseValuesResponse failed: %v", err)
	}
	if valSec.Preceding != 1 || len(valSec.CompactRange) != 1 || valSec.CompactRange[0] != valueRoot {
		t.Errorf("valSec header = %+v", valSec)
	}
	if len(valSec.Indices) != 2 || valSec.Indices[0] != 5 || valSec.Indices[1] != 8 {
		t.Errorf("valSec.Indices = %v, want [5 8]", valSec.Indices)
	}
}

func TestLeafAndInteriorHashMatchRFC6962(t *testing.T) {
	for _, sz := range []int{0, 8, 64, 511, 512, 1024} {
		data := bytes.Repeat([]byte{0xAB}, sz)
		got := LeafHash(data)
		want := rfc6962.DefaultHasher.HashLeaf(data)
		if !bytes.Equal(got[:], want) {
			t.Fatalf("LeafHash(len=%d) = %x, want %x", sz, got, want)
		}
	}

	l := sha256.Sum256([]byte("left"))
	r := sha256.Sum256([]byte("right"))
	gotInt := InteriorHash(l, r)
	wantInt := rfc6962.DefaultHasher.HashChildren(l[:], r[:])
	if !bytes.Equal(gotInt[:], wantInt) {
		t.Fatalf("InteriorHash = %x, want %x", gotInt, wantInt)
	}

	var b0, b1 [8]byte
	binary.BigEndian.PutUint64(b0[:], 10)
	binary.BigEndian.PutUint64(b1[:], 20)
	h0 := LeafHash(b0[:])
	root2, err := ComputeValueLogRoot(nil, 0, []uint64{10, 20})
	if err != nil {
		t.Fatalf("ComputeValueLogRoot(2) failed: %v", err)
	}
	rootFromCompactRange, err := ComputeValueLogRoot([][32]byte{h0}, 1, []uint64{20})
	if err != nil {
		t.Fatalf("ComputeValueLogRoot(compactRange+1) failed: %v", err)
	}
	if root2 != rootFromCompactRange {
		t.Fatalf("root2 %x != rootFromCompactRange %x", root2, rootFromCompactRange)
	}
}

func TestPackageDependencyBoundaries(t *testing.T) {
	cases := []struct {
		pkg       string
		forbidden []string
	}{
		{
			pkg: "github.com/transparency-dev/incubator/vindex/internal/metrics",
			forbidden: []string{
				"github.com/cockroachdb/pebble",
				"github.com/tetratelabs/wazero",
				"github.com/transparency-dev/tessera",
				"filippo.io/torchwood",
				"github.com/transparency-dev/incubator/vindex/internal/wire",
				"github.com/transparency-dev/incubator/vindex/internal/tree",
				"github.com/transparency-dev/incubator/vindex/internal/kvstore",
				"github.com/transparency-dev/incubator/vindex/internal/ingest",
			},
		},
		{
			pkg: "github.com/transparency-dev/incubator/vindex/internal/wire",
			forbidden: []string{
				"github.com/cockroachdb/pebble",
				"github.com/tetratelabs/wazero",
				"github.com/transparency-dev/tessera",
				"filippo.io/torchwood",
				"github.com/transparency-dev/incubator/vindex/internal/metrics",
				"github.com/transparency-dev/incubator/vindex/internal/tree",
				"github.com/transparency-dev/incubator/vindex/internal/kvstore",
				"github.com/transparency-dev/incubator/vindex/internal/ingest",
			},
		},
		{
			pkg: "github.com/transparency-dev/incubator/vindex/client",
			forbidden: []string{
				"github.com/cockroachdb/pebble",
				"github.com/tetratelabs/wazero",
				"github.com/transparency-dev/incubator/vindex/internal/tree",
				"github.com/transparency-dev/incubator/vindex/internal/kvstore",
				"github.com/transparency-dev/incubator/vindex/internal/ingest",
				"github.com/transparency-dev/incubator/vindex/internal/mtc",
			},
		},
		{
			pkg: "github.com/transparency-dev/incubator/vindex/cmd/vindex-wasm",
			forbidden: []string{
				"net/http",
				"github.com/transparency-dev/tessera",
				"github.com/transparency-dev/incubator/vindex/internal/ingest",
			},
		},
		{
			pkg: "github.com/transparency-dev/incubator/vindex/internal/mtc",
			forbidden: []string{
				"github.com/transparency-dev/incubator/vindex/internal/ingest",
				"github.com/transparency-dev/incubator/vindex/internal/kvstore",
				"github.com/transparency-dev/incubator/vindex/internal/tree",
			},
		},
	}

	modRootOut, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -m failed: %v\n%s", err, string(modRootOut))
	}
	modRoot := strings.TrimSpace(string(modRootOut))

	for _, tc := range cases {
		relDir := strings.TrimPrefix(tc.pkg, "github.com/transparency-dev/incubator/")
		goFiles, err := filepath.Glob(filepath.Join(modRoot, relDir, "*.go"))
		if err != nil || len(goFiles) == 0 {
			continue
		}
		out, err := exec.Command("go", "list", "-deps", tc.pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list -deps %s failed: %v\n%s", tc.pkg, err, string(out))
		}
		deps := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, dep := range deps {
			for _, bad := range tc.forbidden {
				if dep == bad || strings.HasPrefix(dep, bad+"/") {
					t.Errorf("package %s transitively depends on forbidden package %s (via %s)", tc.pkg, bad, dep)
				}
			}
		}
	}
}

func TestMTCVerifier(t *testing.T) {
	name := "oid/1.3.6.1.4.1.44363.47.1.44363.48.8"
	pubKeyB64 := "teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU="
	cosignerID := "44363.48.9"
	logID := "44363.48.8"

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		t.Fatalf("Failed to decode pubKey: %v", err)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	v, err := NewMTCVerifier(name, pubKey, cosignerID, logID)
	if err != nil {
		t.Fatalf("NewMTCVerifier failed: %v", err)
	}

	if v.Name() != name {
		t.Errorf("Name() = %q, want %q", v.Name(), name)
	}

	wantKeyHash := uint32(0x8e6a3b1a)
	if v.KeyHash() != wantKeyHash {
		t.Errorf("KeyHash() = 0x%x, want 0x%x", v.KeyHash(), wantKeyHash)
	}

	checkpointText := `bootstrap-mtca.cloudflareresearch.com/logs/shard3
197762974
7NWRnNW49lCjHOLMyMLBYRkRTGxDhVEmQhTw2gD/Pig=`

	sigB64 := "jmo7GsZLYkXSa+C4eXII6rUTN8BECzdUogRIlzML8wqeWnFuTjOjAOGrHu79pnjuZBx1syo5FYNs5sKpj2D93QEkLws="
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("Failed to decode signature: %v", err)
	}
	rawSig := sigBytes[4:]

	if !v.Verify([]byte(checkpointText), rawSig) {
		t.Error("Verification failed")
	}

	parsed, err := ParseVerifier("mtc+" + name + "+" + cosignerID + "+" + logID + "+" + pubKeyB64)
	if err != nil {
		t.Fatalf("ParseVerifier(mtc+...) failed: %v", err)
	}
	if !parsed.Verify([]byte(checkpointText), rawSig) {
		t.Error("ParseVerifier MTC verification failed")
	}
}

func TestParseVerifierAndWitnessVerifier(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "example.com/log")
	if err != nil {
		t.Fatalf("note.GenerateKey failed: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("note.NewSigner failed: %v", err)
	}

	v, err := ParseVerifier(vkey)
	if err != nil {
		t.Fatalf("ParseVerifier(inline) failed: %v", err)
	}
	if v.Name() != "example.com/log" {
		t.Fatalf("v.Name() = %q, want example.com/log", v.Name())
	}

	keyPath := filepath.Join(t.TempDir(), "log.pub")
	if err := os.WriteFile(keyPath, []byte(vkey+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	vFromFile, err := ParseVerifier(keyPath)
	if err != nil {
		t.Fatalf("ParseVerifier(file) failed: %v", err)
	}
	if vFromFile.KeyHash() != v.KeyHash() {
		t.Fatalf("KeyHash mismatch: %x != %x", vFromFile.KeyHash(), v.KeyHash())
	}

	// Cosignature v1 witness key
	cosigSKey, cosigRawVKey, err := note.GenerateKey(rand.Reader, "witness.example/w1")
	if err != nil {
		t.Fatalf("note.GenerateKey failed: %v", err)
	}
	cosigSigner, err := f_note.NewSignerForCosignatureV1(cosigSKey)
	if err != nil {
		t.Fatalf("NewSignerForCosignatureV1 failed: %v", err)
	}
	cosigVKey, err := f_note.VKeyToCosignatureV1(cosigRawVKey)
	if err != nil {
		t.Fatalf("VKeyToCosignatureV1 failed: %v", err)
	}
	wv, err := ParseWitnessVerifier(cosigVKey)
	if err != nil {
		t.Fatalf("ParseWitnessVerifier(cosig) failed: %v", err)
	}

	root := sha256.Sum256([]byte("tree-root"))
	cpText := fmt.Sprintf("example.com/log\n5\n%s\n", base64.StdEncoding.EncodeToString(root[:]))
	signed, err := note.Sign(&note.Note{Text: cpText}, signer, cosigSigner)
	if err != nil {
		t.Fatalf("note.Sign failed: %v", err)
	}

	pol, err := BuildPolicy("example.com/log", v, []note.Verifier{wv}, 1)
	if err != nil {
		t.Fatalf("BuildPolicy failed: %v", err)
	}
	cp, err := pol.Verify(signed)
	if err != nil {
		t.Fatalf("pol.Verify with cosignature witness failed: %v", err)
	}
	if cp.Size != 5 || cp.Origin != "example.com/log" {
		t.Fatalf("unexpected verified checkpoint: %+v", cp)
	}

	// Fallback witness verifier via standard note key file
	witSKey, witVKey, err := note.GenerateKey(rand.Reader, "witness.example/note")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	witSigner, err := note.NewSigner(witSKey)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	witPath := filepath.Join(t.TempDir(), "wit.pub")
	if err := os.WriteFile(witPath, []byte(witVKey+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	wvNote, err := ParseWitnessVerifier(witPath)
	if err != nil {
		t.Fatalf("ParseWitnessVerifier(file) failed: %v", err)
	}
	signed2, err := note.Sign(&note.Note{Text: cpText}, signer, witSigner)
	if err != nil {
		t.Fatalf("note.Sign failed: %v", err)
	}
	pol2, err := ParsePolicyOrVerifier("", keyPath, "", []note.Verifier{wvNote}, 1)
	if err != nil {
		t.Fatalf("ParsePolicyOrVerifier failed: %v", err)
	}
	if _, err := pol2.Verify(signed2); err != nil {
		t.Fatalf("pol2.Verify(signed2) failed: %v", err)
	}
}

func TestBuildPolicyErrorsAndPolicyFile(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "example.com/log")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	signer, _ := note.NewSigner(skey)
	v, _ := ParseVerifier(vkey)
	_, wvkey, _ := note.GenerateKey(rand.Reader, "witness.example/w1")
	wv, _ := ParseVerifier(wvkey)

	if _, err := BuildPolicy("", nil, nil, 0); err == nil {
		t.Fatal("expected error for nil primary verifier")
	}
	if _, err := BuildPolicy("", v, []note.Verifier{v}, 1); err == nil {
		t.Fatal("expected error when witness collides with primary verifier")
	}
	if _, err := BuildPolicy("", v, []note.Verifier{wv, wv}, 2); err == nil {
		t.Fatal("expected error when duplicate witnesses fall short of threshold")
	}

	// Valid tlog-policy file via ParsePolicyOrVerifier
	policyContent := fmt.Sprintf("log %s\nquorum none\n", vkey)
	policyPath := filepath.Join(t.TempDir(), "log.policy")
	if err := os.WriteFile(policyPath, []byte(policyContent), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	pol, err := ParsePolicyOrVerifier(policyPath, "", "", nil, 0)
	if err != nil {
		t.Fatalf("ParsePolicyOrVerifier(policyFile) failed: %v", err)
	}
	root := sha256.Sum256([]byte("policy-file-root"))
	cpText := fmt.Sprintf("example.com/log\n7\n%s\n", base64.StdEncoding.EncodeToString(root[:]))
	signed, err := note.Sign(&note.Note{Text: cpText}, signer)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if _, err := pol.Verify(signed); err != nil {
		t.Fatalf("pol.Verify with policy file failed: %v", err)
	}
}

func TestBuildPolicy_CustomOriginAndWitnessThresholds(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "signer.example/key")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	logSigner, _ := note.NewSigner(skey)
	logVerifier, _ := ParseVerifier(vkey)

	w1SKey, w1RawVKey, _ := note.GenerateKey(rand.Reader, "witness.example/w1")
	w1Signer, _ := f_note.NewSignerForCosignatureV1(w1SKey)
	w1CosigVKey, _ := f_note.VKeyToCosignatureV1(w1RawVKey)
	w1Verifier, _ := ParseWitnessVerifier(w1CosigVKey)

	w2SKey, w2RawVKey, _ := note.GenerateKey(rand.Reader, "witness.example/w2")
	w2Signer, _ := f_note.NewSignerForCosignatureV1(w2SKey)
	w2CosigVKey, _ := f_note.VKeyToCosignatureV1(w2RawVKey)
	w2Verifier, _ := ParseWitnessVerifier(w2CosigVKey)

	customOrigin := "custom.origin/log"
	pol, err := BuildPolicy(customOrigin, logVerifier, []note.Verifier{w1Verifier, w2Verifier}, 2)
	if err != nil {
		t.Fatalf("BuildPolicy failed: %v", err)
	}

	root := sha256.Sum256([]byte("custom-origin-root"))
	validCPText := fmt.Sprintf("%s\n42\n%s\n", customOrigin, base64.StdEncoding.EncodeToString(root[:]))
	wrongOriginText := fmt.Sprintf("signer.example/key\n42\n%s\n", base64.StdEncoding.EncodeToString(root[:]))

	// 1. Valid: signed by log + w1 + w2 with custom origin
	signedAll, err := note.Sign(&note.Note{Text: validCPText}, logSigner, w1Signer, w2Signer)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	cp, err := pol.Verify(signedAll)
	if err != nil {
		t.Fatalf("pol.Verify(signedAll) failed: %v", err)
	}
	if cp.Origin != customOrigin || cp.Size != 42 {
		t.Fatalf("unexpected checkpoint: %+v", cp)
	}

	// 2. Wrong origin (matches signer name instead of custom origin)
	signedWrongOrigin, _ := note.Sign(&note.Note{Text: wrongOriginText}, logSigner, w1Signer, w2Signer)
	if _, err := pol.Verify(signedWrongOrigin); err == nil {
		t.Fatal("expected failure when checkpoint origin does not match custom origin")
	}

	// 3. Missing primary log signature (signed by w1 + w2 only)
	signedNoLog, _ := note.Sign(&note.Note{Text: validCPText}, w1Signer, w2Signer)
	if _, err := pol.Verify(signedNoLog); err == nil {
		t.Fatal("expected failure when primary log signature is missing")
	}

	// 4. Insufficient witness signatures (only 1 of 2 required)
	signedOneWit, _ := note.Sign(&note.Note{Text: validCPText}, logSigner, w1Signer)
	if _, err := pol.Verify(signedOneWit); err == nil {
		t.Fatal("expected failure when only 1 of 2 required witnesses signed")
	}

	// 5. Duplicate signature from the same witness (w1 signs twice)
	signedDupWit, _ := note.Sign(&note.Note{Text: validCPText}, logSigner, w1Signer, w1Signer)
	if _, err := pol.Verify(signedDupWit); err == nil {
		t.Fatal("expected failure when duplicate witness signatures do not meet distinct threshold")
	}
}

func TestParsePolicyFile_MultiWitnessGroupQuorum(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "example.com/log")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	logSigner, _ := note.NewSigner(skey)

	w1SKey, w1RawVKey, _ := note.GenerateKey(rand.Reader, "witness.example/w1")
	w1Signer, _ := f_note.NewSignerForCosignatureV1(w1SKey)
	w1VKey, _ := f_note.VKeyToCosignatureV1(w1RawVKey)

	w2SKey, w2RawVKey, _ := note.GenerateKey(rand.Reader, "witness.example/w2")
	w2Signer, _ := f_note.NewSignerForCosignatureV1(w2SKey)
	w2VKey, _ := f_note.VKeyToCosignatureV1(w2RawVKey)

	policyContent := fmt.Sprintf(
		"log %s\nwitness w1 %s\nwitness w2 %s\ngroup g1 2 w1 w2\nquorum g1\n",
		vkey, w1VKey, w2VKey,
	)
	policyPath := filepath.Join(t.TempDir(), "quorum.policy")
	if err := os.WriteFile(policyPath, []byte(policyContent), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	pol, err := ParsePolicyOrVerifier(policyPath, "", "", nil, 0)
	if err != nil {
		t.Fatalf("ParsePolicyOrVerifier failed: %v", err)
	}

	root := sha256.Sum256([]byte("quorum-root"))
	cpText := fmt.Sprintf("example.com/log\n99\n%s\n", base64.StdEncoding.EncodeToString(root[:]))

	signedBoth, err := note.Sign(&note.Note{Text: cpText}, logSigner, w1Signer, w2Signer)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if _, err := pol.Verify(signedBoth); err != nil {
		t.Fatalf("expected valid quorum checkpoint to pass: %v", err)
	}

	signedOnlyW1, _ := note.Sign(&note.Note{Text: cpText}, logSigner, w1Signer)
	if _, err := pol.Verify(signedOnlyW1); err == nil {
		t.Fatal("expected checkpoint with only 1 of 2 quorum witnesses to fail")
	}
}

func TestAdversarialSpecStrictness(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "example.com/outlog")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	logSigner, _ := note.NewSigner(skey)
	logVerifier, _ := ParseVerifier(vkey)
	pol, _ := BuildPolicy("example.com/outlog", logVerifier, nil, 0)

	inRoot := sha256.Sum256([]byte("in-root"))
	mptRoot := sha256.Sum256([]byte("mpt-root"))
	outLeafRaw := FormatStateEntry("example.com/inlog", 0, 10, inRoot, mptRoot)
	outRoot := LeafHash(outLeafRaw)
	cpBody := fmt.Sprintf("example.com/outlog\n1\n%s\n", base64.StdEncoding.EncodeToString(outRoot[:]))
	outSignedCP, err := note.Sign(&note.Note{Text: cpBody}, logSigner)
	if err != nil {
		t.Fatalf("note.Sign failed: %v", err)
	}

	validBinding := FormatBindingSection(outLeafRaw, 0, nil, outSignedCP)

	// 1. ParseBindingSection rejects truncated checkpoint missing trailing \n
	truncated := validBinding[:len(validBinding)-1]
	if _, err := ParseBindingSection(truncated); err == nil {
		t.Fatal("expected ParseBindingSection to reject binding section missing trailing newline")
	}

	// 2. ParseBindingSection rejects unsigned checkpoint (no \n\n before signature block)
	unsignedBinding := FormatBindingSection(outLeafRaw, 0, nil, []byte(cpBody))
	if _, err := ParseBindingSection(unsignedBinding); err == nil {
		t.Fatal("expected ParseBindingSection to reject unsigned checkpoint")
	}

	// 3. ParseBindingSection rejects > 63 inclusion proof hashes
	tooManyHashes := make([][]byte, 64)
	for i := range tooManyHashes {
		tooManyHashes[i] = inRoot[:]
	}
	hugeBinding := FormatBindingSection(outLeafRaw, 0, tooManyHashes, outSignedCP)
	if _, err := ParseBindingSection(hugeBinding); err == nil {
		t.Fatal("expected ParseBindingSection to reject > 63 audit path hashes")
	}

	// 4. Policy.Verify rejects non-32-byte hash, leading-zero size, and CRLF in signed checkpoints
	shortHashCP, _ := note.Sign(&note.Note{Text: "example.com/outlog\n1\nAAAA\n"}, logSigner)
	if _, err := pol.Verify(shortHashCP); err == nil {
		t.Fatal("expected Policy.Verify to reject checkpoint with non-32-byte hash")
	}
	leadingZeroCP, _ := note.Sign(&note.Note{Text: fmt.Sprintf("example.com/outlog\n01\n%s\n", base64.StdEncoding.EncodeToString(outRoot[:]))}, logSigner)
	if _, err := pol.Verify(leadingZeroCP); err == nil {
		t.Fatal("expected Policy.Verify to reject checkpoint with leading-zero size")
	}
	crlfCP := bytes.ReplaceAll(outSignedCP, []byte("\n"), []byte("\r\n"))
	if _, err := pol.Verify(crlfCP); err == nil {
		t.Fatal("expected Policy.Verify to reject CRLF checkpoint")
	}

	// 5. ParsePolicyOrVerifier enforces origin when policyPath != "" and origin != ""
	policyPath := filepath.Join(t.TempDir(), "test.policy")
	if err := os.WriteFile(policyPath, []byte(fmt.Sprintf("log %s\nquorum none\n", vkey)), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	polWithOrigin, err := ParsePolicyOrVerifier(policyPath, "", "different.example/outlog", nil, 0)
	if err != nil {
		t.Fatalf("ParsePolicyOrVerifier failed: %v", err)
	}
	if _, err := polWithOrigin.Verify(outSignedCP); err == nil {
		t.Fatal("expected ParsePolicyOrVerifier with mismatched origin to reject checkpoint")
	}

	// 6. MTCVerifier rejects forged extension lines, leading-zero size, and bad pubkey size
	if _, err := NewMTCVerifier("example.com/mtc", ed25519.PublicKey("short"), "1.2", "1.3"); err == nil {
		t.Fatal("expected NewMTCVerifier to reject invalid public key size")
	}
	mtcPub, mtcPriv, _ := ed25519.GenerateKey(rand.Reader)
	mtcV, err := NewMTCVerifier("example.com/mtc", mtcPub, "44363.48.9", "44363.48.8")
	if err != nil {
		t.Fatalf("NewMTCVerifier failed: %v", err)
	}
	var mtcInput []byte
	mtcInput = append(mtcInput, []byte("mtc-subtree/v1\n")...)
	mtcInput = append(mtcInput, 0)
	mtcInput = append(mtcInput, byte(len(mtcV.cosignerIDBytes)))
	mtcInput = append(mtcInput, mtcV.cosignerIDBytes...)
	mtcInput = append(mtcInput, byte(len(mtcV.logIDBytes)))
	mtcInput = append(mtcInput, mtcV.logIDBytes...)
	var startBytes, endBytes [8]byte
	binary.BigEndian.PutUint64(endBytes[:], 5)
	mtcInput = append(mtcInput, startBytes[:]...)
	mtcInput = append(mtcInput, endBytes[:]...)
	mtcInput = append(mtcInput, outRoot[:]...)
	mtcSig := ed25519.Sign(mtcPriv, mtcInput)

	validMTCMsg := fmt.Sprintf("example.com/mtc\n5\n%s\n", base64.StdEncoding.EncodeToString(outRoot[:]))
	if !mtcV.Verify([]byte(validMTCMsg), mtcSig) {
		t.Fatal("expected valid MTC message to verify")
	}
	forgedExtMsg := validMTCMsg + "evil-extension-line\n"
	if mtcV.Verify([]byte(forgedExtMsg), mtcSig) {
		t.Fatal("expected MTCVerifier to reject checkpoint with forged extension line")
	}
	leadingZeroMTCMsg := fmt.Sprintf("example.com/mtc\n05\n%s\n", base64.StdEncoding.EncodeToString(outRoot[:]))
	if mtcV.Verify([]byte(leadingZeroMTCMsg), mtcSig) {
		t.Fatal("expected MTCVerifier to reject checkpoint with leading-zero size")
	}

	// 7. ParseValuesResponse and ComputeValueLogRoot reject preceding > indices[0] and unsorted indices
	invalidValResp := FormatValuesResponse(2, [][32]byte{inRoot}, []uint64{1, 5})
	if _, err := ParseValuesResponse(invalidValResp); err == nil {
		t.Fatal("expected ParseValuesResponse to reject preceding (2) > indices[0] (1)")
	}
	if _, err := ComputeValueLogRoot([][32]byte{inRoot}, 2, []uint64{1, 5}); err == nil {
		t.Fatal("expected ComputeValueLogRoot to reject preceding (2) > indices[0] (1)")
	}
	if _, err := ComputeValueLogRoot(nil, 0, []uint64{5, 5}); err == nil {
		t.Fatal("expected ComputeValueLogRoot to reject non-ascending indices")
	}

	// 8. ParseVerifier returns clear file error for nonexistent file path
	if _, err := ParseVerifier(filepath.Join(t.TempDir(), "does-not-exist.pub")); err == nil {
		t.Fatal("expected ParseVerifier to fail on missing file path")
	}
}
