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

package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
)

func FuzzVerifyKeysResponse(f *testing.F) {
	seedReader := bytes.NewReader(bytes.Repeat([]byte{0x42}, 128))
	outSKey, outVKey, err := note.GenerateKey(seedReader, "example.com/output")
	if err != nil {
		f.Fatal(err)
	}
	outSigner, err := note.NewSigner(outSKey)
	if err != nil {
		f.Fatal(err)
	}
	outVerifier, err := note.NewVerifier(outVKey)
	if err != nil {
		f.Fatal(err)
	}

	outPolicy, err := SingleKeyPolicy("example.com/output", outVerifier)
	if err != nil {
		f.Fatal(err)
	}
	cfg := Config{
		ExpectedOutputLogOrigin: "example.com/output",
		OutputLogPolicy:         outPolicy,
		ExpectedInputLogOrigin:  "example.com/input",
	}

	mptMgr := mpt.NewMem()
	vr := sha256.Sum256([]byte("fuzz-vr"))
	mptRoot, err := mptMgr.CommitKeysWithVersion(map[string][32]byte{"com.example.": vr}, 10)
	if err != nil {
		f.Fatal(err)
	}
	inHash := sha256.Sum256([]byte("fuzz-in-root"))
	inCP := &log.Checkpoint{Origin: "example.com/input", Size: 10, Hash: inHash[:]}
	outLeaf := wire.FormatOutputLogLeafFull(mptRoot, 0, inCP)
	outRoot := wire.LeafHash(outLeaf)
	outSignedCP, err := note.Sign(&note.Note{
		Text: fmt.Sprintf("example.com/output\n1\n%s\n", base64.StdEncoding.EncodeToString(outRoot[:])),
	}, outSigner)
	if err != nil {
		f.Fatal(err)
	}

	incProof, _, _, _ := mptMgr.ProveKey([]byte("com.example."))
	nonIncProof, _, _, _ := mptMgr.ProveKey([]byte("com.other."))
	mptMgr.RLock()
	pfxProof, pfxMatches, _ := mptMgr.ProvePrefixLocked([]byte("com."), 0)
	mptMgr.RUnlock()

	f.Add(wire.FormatKeysResponseFull(outSignedCP, 0, mptRoot, 0, inCP, nil, "", incProof, []wire.KeyValueRoot{{Key: "com.example.", ValueRoot: vr}}), "com.example.", false)
	f.Add(wire.FormatKeysResponseFull(outSignedCP, 0, mptRoot, 0, inCP, nil, "", nonIncProof, nil), "com.other.", false)
	f.Add(wire.FormatKeysResponseFull(outSignedCP, 0, mptRoot, 0, inCP, nil, "", pfxProof, pfxMatches), "com.", true)
	f.Add([]byte(""), "", false)

	f.Fuzz(func(_ *testing.T, rawBody []byte, target string, isPrefix bool) {
		_, _ = VerifyKeysResponse(rawBody, target, isPrefix, cfg)
	})
}

func FuzzVerifyValuesResponse(f *testing.F) {
	vr0, err := wire.ComputeValueLogRoot(nil, 0, []uint64{10, 20})
	if err != nil {
		f.Fatal(err)
	}
	comp0 := sha256.Sum256([]byte("prev-leaf"))
	vr1, err := wire.ComputeValueLogRoot([][32]byte{comp0}, 1, []uint64{55})
	if err != nil {
		f.Fatal(err)
	}

	f.Add(wire.FormatValuesResponse(0, nil, []uint64{10, 20}), vr0[:], uint64(0), uint64(100))
	f.Add(wire.FormatValuesResponse(1, [][32]byte{comp0}, []uint64{55}), vr1[:], uint64(50), uint64(60))
	f.Add([]byte(""), make([]byte, 32), uint64(0), uint64(0))

	f.Fuzz(func(_ *testing.T, rawBody []byte, rootSlice []byte, from, before uint64) {
		var expectedRoot [sha256.Size]byte
		copy(expectedRoot[:], rootSlice)
		resp, err := VerifyValuesResponse(rawBody, expectedRoot, from, before)
		if err == nil && resp != nil {
			_, _, _ = resp.NextPage()
		}
	})
}

func FuzzDomainToCanonicalKey(f *testing.F) {
	for _, seed := range []string{"example.com", "*.example.com", "Example.COM.", "Kelvin.com", "https://example.com:443", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, domain string) {
		_, _ = DomainToCanonicalKey(domain)
	})
}
